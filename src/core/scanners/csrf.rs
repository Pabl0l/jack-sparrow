#![allow(dead_code)]

use crate::core::scanners::crawl_integration::{ScanTarget, TargetType};
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

/// CSRF token patterns commonly used by frameworks.
const CSRF_PATTERNS: &[&str] = &[
    "csrf",
    "xsrf",
    "_token",
    "csrfmiddlewaretoken",
    "csrf_token",
    "authenticity_token",
    "__RequestVerificationToken",
    "anti Forgery",
    "_csrf",
    "csrffield",
    "token",
    "nonce",
    "verification",
];

/// Known cookie attributes that matter for CSRF.
const SAMESITE_MARKERS: &[&str] = &["samesite", "same-site", "same_site"];

/// CSRF scanner — detects missing or weak CSRF protections on state-changing forms.
pub struct CsrfScanner {
    client: Client,
}

impl CsrfScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        let timeout = Duration::from_secs(config.general.timeout_secs.min(10));
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        Self { client }
    }

    /// Check if a form has a CSRF token field.
    fn has_csrf_token(params: &[crate::core::scanners::crawl_integration::ScanParam]) -> bool {
        params.iter().any(|p| {
            let name_lower = p.name.to_lowercase();
            CSRF_PATTERNS.iter().any(|pat| name_lower.contains(pat))
        })
    }

    /// Detect the CSRF token type/name if present.
    fn detect_csrf_token_name(params: &[crate::core::scanners::crawl_integration::ScanParam]) -> Option<String> {
        params.iter().find_map(|p| {
            let name_lower = p.name.to_lowercase();
            if CSRF_PATTERNS.iter().any(|pat| name_lower.contains(pat)) {
                Some(p.name.clone())
            } else {
                None
            }
        })
    }

    /// Send POST with empty/missing CSRF token and check if it's rejected.
    async fn test_empty_token(
        &self,
        target: &ScanTarget,
        token_param: &str,
        context: &ScanContext,
    ) -> Result<bool, JackSparrowError> {
        let url = target.url.as_str();
        let body: Vec<(&str, String)> = target
            .params
            .iter()
            .map(|p| {
                if p.name == token_param {
                    (p.name.as_str(), String::new()) // Empty token
                } else {
                    (p.name.as_str(), p.value.clone().unwrap_or_else(|| "test".to_string()))
                }
            })
            .collect();

        let mut req = self.client.post(url).form(&body);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "csrf-scanner".to_string(),
            message: e.to_string(),
        })?;

        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        // If we get 200 with success indicators, the token is NOT validated
        let is_success = status == 200
            && (body_text.to_lowercase().contains("success")
                || body_text.to_lowercase().contains("created")
                || body_text.to_lowercase().contains("updated")
                || (!body_text.to_lowercase().contains("error")
                    && !body_text.to_lowercase().contains("invalid")
                    && !body_text.to_lowercase().contains("forbidden")));

        Ok(is_success)
    }

    /// Send POST with a static/guessed token and check if it's accepted.
    async fn test_guessed_token(
        &self,
        target: &ScanTarget,
        token_param: &str,
        context: &ScanContext,
    ) -> Result<bool, JackSparrowError> {
        let url = target.url.as_str();
        let body: Vec<(&str, String)> = target
            .params
            .iter()
            .map(|p| {
                if p.name == token_param {
                    (p.name.as_str(), "test_token_12345".to_string())
                } else {
                    (p.name.as_str(), p.value.clone().unwrap_or_else(|| "test".to_string()))
                }
            })
            .collect();

        let mut req = self.client.post(url).form(&body);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "csrf-scanner".to_string(),
            message: e.to_string(),
        })?;

        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        let is_success = status == 200
            && (body_text.to_lowercase().contains("success")
                || body_text.to_lowercase().contains("created")
                || body_text.to_lowercase().contains("updated")
                || (!body_text.to_lowercase().contains("error")
                    && !body_text.to_lowercase().contains("invalid")
                    && !body_text.to_lowercase().contains("forbidden")));

        Ok(is_success)
    }

    /// Check response headers for SameSite cookie attributes.
    async fn check_samesite_cookies(
        &self,
        url: &str,
        context: &ScanContext,
    ) -> Result<Vec<String>, JackSparrowError> {
        let mut req = self.client.get(url);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "csrf-scanner".to_string(),
            message: e.to_string(),
        })?;

        let mut issues = Vec::new();
        let headers = resp.headers();

        // Check Set-Cookie headers
        for (name, value) in headers.iter() {
            if name.as_str().to_lowercase() == "set-cookie" {
                let cookie_str = value.to_str().unwrap_or("");
                let cookie_lower = cookie_str.to_lowercase();

                // Check for SameSite
                if !SAMESITE_MARKERS.iter().any(|m| cookie_lower.contains(m)) {
                    issues.push(format!(
                        "Cookie '{}' missing SameSite attribute",
                        cookie_str.split('=').next().unwrap_or("unknown")
                    ));
                }

                // Check for Secure flag on sensitive cookies
                if cookie_lower.contains("session")
                    || cookie_lower.contains("token")
                    || cookie_lower.contains("auth")
                {
                    if !cookie_lower.contains("secure") {
                        issues.push(format!(
                            "Sensitive cookie '{}' missing Secure flag",
                            cookie_str.split('=').next().unwrap_or("unknown")
                        ));
                    }
                }

                // Check for HttpOnly
                if cookie_lower.contains("session") || cookie_lower.contains("token") {
                    if !cookie_lower.contains("httponly") {
                        issues.push(format!(
                            "Cookie '{}' missing HttpOnly flag",
                            cookie_str.split('=').next().unwrap_or("unknown")
                        ));
                    }
                }
            }
        }

        Ok(issues)
    }
}

#[async_trait]
impl Scanner for CsrfScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::Csrf
    }

    async fn scan(
        &self,
        _target: &str,
        _config: &JackSparrowConfig,
        _context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        Ok(Vec::new())
    }
}

impl CsrfScanner {
    /// Scan a list of form targets for CSRF vulnerabilities.
    pub async fn scan_with_targets(
        &self,
        targets: &[&ScanTarget],
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        for target in targets {
            if target.target_type != TargetType::Form {
                continue;
            }

            // Only check state-changing methods
            let method = &target.method;
            if *method != crate::core::crawler::parser::Method::Post
                && *method != crate::core::crawler::parser::Method::Put
                && *method != crate::core::crawler::parser::Method::Delete
                && *method != crate::core::crawler::parser::Method::Patch
            {
                continue;
            }

            let has_token = Self::has_csrf_token(&target.params);

            if !has_token {
                // Finding 1: No CSRF token at all
                findings.push(Finding {
                    id: uuid::Uuid::new_v4(),
                    vulnerability_type: VulnerabilityType::Csrf,
                    severity: Severity::High,
                    confidence: Confidence::Confirmed,
                    title: format!("Missing CSRF token in form at {}", target.url),
                    description: format!(
                        "State-changing form at {} (method: {:?}) has no CSRF token field. \
                         An attacker can forge cross-site requests to perform actions on behalf of authenticated users.",
                        target.url, method
                    ),
                    url: target.url.to_string(),
                    parameter: None,
                    evidence: Evidence {
                        request: Some(format!("Form action: {} (method: {:?})", target.url, method)),
                        response: None,
                        payload: None,
                        pattern: Some("No CSRF token parameter found".to_string()),
                        context: Some(format!("Form parameters: {:?}", target.params.iter().map(|p| &p.name).collect::<Vec<_>>())),
                    },
                    remediation: "Add a CSRF token to all state-changing forms. Use framework-provided CSRF protection (e.g., Django CSRF middleware, Rails authenticity_token).".to_string(),
                    references: vec![
                        "https://owasp.org/www-community/attacks/csrf".to_string(),
                        "https://cwe.mitre.org/data/definitions/352.html".to_string(),
                    ],
                    timestamp: chrono::Utc::now(),
                    cvss_score: Some(8.0),
                    cwe_id: Some("CWE-352".to_string()),
                    tool_source: "csrf-scanner".to_string(),
                });
            } else {
                // Token exists — test if it's validated
                let token_name = Self::detect_csrf_token_name(&target.params).unwrap_or_default();

                // Test empty token
                if let Ok(accepted) = self.test_empty_token(target, &token_name, context).await {
                    if accepted {
                        findings.push(Finding {
                            id: uuid::Uuid::new_v4(),
                            vulnerability_type: VulnerabilityType::Csrf,
                            severity: Severity::Critical,
                            confidence: Confidence::Confirmed,
                            title: format!("CSRF token not validated (empty token accepted) at {}", target.url),
                            description: format!(
                                "The CSRF token field '{}' in form at {} accepts empty values. \
                                 The server does not validate the token, making CSRF protection ineffective.",
                                token_name, target.url
                            ),
                            url: target.url.to_string(),
                            parameter: Some(token_name.clone()),
                            evidence: Evidence {
                                request: Some(format!("POST {} with empty '{}'", target.url, token_name)),
                                response: Some("Request accepted with empty CSRF token".to_string()),
                                payload: Some(format!("{}=", token_name)),
                                pattern: Some("Empty token accepted".to_string()),
                                context: None,
                            },
                            remediation: "Validate CSRF tokens server-side. Reject requests with empty or missing tokens.".to_string(),
                            references: vec![
                                "https://owasp.org/www-community/attacks/csrf".to_string(),
                                "https://cwe.mitre.org/data/definitions/352.html".to_string(),
                            ],
                            timestamp: chrono::Utc::now(),
                            cvss_score: Some(9.0),
                            cwe_id: Some("CWE-352".to_string()),
                            tool_source: "csrf-scanner".to_string(),
                        });
                    }
                }

                // Test static/guessed token
                if let Ok(accepted) = self.test_guessed_token(target, &token_name, context).await {
                    if accepted {
                        findings.push(Finding {
                            id: uuid::Uuid::new_v4(),
                            vulnerability_type: VulnerabilityType::Csrf,
                            severity: Severity::Critical,
                            confidence: Confidence::Confirmed,
                            title: format!("CSRF token predictable (static token accepted) at {}", target.url),
                            description: format!(
                                "The CSRF token '{}' in form at {} accepts static/guessed values. \
                                 The token is not properly random or not validated.",
                                token_name, target.url
                            ),
                            url: target.url.to_string(),
                            parameter: Some(token_name.clone()),
                            evidence: Evidence {
                                request: Some(format!("POST {} with '{}=test_token_12345'", target.url, token_name)),
                                response: Some("Request accepted with guessed token".to_string()),
                                payload: Some("test_token_12345".to_string()),
                                pattern: Some("Static token accepted".to_string()),
                                context: None,
                            },
                            remediation: "Generate cryptographically random CSRF tokens. Validate tokens server-side using constant-time comparison.".to_string(),
                            references: vec![
                                "https://owasp.org/www-community/attacks/csrf".to_string(),
                                "https://cwe.mitre.org/data/definitions/352.html".to_string(),
                            ],
                            timestamp: chrono::Utc::now(),
                            cvss_score: Some(9.0),
                            cwe_id: Some("CWE-352".to_string()),
                            tool_source: "csrf-scanner".to_string(),
                        });
                    }
                }
            }
        }

        // Check cookie security on first target's domain
        if let Some(first) = targets.first() {
            let domain_url = format!("{}://{}", first.url.scheme(), first.url.host_str().unwrap_or(""));
            if let Ok(issues) = self.check_samesite_cookies(&domain_url, context).await {
                for issue in issues {
                    findings.push(Finding {
                        id: uuid::Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::Csrf,
                        severity: Severity::Medium,
                        confidence: Confidence::Likely,
                        title: "Cookie security issue".to_string(),
                        description: issue.clone(),
                        url: domain_url.clone(),
                        parameter: None,
                        evidence: Evidence {
                            request: None,
                            response: Some(issue),
                            payload: None,
                            pattern: None,
                            context: Some("Cookie attribute analysis".to_string()),
                        },
                        remediation: "Set SameSite=Lax or SameSite=Strict on session cookies. Add Secure and HttpOnly flags.".to_string(),
                        references: vec![
                            "https://owasp.org/www-community/SameSite".to_string(),
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite".to_string(),
                        ],
                        timestamp: chrono::Utc::now(),
                        cvss_score: Some(5.0),
                        cwe_id: Some("CWE-1275".to_string()),
                        tool_source: "csrf-scanner".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crawler::parser::Method;
    use crate::core::scanners::crawl_integration::{ParamType, ScanParam, TargetType};
    use url::Url;

    fn make_form_target(url: &str, params: Vec<ScanParam>) -> ScanTarget {
        ScanTarget {
            url: Url::parse(url).unwrap(),
            method: Method::Post,
            params,
            source_url: None,
            target_type: TargetType::Form,
            depth: 1,
        }
    }

    fn make_param(name: &str) -> ScanParam {
        ScanParam {
            name: name.to_string(),
            param_type: ParamType::Body,
            value: Some("test".to_string()),
            is_hidden: false,
        }
    }

    fn make_hidden_param(name: &str, value: &str) -> ScanParam {
        ScanParam {
            name: name.to_string(),
            param_type: ParamType::Hidden,
            value: Some(value.to_string()),
            is_hidden: true,
        }
    }

    #[test]
    fn test_has_csrf_token_with_token() {
        let params = vec![make_param("username"), make_hidden_param("csrf_token", "abc123")];
        assert!(CsrfScanner::has_csrf_token(&params));
    }

    #[test]
    fn test_has_csrf_token_without() {
        let params = vec![make_param("username"), make_param("password")];
        assert!(!CsrfScanner::has_csrf_token(&params));
    }

    #[test]
    fn test_detect_csrf_token_name() {
        let params = vec![make_param("username"), make_hidden_param("_token", "xyz")];
        assert_eq!(CsrfScanner::detect_csrf_token_name(&params), Some("_token".to_string()));
    }

    #[test]
    fn test_detect_no_csrf_token() {
        let params = vec![make_param("username"), make_param("password")];
        assert!(CsrfScanner::detect_csrf_token_name(&params).is_none());
    }

    #[test]
    fn test_csrf_patterns_coverage() {
        // Verify our patterns cover common frameworks
        let test_cases = [
            ("csrf_token", true),
            ("_token", true),
            ("csrfmiddlewaretoken", true),
            ("authenticity_token", true),
            ("__RequestVerificationToken", true),
            ("username", false),
            ("password", false),
            ("email", false),
        ];

        for (name, expected) in test_cases {
            let _param = make_param(name);
            let has = CSRF_PATTERNS.iter().any(|pat| name.to_lowercase().contains(pat));
            assert_eq!(has, expected, "Failed for param: {}", name);
        }
    }

    #[test]
    fn test_form_with_csrf_not_flagged() {
        let params = vec![
            make_param("username"),
            make_hidden_param("csrf_token", "valid_token_here"),
        ];
        let target = make_form_target("http://example.com/login", params);
        assert!(CsrfScanner::has_csrf_token(&target.params));
    }

    #[test]
    fn test_form_without_csrf_flagged() {
        let params = vec![make_param("username"), make_param("password")];
        let target = make_form_target("http://example.com/login", params);
        assert!(!CsrfScanner::has_csrf_token(&target.params));
    }

    #[test]
    fn test_scanner_type() {
        let scanner = CsrfScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::Csrf);
    }

    #[test]
    fn test_csrf_variations() {
        // Test various CSRF token naming conventions
        let names = [
            "csrf_token", "csrf", "xsrf_token", "_token",
            "csrfmiddlewaretoken", "authenticity_token",
            "_csrf", "csrffield", "token", "nonce",
        ];
        for name in &names {
            let _param = make_param(name);
            let has = CSRF_PATTERNS.iter().any(|pat| name.to_lowercase().contains(pat));
            assert!(has, "Pattern should match: {}", name);
        }
    }
}

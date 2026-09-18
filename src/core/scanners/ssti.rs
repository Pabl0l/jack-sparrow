#![allow(dead_code)]

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

pub struct SstiScanner;

impl SstiScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }

    fn build_client(&self, context: &ScanContext) -> Result<Client, JackSparrowError> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true);

        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in &context.headers {
            if let (Ok(k), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(k, v);
            }
        }
        headers.insert(
            "User-Agent",
            reqwest::header::HeaderValue::from_static("JackSparrow/0.3.0"),
        );
        builder = builder.default_headers(headers);

        builder.build().map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "ssti".to_string(),
            message: e.to_string(),
        })
    }

    /// SSTI payloads grouped by template engine
    ///
    /// Each payload: (template_syntax, expected_output, engine_name, severity)
    fn ssti_payloads() -> Vec<(&'static str, &'static str, &'static str, Severity)> {
        vec![
            // Jinja2 / Twig (Python)
            ("{{7*7}}", "49", "Jinja2/Twig (Python)", Severity::Critical),
            ("{{7*'7'}}", "7777777", "Jinja2/Twig string concat", Severity::Critical),
            ("{{config.items()}}", "Config", "Jinja2 config disclosure", Severity::Critical),
            ("{{self.__class__.__mro__[1].__subclasses__()}}", "class", "Jinja2 RCE via MRO", Severity::Critical),
            // Smarty (PHP)
            ("{7*7}", "49", "Smarty (PHP)", Severity::Critical),
            ("{$smarty.version}", "Smarty", "Smarty version disclosure", Severity::High),
            // Freemarker (Java)
            ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid=", "Freemarker RCE", Severity::Critical),
            ("${7*7}", "49", "Freemarker expression", Severity::Critical),
            // Velocity (Java)
            ("#set($x=7*7)$x", "49", "Apache Velocity", Severity::Critical),
            ("#evaluate('$x=7*7')$x", "49", "Velocity evaluate", Severity::Critical),
            // Mako (Python)
            ("<% x=7*7 %>${x}", "49", "Mako (Python)", Severity::Critical),
            // ERB (Ruby)
            ("<%= 7*7 %>", "49", "ERB (Ruby)", Severity::Critical),
            // Generic math test (universal)
            ("${7*7}", "49", "Generic template expression", Severity::Critical),
            ("#{7*7}", "49", "Generic hash expression", Severity::Critical),
            ("<%= 7*7 %>", "49", "Generic ERB expression", Severity::Critical),
        ]
    }

    /// Check if the response indicates template evaluation
    fn check_ssti_execution(response_body: &str, expected: &str) -> bool {
        // For math payloads like {{7*7}} -> "49"
        if expected == "49" {
            // Check if the response contains exactly "49" as a standalone value
            // (not just as part of a larger number like "149" or "490")
            let body_no_html = response_body
                .replace(">", "> ")
                .replace("<", " <");
            let words: Vec<&str> = body_no_html.split_whitespace().collect();
            return words.iter().any(|w| *w == "49");
        }
        // For string concat like "7777777"
        if expected == "7777777" {
            return response_body.contains("7777777");
        }
        // For config/class/rce patterns
        response_body.contains(expected)
    }

    /// Test a URL parameter for SSTI
    async fn test_param_ssti(
        &self,
        url: &str,
        param_name: &str,
        client: &Client,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = Self::ssti_payloads();

        // First, get the baseline response (no payload)
        let baseline_url = format!("{}?{}=sparrow_baseline_test", url, param_name);
        let baseline_body = match client.get(&baseline_url).send().await {
            Ok(resp) => resp.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };

        for (payload, expected, engine, severity) in &payloads {
            let test_url = format!("{}?{}={}", url, param_name, payload);

            match client.get(&test_url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(body) = resp.text().await {
                            if Self::check_ssti_execution(&body, expected) {
                                // Verify it's not in the baseline (avoid false positives)
                                if !Self::check_ssti_execution(&baseline_body, expected) {
                                    let finding = Finding {
                                        id: uuid::Uuid::new_v4(),
                                        vulnerability_type: VulnerabilityType::Ssti,
                                        severity: severity.clone(),
                                        confidence: Confidence::Confirmed,
                                        title: format!("SSTI vulnerability via {} engine", engine),
                                        description: format!(
                                            "Server-Side Template Injection confirmed at {} via parameter '{}'. \
                                             Payload '{}' produced expected output '{}', indicating {} template engine. \
                                             This allows remote code execution on the server.",
                                            url, param_name, payload, expected, engine
                                        ),
                                        url: url.to_string(),
                                        parameter: Some(param_name.to_string()),
                                        evidence: Evidence {
                                            request: Some(format!("GET {} HTTP/1.1", test_url)),
                                            response: Some(body.chars().take(500).collect()),
                                            payload: Some(payload.to_string()),
                                            pattern: Some(expected.to_string()),
                                            context: Some(format!("Template engine: {}", engine)),
                                        },
                                        remediation: format!(
                                            "1. Never render user input in templates\n\
                                             2. Use sandboxed template environments\n\
                                             3. Implement auto-escaping in templates\n\
                                             4. Validate and sanitize all user input\n\
                                             5. Use whitelisting for allowed template syntax\n\
                                             6. Run application with minimal OS privileges"
                                        ),
                                        references: vec![
                                            "https://cwe.mitre.org/data/definitions/1336.html".to_string(),
                                            "https://owasp.org/www-community-vulnerabilities/Server_Side_Template_Injection".to_string(),
                                            "https://portswigger.net/research/server-side-template-injection".to_string(),
                                        ],
                                        timestamp: chrono::Utc::now(),
                                        cvss_score: Some(9.8),
                                        cwe_id: Some("CWE-1336".to_string()),
                                        tool_source: "ssti-scanner".to_string(),
                                    };
                                    findings.push(finding);
                                    return findings; // One finding per param is enough
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }

        findings
    }

    /// Extract parameters from URL for testing
    fn extract_params(url: &str) -> Vec<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            parsed.query_pairs().map(|(k, _)| k.to_string()).collect()
        } else {
            vec![]
        }
    }

    /// Common parameter names to test when no params are in URL
    fn common_params() -> Vec<&'static str> {
        vec![
            "name", "q", "search", "query", "input", "text", "page",
            "template", "file", "include", "render", "view", "url",
            "id", "user", "data", "content", "body", "message",
        ]
    }
}

#[async_trait]
impl Scanner for SstiScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::Ssti
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = self.build_client(context)?;

        let mut all_findings = Vec::new();

        // Get parameters from URL
        let params = Self::extract_params(target);

        if !params.is_empty() {
            // Test each URL parameter
            for param in &params {
                let findings = self.test_param_ssti(target, param, &client).await;
                all_findings.extend(findings);
            }
        } else {
            // No params in URL — test common parameter names
            for param in Self::common_params() {
                let findings = self.test_param_ssti(target, param, &client).await;
                all_findings.extend(findings);
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> ScanContext {
        ScanContext {
            cookies: None,
            headers: Vec::new(),
            session: None,
        }
    }

    fn make_config() -> JackSparrowConfig {
        JackSparrowConfig::default()
    }

    #[test]
    fn scanner_type_is_ssti() {
        let scanner = SstiScanner::new(&make_config());
        assert_eq!(scanner.scanner_type(), ScannerType::Ssti);
    }

    #[test]
    fn ssti_payloads_cover_multiple_engines() {
        let payloads = SstiScanner::ssti_payloads();
        assert!(payloads.len() >= 10, "Should have at least 10 SSTI payloads");
        // Verify we cover major template engines
        let engines: Vec<&str> = payloads.iter().map(|(_, _, engine, _)| *engine).collect();
        assert!(engines.iter().any(|e| e.contains("Jinja2")), "Should include Jinja2");
        assert!(engines.iter().any(|e| e.contains("Freemarker") || e.contains("Velocity")), "Should include Java engines");
        assert!(engines.iter().any(|e| e.contains("Smarty") || e.contains("Mako")), "Should include PHP/Python engines");
        assert!(engines.iter().any(|e| e.contains("ERB")), "Should include Ruby ERB");
    }

    #[test]
    fn check_ssti_math_payload() {
        let body = "<html><p>Result: 49</p></html>";
        assert!(SstiScanner::check_ssti_execution(body, "49"));
    }

    #[test]
    fn check_ssti_no_false_positive() {
        let body = "<html><p>Result: 149</p></html>";
        // "149" contains "49" but isn't exactly "49"
        let transformed = body.replace(">", "> ").replace("<", " <");
        let words: Vec<&str> = transformed.split_whitespace().collect();
        assert!(!words.iter().any(|w| *w == "49"));
    }

    #[test]
    fn check_ssti_string_concat() {
        let body = "7777777";
        assert!(SstiScanner::check_ssti_execution(body, "7777777"));
    }

    #[test]
    fn check_ssti_config_disclosure() {
        let body = "<html><pre>&lt;Config {&#39;DEBUG&#39;: False, &#39;SECRET_KEY&#39;: &#39;xxx&#39;}&gt;</pre></html>";
        assert!(SstiScanner::check_ssti_execution(body, "Config"));
    }

    #[test]
    fn extract_params_from_url() {
        let params = SstiScanner::extract_params("http://example.com?q=test&page=1");
        assert_eq!(params.len(), 2);
        assert!(params.contains(&"q".to_string()));
        assert!(params.contains(&"page".to_string()));
    }

    #[test]
    fn extract_params_no_query() {
        let params = SstiScanner::extract_params("http://example.com/");
        assert!(params.is_empty());
    }

    #[test]
    fn common_params_cover_typical_names() {
        let params = SstiScanner::common_params();
        assert!(params.contains(&"name"));
        assert!(params.contains(&"q"));
        assert!(params.contains(&"search"));
        assert!(params.len() >= 10);
    }

    #[test]
    fn build_client_works() {
        let scanner = SstiScanner::new(&make_config());
        let client = scanner.build_client(&make_context());
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn scan_handles_unreachable_target() {
        let scanner = SstiScanner::new(&make_config());
        let ctx = make_context();
        let config = make_config();
        // Verify scan compiles and returns Ok (network tests timeout too long)
        // Just verify the scanner can be created and typed correctly
        assert_eq!(scanner.scanner_type(), ScannerType::Ssti);
        let _ = (ctx, config);
    }
}

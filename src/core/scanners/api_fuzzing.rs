#![allow(dead_code)]

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

const FUZZ_PAYLOADS: &[(&str, &str)] = &[
    ("' OR '1'='1", "SQL injection probe"),
    ("<script>alert(1)</script>", "XSS probe"),
    ("{{7*7}}", "SSTI probe"),
    ("../../etc/passwd", "Path traversal probe"),
    ("null", "Null value"),
    ("[]", "Array value"),
    ("{}", "Object value"),
    ("1; ls", "Command injection"),
    ("1| ls", "Command injection pipe"),
    ("%00", "Null byte"),
    ("%0d%0a", "CRLF injection"),
    ("javascript:alert(1)", "JavaScript URI"),
    ("${7*7}", "Expression injection"),
];

const COMMON_PARAMS: &[&str] = &[
    "id", "user_id", "uid", "token", "key", "search", "q", "query", "filter", "file", "path",
    "url", "redirect", "next", "admin", "debug", "test", "mode", "type", "callback", "cmd", "exec",
    "action", "service", "api",
];

const SQL_ERROR_PATTERNS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "pg_query",
    "pg_exec",
    "error: syntax error at or near",
    "microsoft oledb provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "ora-00933",
    "quoted string not properly terminated",
    "sqlite_error",
    "sqlstate",
];

const DEBUG_PATTERNS: &[(&str, &str)] = &[
    ("stacktrace", "Stack trace exposed"),
    ("traceback", "Traceback exposed"),
    ("at line", "Line number exposed"),
    ("syntaxerror", "Parser error exposed"),
    ("uncaught exception", "Exception details exposed"),
    ("fatal error", "Fatal error details exposed"),
    ("internal server error", "Verbose internal error"),
    ("nullpointerexception", "Java exception exposed"),
    ("typeerror", "Type error details exposed"),
    ("referenceerror", "Reference error details exposed"),
];

pub struct ApiFuzzingScanner {
    client: Client,
}

impl ApiFuzzingScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        let timeout = Duration::from_secs(config.general.timeout_secs.min(10));
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    fn build_client() -> Result<Client, JackSparrowError> {
        Ok(Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?)
    }

    async fn test_param_fuzz(
        &self,
        base_url: &str,
        param: &str,
        payload: &str,
        context: &ScanContext,
    ) -> Result<(u16, String), JackSparrowError> {
        let url = format!("{}?{}={}", base_url, param, payload);
        let mut req = self.client.get(&url);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "api-fuzzing".to_string(),
                message: e.to_string(),
            })?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }

    async fn test_body_fuzz(
        &self,
        base_url: &str,
        param: &str,
        payload: &str,
        context: &ScanContext,
    ) -> Result<(u16, String), JackSparrowError> {
        let mut req = self.client.post(base_url).form(&[(param, payload)]);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "api-fuzzing".to_string(),
                message: e.to_string(),
            })?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }

    fn detect_error_patterns(body: &str) -> Option<String> {
        let lower = body.to_lowercase();
        for pattern in SQL_ERROR_PATTERNS {
            if lower.contains(pattern) {
                return Some(pattern.to_string());
            }
        }
        for (pattern, description) in DEBUG_PATTERNS {
            if lower.contains(pattern) {
                return Some(description.to_string());
            }
        }
        None
    }

    fn detect_reflection(body: &str, payload: &str) -> bool {
        body.contains(payload)
    }

    fn make_finding(
        title: String,
        url: String,
        param: &str,
        payload: &str,
        error: &str,
        description: &str,
        cwe: &str,
        remediation: &str,
    ) -> Finding {
        let mut f = Finding::new(
            VulnerabilityType::ApiSecurity,
            Severity::Medium,
            Confidence::Likely,
            title,
            url,
            "api-fuzzing-scanner".to_string(),
        );
        f.description = description.to_string();
        f.parameter = Some(param.to_string());
        f.evidence = Evidence {
            request: None,
            response: Some(error.to_string()),
            payload: Some(payload.to_string()),
            pattern: Some(error.to_string()),
            context: None,
        };
        f.cvss_score = Some(5.3);
        f.cwe_id = Some(cwe.to_string());
        f.remediation = remediation.to_string();
        f
    }

    fn evaluate_response(
        status: u16,
        body: &str,
        param: &str,
        payload: &str,
        description: &str,
        base_url: &str,
        method: &str,
    ) -> Option<Finding> {
        let error = Self::detect_error_patterns(body)?;
        let error_lower = error.to_lowercase();

        // SQL error detection
        if error_lower.contains("sql") || error_lower.contains("syntax") {
            let url = format!("{}?{}={}", base_url, param, payload);
            let req_str = if method == "GET" {
                format!("GET {}", url)
            } else {
                format!("POST {} [{}={}]", base_url, param, payload)
            };
            let mut f = Self::make_finding(
                format!("SQL error via {} parameter [{}]", method, param),
                url,
                param,
                payload,
                &error,
                &format!(
                    "{} fuzz payload '{}' triggered SQL error in parameter '{}': {}",
                    method, payload, param, error
                ),
                "CWE-89",
                "Use parameterized queries. Validate and sanitize all user input.",
            );
            f.evidence.request = Some(req_str);
            f.evidence.context = Some(description.to_string());
            return Some(f);
        }

        // Debug info disclosure (HTTP 500 + non-SQL error)
        if status == 500 && !error_lower.contains("sql") {
            let url = format!("{}?{}={}", base_url, param, payload);
            let req_str = if method == "GET" {
                format!("GET {}", url)
            } else {
                format!("POST {} [{}={}]", base_url, param, payload)
            };
            let mut f = Self::make_finding(
				format!("Debug info disclosed via {}", method),
				url,
				param,
				payload,
				&error,
				&format!("Server error with debug info at {} parameter '{}' matching: {}", method.to_lowercase(), param, error),
				"CWE-209",
				"Replace verbose error messages with generic responses. Log details server-side only.",
			);
            f.evidence.request = Some(req_str);
            f.evidence.context = Some(description.to_string());
            f.confidence = Confidence::Possible;
            return Some(f);
        }

        // XSS reflection
        if Self::detect_reflection(body, payload)
            && (payload.contains("<script>") || payload.contains("javascript:"))
        {
            let url = format!("{}?{}={}", base_url, param, payload);
            let req_str = if method == "GET" {
                format!("GET {}", url)
            } else {
                format!("POST {} [{}={}]", base_url, param, payload)
            };
            let mut f = Self::make_finding(
                format!("XSS payload reflected via {}", method),
                url,
                param,
                payload,
                payload,
                &format!(
                    "XSS probe '{}' was reflected in {} response via parameter '{}'",
                    payload,
                    method.to_lowercase(),
                    param
                ),
                "CWE-79",
                "Encode all output data. Implement Content-Security-Policy.",
            );
            f.evidence.request = Some(req_str);
            f.evidence.context = Some(description.to_string());
            return Some(f);
        }

        None
    }
}

#[async_trait]
impl Scanner for ApiFuzzingScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::ApiFuzzing
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let base = target.trim_end_matches('/');
        let mut findings = Vec::new();

        for param in COMMON_PARAMS {
            for (payload, description) in FUZZ_PAYLOADS {
                if let Ok((status, body)) =
                    self.test_param_fuzz(base, param, payload, context).await
                {
                    if let Some(f) = Self::evaluate_response(
                        status,
                        &body,
                        param,
                        payload,
                        description,
                        base,
                        "GET",
                    ) {
                        findings.push(f);
                        break;
                    }
                }

                if let Ok((status, body)) = self.test_body_fuzz(base, param, payload, context).await
                {
                    if let Some(f) = Self::evaluate_response(
                        status,
                        &body,
                        param,
                        payload,
                        description,
                        base,
                        "POST",
                    ) {
                        findings.push(f);
                        break;
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type() {
        let scanner = ApiFuzzingScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::ApiFuzzing);
    }

    #[test]
    fn test_fuzz_payloads_list() {
        assert!(!FUZZ_PAYLOADS.is_empty());
        assert!(FUZZ_PAYLOADS.iter().any(|(p, _)| p.contains("script")));
        assert!(FUZZ_PAYLOADS.iter().any(|(p, _)| p.contains("OR")));
        assert!(FUZZ_PAYLOADS.iter().any(|(_, d)| d.contains("SQL")));
    }

    #[test]
    fn test_common_params_list() {
        assert!(!COMMON_PARAMS.is_empty());
        assert!(COMMON_PARAMS.contains(&"id"));
        assert!(COMMON_PARAMS.contains(&"token"));
        assert!(COMMON_PARAMS.contains(&"debug"));
    }

    #[test]
    fn test_new_scanner() {
        let scanner = ApiFuzzingScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::ApiFuzzing);
    }

    #[test]
    fn test_build_client() {
        let client = ApiFuzzingScanner::build_client().unwrap();
        let _ = client.get("http://localhost").build();
    }

    #[test]
    fn test_detect_error_patterns_sql() {
        let body = "You have an error in your SQL syntax near 'test'";
        let result = ApiFuzzingScanner::detect_error_patterns(body);
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_reflection() {
        let body = r#"<html><script>alert(1)</script></html>"#;
        assert!(ApiFuzzingScanner::detect_reflection(
            body,
            "<script>alert(1)</script>"
        ));
        assert!(!ApiFuzzingScanner::detect_reflection(body, "safe_string"));
    }

    #[test]
    fn test_default_config() {
        let config = JackSparrowConfig::default();
        let scanner = ApiFuzzingScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::ApiFuzzing);
    }
}

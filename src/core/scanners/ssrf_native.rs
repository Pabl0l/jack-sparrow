use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use url::Url;

/// Native SSRF scanner — no external tools required.
///
/// Detects: internal endpoint access, cloud metadata, port scanning, file reads.
pub struct NativeSsrfScanner;

impl NativeSsrfScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	fn build_client(&self, context: &ScanContext) -> Result<Client, JackSparrowError> {
		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert(
			"User-Agent",
			reqwest::header::HeaderValue::from_static("JackSparrow/0.4.0"),
		);
		for (key, value) in &context.headers {
			if let (Ok(k), Ok(v)) = (
				reqwest::header::HeaderName::from_bytes(key.as_bytes()),
				reqwest::header::HeaderValue::from_str(value),
			) {
				headers.insert(k, v);
			}
		}
		Ok(Client::builder()
			.default_headers(headers)
			.danger_accept_invalid_certs(true)
			.redirect(reqwest::redirect::Policy::none())
			.timeout(std::time::Duration::from_secs(8))
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "native-ssrf".to_string(),
				message: e.to_string(),
			})?)
	}

	/// Extract URL-type parameters from the target URL (e.g., ?url=..., ?fetch=..., ?link=...)
	fn find_url_params(url_str: &str) -> Vec<String> {
		let url_params = [
			"url", "uri", "link", "fetch", "load", "href", "src", "dest",
			"redirect", "return", "next", "continue", "target", "path", "file",
			"page", "document", "site", "proxy", "image", "img", "avatar",
		];
		if let Ok(url) = Url::parse(url_str) {
			url.query_pairs()
				.filter(|(k, _)| url_params.contains(&k.to_lowercase().as_str()))
				.map(|(k, _)| k.to_string())
				.collect()
		} else {
			Vec::new()
		}
	}

	/// Build URL with modified parameter value
	fn build_url(base: &str, param: &str, value: &str) -> Result<String, JackSparrowError> {
		let mut url = Url::parse(base).map_err(|e| JackSparrowError::InvalidTarget { url: e.to_string() })?;
		let mut pairs: Vec<(String, String)> = url.query_pairs()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect();
		for (k, v) in &mut pairs {
			if k == param {
				*v = value.to_string();
				break;
			}
		}
		url.query_pairs_mut().clear();
		for (k, v) in &pairs {
			url.query_pairs_mut().append_pair(k, v);
		}
		Ok(url.to_string())
	}

	/// Fetch and return (status, body, headers)
	async fn fetch(
		&self,
		client: &Client,
		url: &str,
		context: &ScanContext,
	) -> Result<(u16, String, String), JackSparrowError> {
		let mut req = client.get(url);
		if let Some(ref cookies) = context.cookies {
			req = req.header("Cookie", cookies.as_str());
		}
		let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
			tool: "native-ssrf".to_string(),
			message: e.to_string(),
		})?;
		let status = resp.status().as_u16();
		let headers = format!("{:?}", resp.headers());
		let body = resp.text().await.unwrap_or_default();
		Ok((status, body, headers))
	}

	/// Check if response contains internal/leaked data
	fn detect_internal_access(body: &str, status: u16) -> Option<String> {
		let indicators = [
			// Linux /etc/passwd
			("root:x:0:0:", "Linux /etc/passwd leaked"),
			("root:*:0:0:", "macOS /etc/passwd leaked"),
			// AWS metadata
			("instance-id", "AWS EC2 instance metadata"),
			("ami-id", "AWS AMI metadata"),
			("iam/security-credentials", "AWS IAM credentials endpoint"),
			// GCP metadata
			("computeMetadata/v1", "GCP metadata endpoint"),
			// Azure metadata
			("Metadata/Instance", "Azure instance metadata"),
			// Internal hostnames
			("localhost", "Internal localhost reference"),
			("127.0.0.1", "Internal loopback reference"),
			// Docker
			("docker", "Docker internal reference"),
			// Database connection strings
			("mysql://", "MySQL connection string"),
			("postgres://", "PostgreSQL connection string"),
			("mongodb://", "MongoDB connection string"),
			// Private IP ranges
			("192.168.", "Private IP 192.168.x.x"),
			("10.0.0.", "Private IP 10.x.x.x"),
			("172.16.", "Private IP 172.16.x.x"),
		];

		let body_lower = body.to_lowercase();
		for (pattern, description) in &indicators {
			if body_lower.contains(&pattern.to_lowercase()) {
				return Some(description.to_string());
			}
		}

		// Check for interesting status codes when probing internal endpoints
		if status == 200 && body.len() > 100 {
			// Response with substantial content from internal probe
			if body_lower.contains("html") && (body_lower.contains("admin") || body_lower.contains("dashboard")) {
				return Some("Internal admin panel accessible".to_string());
			}
		}

		None
	}

	/// Get SSRF probe targets (internal endpoints to test)
	fn ssrf_probes() -> Vec<(&'static str, &'static str)> {
		vec![
			// Internal services
			("http://127.0.0.1", "Loopback (127.0.0.1)"),
			("http://localhost", "Loopback (localhost)"),
			("http://0.0.0.0", "Zero address (0.0.0.0)"),
			// Cloud metadata
			("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
			("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
			("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
			("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
			// Kubernetes
			("https://kubernetes.default.svc", "Kubernetes API"),
			("http://10.0.0.1:443", "Kubernetes API (10.0.0.1)"),
		]
	}

	/// Check if response is different from baseline (indicates SSRF worked)
	fn is_different_from_baseline(baseline: &str, response: &str) -> bool {
		if baseline.is_empty() || response.is_empty() {
			return false;
		}
		// Significant length difference
		let len_diff = (baseline.len() as i64 - response.len() as i64).abs();
		if len_diff > 100 {
			return true;
		}
		// Content is substantially different
		baseline != response
	}
}

#[async_trait]
impl Scanner for NativeSsrfScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::Ssrf
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = self.build_client(context)?;
		let url_params = Self::find_url_params(target);

		if url_params.is_empty() {
			return Ok(Vec::new());
		}

		let mut findings = Vec::new();

		for param in &url_params {
			// Get baseline response (with a normal value)
			let baseline_url = Self::build_url(target, param, "test")?;
			let baseline = self.fetch(&client, &baseline_url, context).await;
			let baseline_body = baseline.as_ref().map(|(_, b, _)| b.clone()).unwrap_or_default();

			// Test each SSRF probe
			for (probe_url, description) in Self::ssrf_probes() {
				let inject_url = Self::build_url(target, param, probe_url)?;
				if let Ok((status, body, _headers)) = self.fetch(&client, &inject_url, context).await {
					// Check for direct internal access indicators
					if let Some(indicator) = Self::detect_internal_access(&body, status) {
						let severity = if probe_url.contains("169.254.169.254") {
							Severity::Critical // Cloud metadata = critical
						} else if probe_url.contains("127.0.0.1") || probe_url.contains("localhost") {
							Severity::High
						} else {
							Severity::Medium
						};
						let cvss = if severity == Severity::Critical { 9.0 } else { 7.5 };

						let mut finding = Finding::new(
							VulnerabilityType::Ssrf,
							severity,
							Confidence::Confirmed,
							format!("SSRF: {} via parameter '{}' — {}", description, param, indicator),
							target.to_string(),
							"native-ssrf-scanner".to_string(),
						);
						finding.parameter = Some(param.clone());
						finding.evidence = Evidence {
							request: Some(format!("GET {}", inject_url)),
							response: Some(format!("Status: {}, Indicator: {}", status, indicator)),
							payload: Some(probe_url.to_string()),
							pattern: Some(indicator),
							context: Some(description.to_string()),
						};
						finding.cwe_id = Some("CWE-918".to_string());
						finding.cvss_score = Some(cvss);
						finding.remediation = "Validate and sanitize URL inputs. Use allowlists for permitted domains. Block requests to internal IP ranges and cloud metadata endpoints.".to_string();
						finding.references = vec![
							"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
						];
						findings.push(finding);
						break; // One finding per parameter
					}

					// Check for response difference (blind SSRF)
					if !baseline_body.is_empty()
						&& status != 0
						&& Self::is_different_from_baseline(&baseline_body, &body)
						&& !body.contains("error")
						&& !body.contains("404")
					{
						// Only report if we got a 200 from an internal probe
						if status == 200 && probe_url.contains("127.0.0.1") || probe_url.contains("localhost") {
							let mut finding = Finding::new(
								VulnerabilityType::Ssrf,
								Severity::Medium,
								Confidence::Likely,
								format!("Blind SSRF: internal endpoint reachable via parameter '{}'", param),
								target.to_string(),
								"native-ssrf-scanner".to_string(),
							);
							finding.parameter = Some(param.clone());
							finding.evidence = Evidence {
								request: Some(format!("GET {}", inject_url)),
								response: Some(format!("Status: {}, Body: {} bytes (baseline: {} bytes)", status, body.len(), baseline_body.len())),
								payload: Some(probe_url.to_string()),
								pattern: Some("Different response from internal endpoint".to_string()),
								context: Some(description.to_string()),
							};
							finding.cwe_id = Some("CWE-918".to_string());
							finding.cvss_score = Some(6.5);
							finding.remediation = "Validate and sanitize URL inputs. Use allowlists for permitted domains.".to_string();
							finding.references = vec!["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string()];
							findings.push(finding);
							break;
						}
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
	fn test_find_url_params() {
		let params = NativeSsrfScanner::find_url_params("http://example.com/fetch?url=http://evil.com&name=test");
		assert!(params.contains(&"url".to_string()));
		assert!(!params.contains(&"name".to_string()));
	}

	#[test]
	fn test_find_url_params_multiple() {
		let params = NativeSsrfScanner::find_url_params("http://example.com/page?link=foo&redirect=bar&safe=1");
		assert_eq!(params.len(), 2);
	}

	#[test]
	fn test_detect_internal_access_passwd() {
		let body = "root:x:0:0:root:/root:/bin/bash";
		assert!(NativeSsrfScanner::detect_internal_access(body, 200).is_some());
	}

	#[test]
	fn test_detect_internal_access_aws() {
		let body = r#"{"ami-id": "ami-12345", "instance-id": "i-12345"}"#;
		assert!(NativeSsrfScanner::detect_internal_access(body, 200).is_some());
	}

	#[test]
	fn test_no_false_positive_normal_page() {
		let body = "<html><body>Hello World</body></html>";
		assert!(NativeSsrfScanner::detect_internal_access(body, 200).is_none());
	}

	#[test]
	fn test_ssrf_probes_not_empty() {
		assert!(!NativeSsrfScanner::ssrf_probes().is_empty());
	}

	#[test]
	fn test_scanner_type() {
		let scanner = NativeSsrfScanner;
		assert_eq!(scanner.scanner_type(), ScannerType::Ssrf);
	}
}

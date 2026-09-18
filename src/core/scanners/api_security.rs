use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;

/// Common REST API paths to probe
const COMMON_API_PATHS: &[&str] = &[
	"/api", "/api/v1", "/api/v2",
	"/rest", "/rest/v1",
	"/graphql", "/gql",
	"/swagger.json", "/openapi.json", "/api-docs",
	"/.well-known/openapi.json",
	"/api/health", "/api/status", "/api/info", "/api/version",
	"/api/config", "/api/settings",
	"/api/users", "/api/user", "/api/accounts",
	"/api/admin", "/api/internal",
	"/api/debug", "/api/logs", "/api/metrics",
];

/// HTTP methods to test for method-based access control
const TEST_METHODS: &[&str] = &["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"];

/// Patterns indicating verbose error messages
const ERROR_PATTERNS: &[(&str, &str)] = &[
	("stacktrace", "Stack trace exposed"),
	("traceback", "Traceback exposed"),
	("at line", "Line number exposed"),
	("SyntaxError", "Parser error exposed"),
	("SQLSTATE", "SQL error exposed"),
	("ORA-", "Oracle error exposed"),
	("MySQL", "MySQL error exposed"),
	("PostgreSQL", "PostgreSQL error exposed"),
	("Uncaught Exception", "Exception details exposed"),
	("fatal error", "Fatal error details exposed"),
	("internal server error", "Verbose internal error"),
	("NullPointerException", "Java exception exposed"),
	("TypeError", "Type error details exposed"),
	("ReferenceError", "Reference error details exposed"),
];

/// Check for CORS misconfiguration indicators
fn check_cors(response: &reqwest::Response) -> Option<(Severity, String, String)> {
	if let Some(aoc) = response.headers().get("access-control-allow-origin") {
		let aoc_str = aoc.to_str().unwrap_or("");
		if aoc_str == "*" {
			return Some((
				Severity::Medium,
				"CORS allows all origins (*)".to_string(),
				"Set Access-Control-Allow-Origin to specific trusted domains.".to_string(),
			));
		}
	}
	if let Some(aoc) = response.headers().get("access-control-allow-credentials") {
		let val = aoc.to_str().unwrap_or("");
		if val == "true" {
			if let Some(origin) = response.headers().get("access-control-allow-origin") {
				if origin.to_str().unwrap_or("") == "*" {
					return Some((
						Severity::High,
						"CORS: credentials allowed with wildcard origin".to_string(),
						"Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true. This is a critical misconfiguration.".to_string(),
					));
				}
			}
		}
	}
	None
}

/// API Security Scanner
///
/// Checks:
/// 1. REST API endpoint discovery (common paths)
/// 2. HTTP method enumeration (OPTIONS, TRACE, etc.)
/// 3. CORS misconfiguration detection
/// 4. Verbose error message detection
/// 5. Missing authentication indicators
/// 6. Rate limiting presence
/// 7. Information disclosure headers
pub struct ApiSecurityScanner;

impl ApiSecurityScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}
}

#[async_trait]
impl Scanner for ApiSecurityScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::ApiSecurity
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = reqwest::Client::builder()
			.timeout(std::time::Duration::from_secs(10))
			.danger_accept_invalid_certs(true)
			.build()?;

		let base = target.trim_end_matches('/');
		let mut all_findings = Vec::new();

		// 1. CORS check on base URL
		{
			let mut req = client.request(reqwest::Method::OPTIONS, base);
			for (k, v) in &context.headers {
				req = req.header(k.as_str(), v.as_str());
			}
			req = req.header("Origin", "https://evil.com");
			if let Ok(resp) = req.send().await {
				if let Some((sev, title, remediation)) = check_cors(&resp) {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						sev,
						Confidence::Confirmed,
						title,
						base.to_string(),
						"api-security-scanner".to_string(),
					);
					finding.description = "CORS misconfiguration detected on the target API.".to_string();
					finding.remediation = remediation;
					finding.evidence = Evidence {
						request: Some(format!("OPTIONS {} Origin: https://evil.com", base)),
						response: Some(format!("Access-Control-Allow-Origin: {}", resp.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok()).unwrap_or("unset"))),
						payload: None,
						pattern: Some("Access-Control-Allow-Origin".to_string()),
						context: None,
					};
					finding.references = vec![
						"https://portswigger.net/web-security/cors".to_string(),
					];
					finding.cvss_score = Some(5.3);
					finding.cwe_id = Some("CWE-942".to_string());
					all_findings.push(finding);
				}
			}
		}

		// 2. Probe common API paths
		for path in COMMON_API_PATHS {
			let url = format!("{}{}", base, path);
			let mut req = client.get(&url);
			for (k, v) in &context.headers {
				req = req.header(k.as_str(), v.as_str());
			}
			if let Some(ref cookies) = context.cookies {
				req = req.header("Cookie", cookies.as_str());
			}

			if let Ok(resp) = req.send().await {
				let status = resp.status();
				let content_type = resp.headers()
					.get("content-type")
					.and_then(|v| v.to_str().ok())
					.unwrap_or("")
					.to_string();
				let server = resp.headers()
					.get("server")
					.and_then(|v| v.to_str().ok())
					.unwrap_or("")
					.to_string();
				let x_powered = resp.headers()
					.get("x-powered-by")
					.and_then(|v| v.to_str().ok())
					.unwrap_or("")
					.to_string();
				let x_asp_net = resp.headers()
					.get("x-aspnet-version")
					.and_then(|v| v.to_str().ok())
					.unwrap_or("")
					.to_string();

				// Found an API endpoint
				if status.is_success() || status.as_u16() == 401 || status.as_u16() == 403 {
					if content_type.contains("json") || content_type.contains("yaml") {
						let mut finding = Finding::new(
							VulnerabilityType::ApiSecurity,
							Severity::Info,
							Confidence::Confirmed,
							format!("API endpoint discovered: {}", path),
							url.clone(),
							"api-security-scanner".to_string(),
						);
						finding.description = format!(
							"API endpoint found at {} (HTTP {}, content-type: {})",
							path, status.as_u16(), content_type
						);
						finding.evidence = Evidence {
							request: Some(format!("GET {}", url)),
							response: Some(format!("HTTP {} Content-Type: {}", status.as_u16(), content_type)),
							payload: None,
							pattern: Some(path.to_string()),
							context: None,
						};
						finding.cvss_score = Some(0.0);
						all_findings.push(finding);
					}
				}

				// Check for information disclosure via headers
				if !server.is_empty() {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						Severity::Low,
						Confidence::Confirmed,
						"Server header reveals software version".to_string(),
						url.clone(),
						"api-security-scanner".to_string(),
					);
					finding.description = format!("Server header: {}", server);
					finding.remediation = "Remove or obfuscate the Server header to prevent version fingerprinting.".to_string();
					finding.evidence = Evidence {
						request: Some(format!("GET {}", url)),
						response: Some(format!("Server: {}", server)),
						payload: None,
						pattern: Some("Server:".to_string()),
						context: None,
					};
					finding.cvss_score = Some(0.0);
					finding.cwe_id = Some("CWE-200".to_string());
					all_findings.push(finding);
					break; // Only report server header once
				}
				if !x_powered.is_empty() {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						Severity::Low,
						Confidence::Confirmed,
						"X-Powered-By header reveals technology".to_string(),
						url.clone(),
						"api-security-scanner".to_string(),
					);
					finding.description = format!("X-Powered-By: {}", x_powered);
					finding.remediation = "Remove the X-Powered-By header.".to_string();
					finding.cvss_score = Some(0.0);
					finding.cwe_id = Some("CWE-200".to_string());
					all_findings.push(finding);
				}
				if !x_asp_net.is_empty() {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						Severity::Low,
						Confidence::Confirmed,
						"X-AspNet-Version header reveals version".to_string(),
						url.clone(),
						"api-security-scanner".to_string(),
					);
					finding.description = format!("X-AspNet-Version: {}", x_asp_net);
					finding.remediation = "Remove the X-AspNet-Version header.".to_string();
					finding.cvss_score = Some(0.0);
					finding.cwe_id = Some("CWE-200".to_string());
					all_findings.push(finding);
				}

				// Check for verbose errors in response body
				if status.is_server_error() {
					let body = resp.text().await.unwrap_or_default();
					let body_lower = body.to_lowercase();
					for (pattern, description) in ERROR_PATTERNS {
						if body_lower.contains(&pattern.to_lowercase()) {
							let mut finding = Finding::new(
								VulnerabilityType::ApiSecurity,
								Severity::Medium,
								Confidence::Likely,
								description.to_string(),
								url.clone(),
								"api-security-scanner".to_string(),
							);
							finding.description = format!(
								"Verbose error message detected at {} matching pattern '{}'.",
								path, pattern
							);
							finding.evidence = Evidence {
								request: Some(format!("GET {}", url)),
								response: Some(body[..body.len().min(300)].to_string()),
								payload: None,
								pattern: Some(pattern.to_string()),
								context: None,
							};
							finding.remediation = "Replace verbose error messages with generic error responses. Log detailed errors server-side only.".to_string();
							finding.cvss_score = Some(5.3);
							finding.cwe_id = Some("CWE-209".to_string());
							all_findings.push(finding);
							break; // One per path
						}
					}
				}
			}
		}

		// 3. HTTP method enumeration on base URL
		for method in TEST_METHODS {
			let mut req = match *method {
				"OPTIONS" => client.request(reqwest::Method::OPTIONS, base),
				"TRACE" => client.request(reqwest::Method::TRACE, base),
				"PUT" => client.put(base),
				"DELETE" => client.delete(base),
				"PATCH" => client.patch(base),
				_ => continue,
			};
			for (k, v) in &context.headers {
				req = req.header(k.as_str(), v.as_str());
			}

			if let Ok(resp) = req.send().await {
				let status = resp.status();

				// TRACE method should be disabled (XST risk)
				if *method == "TRACE" && status.is_success() {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						Severity::Medium,
						Confidence::Confirmed,
						"TRACE method enabled (XST risk)".to_string(),
						base.to_string(),
						"api-security-scanner".to_string(),
					);
					finding.description = "The HTTP TRACE method is enabled. This can be exploited via Cross-Site Tracing (XST) to steal cookies via XSS.".to_string();
					finding.remediation = "Disable the TRACE method on the web server.".to_string();
					finding.evidence = Evidence {
						request: Some(format!("TRACE {}", base)),
						response: Some(format!("HTTP {}", status.as_u16())),
						payload: None,
						pattern: Some("TRACE".to_string()),
						context: None,
					};
					finding.cvss_score = Some(5.3);
					finding.cwe_id = Some("CWE-16".to_string());
					all_findings.push(finding);
				}

				// DELETE/PUT returning 200 without auth = access control issue
				if (*method == "DELETE" || *method == "PUT") && status.is_success() {
					let mut finding = Finding::new(
						VulnerabilityType::ApiSecurity,
						Severity::High,
						Confidence::Likely,
						format!("{} method accepted on root URL", method),
						base.to_string(),
						"api-security-scanner".to_string(),
					);
					finding.description = format!(
						"The {} method returned HTTP {} on {}. This may indicate missing access control.",
						method, status.as_u16(), base
					);
					finding.remediation = format!(
						"Ensure {} operations require proper authentication and authorization.",
						method
					);
					finding.evidence = Evidence {
						request: Some(format!("{} {}", method, base)),
						response: Some(format!("HTTP {}", status.as_u16())),
						payload: None,
						pattern: None,
						context: None,
					};
					finding.cvss_score = Some(7.5);
					finding.cwe_id = Some("CWE-284".to_string());
					all_findings.push(finding);
				}
			}
		}

		// 4. Check for rate limiting on base URL
		{
			let mut rate_limited = false;
			for _ in 0..5 {
				let mut req = client.get(base);
				for (k, v) in &context.headers {
					req = req.header(k.as_str(), v.as_str());
				}
				if let Ok(resp) = req.send().await {
					if resp.status().as_u16() == 429 {
						rate_limited = true;
						break;
					}
				}
			}
			if !rate_limited {
				let mut finding = Finding::new(
					VulnerabilityType::ApiSecurity,
					Severity::Low,
					Confidence::Possible,
					"No rate limiting detected".to_string(),
					base.to_string(),
					"api-security-scanner".to_string(),
				);
				finding.description = "5 rapid requests were sent without triggering rate limiting (HTTP 429). The API may be vulnerable to brute-force or DoS attacks.".to_string();
				finding.remediation = "Implement rate limiting on all API endpoints. Return HTTP 429 with Retry-After header when limits are exceeded.".to_string();
				finding.references = vec![
					"https://owasp.org/www-community/controls/Rate_Limiting".to_string(),
				];
				finding.cvss_score = Some(2.5);
				finding.cwe_id = Some("CWE-770".to_string());
				all_findings.push(finding);
			}
		}

		Ok(all_findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_error_patterns_contain_common_errors() {
		assert!(ERROR_PATTERNS.iter().any(|(p, _)| p.contains("SQLSTATE")));
		assert!(ERROR_PATTERNS.iter().any(|(p, _)| p.contains("stacktrace")));
		assert!(ERROR_PATTERNS.iter().any(|(p, _)| p.contains("traceback")));
	}

	#[test]
	fn test_common_api_paths_not_empty() {
		assert!(!COMMON_API_PATHS.is_empty());
		assert!(COMMON_API_PATHS.contains(&"/api"));
		assert!(COMMON_API_PATHS.contains(&"/graphql"));
		assert!(COMMON_API_PATHS.contains(&"/swagger.json"));
	}

	#[test]
	fn test_test_methods_include_risky() {
		assert!(TEST_METHODS.contains(&"TRACE"));
		assert!(TEST_METHODS.contains(&"OPTIONS"));
		assert!(TEST_METHODS.contains(&"DELETE"));
	}
}

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

/// Security header check definition
struct HeaderCheck {
	/// Header name (case-insensitive)
	name: &'static str,
	/// Expected presence: `true` = must exist, `false` = must NOT exist
	must_exist: bool,
	/// If `must_exist`, minimum expected value (substring match)
	min_value: Option<&'static str>,
	/// Severity if missing/weak
	severity: Severity,
	/// CWE reference
	cwe: &'static str,
	/// Remediation advice
	remediation: &'static str,
	/// OWASP reference
	reference: &'static str,
}

/// Build the list of security header checks
fn security_header_checks() -> Vec<HeaderCheck> {
	vec![
		HeaderCheck {
			name: "Content-Security-Policy",
			must_exist: true,
			min_value: None,
			severity: Severity::Medium,
			cwe: "CWE-693",
			remediation: "Implement a Content-Security-Policy header to prevent XSS and data injection",
			reference: "https://owasp.org/www-project-secure-headers/#content-security-policy",
		},
		HeaderCheck {
			name: "X-Frame-Options",
			must_exist: true,
			min_value: None,
			severity: Severity::Medium,
			cwe: "CWE-1021",
			remediation: "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking",
			reference: "https://owasp.org/www-project-secure-headers/#x-frame-options",
		},
		HeaderCheck {
			name: "Strict-Transport-Security",
			must_exist: true,
			min_value: Some("max-age="),
			severity: Severity::Medium,
			cwe: "CWE-319",
			remediation: "Enable HSTS with a long max-age (at least 31536000 seconds)",
			reference: "https://owasp.org/www-project-secure-headers/#strict-transport-security",
		},
		HeaderCheck {
			name: "X-Content-Type-Options",
			must_exist: true,
			min_value: Some("nosniff"),
			severity: Severity::Low,
			cwe: "CWE-693",
			remediation: "Set X-Content-Type-Options to nosniff to prevent MIME type sniffing",
			reference: "https://owasp.org/www-project-secure-headers/#x-content-type-options",
		},
		HeaderCheck {
			name: "Referrer-Policy",
			must_exist: true,
			min_value: None,
			severity: Severity::Low,
			cwe: "CWE-200",
			remediation: "Set Referrer-Policy to limit information leakage (e.g. strict-origin-when-cross-origin)",
			reference: "https://owasp.org/www-project-secure-headers/#referrer-policy",
		},
		HeaderCheck {
			name: "Permissions-Policy",
			must_exist: true,
			min_value: None,
			severity: Severity::Low,
			cwe: "CWE-693",
			remediation: "Set Permissions-Policy to restrict browser features (camera, microphone, geolocation)",
			reference: "https://owasp.org/www-project-secure-headers/#permissions-policy",
		},
		HeaderCheck {
			name: "X-XSS-Protection",
			must_exist: false,
			min_value: None,
			severity: Severity::Info,
			cwe: "CWE-79",
			remediation: "Remove X-XSS-Protection header (deprecated, can introduce vulnerabilities in older browsers)",
			reference: "https://owasp.org/www-project-secure-headers/#x-xss-protection",
		},
	]
}

pub struct SecurityHeadersScanner;

impl SecurityHeadersScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}
}

#[async_trait]
impl Scanner for SecurityHeadersScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::SecurityHeaders
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		// Build client with auth headers
		let mut headers = reqwest::header::HeaderMap::new();
		for (key, value) in &context.headers {
			if let (Ok(name), Ok(val)) = (
				reqwest::header::HeaderName::from_bytes(key.as_bytes()),
				reqwest::header::HeaderValue::from_str(value),
			) {
				headers.insert(name, val);
			}
		}
		if let Some(ref cookies) = context.cookies {
			if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
				headers.insert(reqwest::header::COOKIE, val);
			}
		}

		let client = Client::builder()
			.default_headers(headers)
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "headers-scanner".to_string(),
				message: e.to_string(),
			})?;

		// Send request to get headers
		let response = client.get(target).send().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "headers-scanner".to_string(),
				message: e.to_string(),
			}
		})?;

		let response_headers = response.headers().clone();
		let status = response.status();

		let checks = security_header_checks();
		let mut findings = Vec::new();

		for check in &checks {
			let header_value = response_headers
				.get(check.name)
				.and_then(|v| v.to_str().ok());

			match check.must_exist {
				true => {
					// Header must exist
					match header_value {
						None => {
							// Missing header
							let mut finding = Finding::new(
								VulnerabilityType::SecurityHeader,
								check.severity.clone(),
								Confidence::Confirmed,
								format!("Missing security header: {}", check.name),
								target.to_string(),
								"headers-scanner".to_string(),
							);
							finding.description = format!(
								"The '{}' header is missing. {}",
								check.name, check.remediation
							);
							finding.evidence = Evidence {
								request: Some(format!("GET {} HTTP/1.1", target)),
								response: Some(format!("Status: {}, Header '{}' not present", status, check.name)),
								payload: None,
								pattern: Some(check.name.to_string()),
								context: None,
							};
							finding.cwe_id = Some(check.cwe.to_string());
							finding.remediation = check.remediation.to_string();
							finding.references = vec![check.reference.to_string()];
							findings.push(finding);
						}
						Some(value) => {
							// Header exists, check value if required
							if let Some(min) = check.min_value {
								if !value.to_lowercase().contains(&min.to_lowercase()) {
									let mut finding = Finding::new(
										VulnerabilityType::SecurityHeader,
										check.severity.clone(),
										Confidence::Confirmed,
										format!("Weak security header: {}", check.name),
										target.to_string(),
										"headers-scanner".to_string(),
									);
									finding.description = format!(
										"The '{}' header has a weak value: '{}'. {}",
										check.name, value, check.remediation
									);
									finding.evidence = Evidence {
										request: Some(format!("GET {} HTTP/1.1", target)),
										response: Some(format!(
											"Status: {}, {}={}",
											status, check.name, value
										)),
										payload: None,
										pattern: Some(check.name.to_string()),
										context: Some(value.to_string()),
									};
									finding.cwe_id = Some(check.cwe.to_string());
									finding.remediation = check.remediation.to_string();
									finding.references = vec![check.reference.to_string()];
									findings.push(finding);
								}
							}
						}
					}
				}
				false => {
					// Header must NOT exist (e.g. X-XSS-Protection)
					if header_value.is_some() {
						let mut finding = Finding::new(
							VulnerabilityType::SecurityHeader,
							check.severity.clone(),
							Confidence::Confirmed,
							format!("Deprecated header present: {}", check.name),
							target.to_string(),
							"headers-scanner".to_string(),
						);
						finding.description = format!(
							"The '{}' header is present but deprecated and can introduce vulnerabilities. {}",
							check.name, check.remediation
						);
						finding.evidence = Evidence {
							request: Some(format!("GET {} HTTP/1.1", target)),
							response: Some(format!(
								"Status: {}, {}={}",
								status,
								check.name,
								header_value.unwrap_or("")
							)),
							payload: None,
							pattern: Some(check.name.to_string()),
							context: None,
						};
						finding.cwe_id = Some(check.cwe.to_string());
						finding.remediation = check.remediation.to_string();
						finding.references = vec![check.reference.to_string()];
						findings.push(finding);
					}
				}
			}
		}

		Ok(findings)
	}
}

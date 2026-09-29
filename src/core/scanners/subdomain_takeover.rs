use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use url::Url;

/// Known services vulnerable to subdomain takeover (service domain, display name)
/// Note: ScannerType::SubdomainTakeover needs to be added to mod.rs
const TAKEOVER_SERVICES: &[(&str, &str)] = &[
	("s3.amazonaws.com", "AWS S3 Bucket"),
	("s3-website", "AWS S3 Website"),
	("cloudfront.net", "AWS CloudFront"),
	("herokuapp.com", "Heroku"),
	("herokussl.com", "Heroku SSL"),
	("ghost.io", "Ghost CMS"),
	("shopify.com", "Shopify"),
	("surge.sh", "Surge.sh"),
	("bitbucket.io", "Bitbucket Pages"),
	("azurewebsites.net", "Azure Web Apps"),
	("cloudapp.azure.com", "Azure Cloud App"),
	("blob.core.windows.net", "Azure Blob Storage"),
	("appspot.com", "Google App Engine"),
	("firebaseapp.com", "Firebase"),
	("github.io", "GitHub Pages"),
	("gitlab.io", "GitLab Pages"),
	("readme.io", "ReadMe"),
	("zendesk.com", "Zendesk"),
	("pantheon.io", "Pantheon"),
	("fastly.net", "Fastly"),
];

/// Response body signatures indicating an unclaimed takeover service
const TAKEOVER_SIGNATURES: &[(&str, &str)] = &[
	("NoSuchBucket", "AWS S3"),
	("No such app", "Heroku"),
	("If this is your website and you've just created it", "GitHub Pages"),
	("Repository not found", "Bitbucket"),
	("The page you are looking for doesn't exist", "Pantheon"),
	("Fastly error: unknown domain", "Fastly"),
	("No Such Account", "Shopify"),
	("helpdesk powered by", "Zendesk"),
	("No site configured for this subdomain", "Firebase"),
	("No such host", "Generic DNS"),
	("NXDOMAIN", "Generic DNS"),
	("404 Not Found", "Generic NotFound"),
];

/// Common subdomain prefixes for brute-force generation
const BRUTE_SUBDOMAINS: &[&str] = &[
	"www", "mail", "api", "dev", "staging", "test", "admin", "portal",
	"vpn", "shop", "store", "app", "cdn", "media", "static", "assets",
	"blog", "webmail", "smtp", "ftp", "git", "gitlab", "jenkins", "ci",
	"monitor", "grafana", "kibana", "docs", "wiki", "help", "support",
	"files", "upload", "download", "video", "m", "mobile", "beta", "demo",
	"sandbox", "old", "new", "v1", "v2", "legacy", "backup", "db",
	"database", "proxy", "internal", "auth", "login", "sso", "gateway",
	"secure", "search", "analytics", "status", "health", "status",
];

/// Subdomain takeover scanner
///
/// Detects subdomains vulnerable to takeover by sending HTTP requests
/// and matching response bodies against known service signatures.
pub struct SubdomainTakeoverScanner {
	client: Client,
}

impl SubdomainTakeoverScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		let client = Client::builder()
			.timeout(Duration::from_secs(10))
			.danger_accept_invalid_certs(true)
			.build()
			.unwrap_or_else(|_| Client::new());
		Self { client }
	}

	/// Extract root domain from a URL or bare domain
	fn extract_root_domain(target: &str) -> Option<String> {
		let host = if target.starts_with("http") {
			let url = Url::parse(target).ok()?;
			url.host_str()?.to_string()
		} else {
			target.split('/').next().unwrap_or(target).to_string()
		};
		let parts: Vec<&str> = host.rsplit('.').collect();
		if parts.len() >= 2 {
			Some(format!("{}.{}", parts[1], parts[0]))
		} else {
			Some(host)
		}
	}

	/// Generate candidate subdomains from root domain
	fn generate_subdomains(domain: &str) -> Vec<String> {
		BRUTE_SUBDOMAINS
			.iter()
			.map(|sub| format!("{}.{}", sub, domain))
			.collect()
	}

	/// Check if a response body contains any known takeover signature.
	/// Returns the service name if matched.
	fn check_response_signatures(body: &str) -> Option<&'static str> {
		for &(signature, service) in TAKEOVER_SIGNATURES {
			if body.contains(signature) {
				return Some(service);
			}
		}
		None
	}

	/// Check if a CNAME or redirect target matches a known takeover service.
	/// Returns the service display name if matched.
	fn check_service_match(target: &str) -> Option<&'static str> {
		let lower = target.to_lowercase();
		for &(service_domain, display_name) in TAKEOVER_SERVICES {
			if lower.contains(service_domain) {
				return Some(display_name);
			}
		}
		None
	}

	/// Probe a single subdomain for takeover indicators
	async fn probe_subdomain(&self, subdomain: &str) -> Option<TakeoverResult> {
		let urls = vec![
			format!("https://{}", subdomain),
			format!("http://{}", subdomain),
		];

		for url in urls {
			if let Ok(resp) = self.client.get(&url).send().await {
				let status = resp.status().as_u16();
				let headers = resp.headers().clone();
				if let Ok(body) = resp.text().await {
					// Check response body for takeover signatures
					if let Some(service) = Self::check_response_signatures(&body) {
						return Some(TakeoverResult {
							subdomain: subdomain.to_string(),
							service: service.to_string(),
							status,
							body_snippet: body.chars().take(500).collect(),
							severity: Severity::Critical,
						});
					}

					// Check redirect headers for known services
					if let Some(location) = headers.get("location") {
						if let Ok(loc) = location.to_str() {
							if let Some(service) = Self::check_service_match(loc) {
								return Some(TakeoverResult {
									subdomain: subdomain.to_string(),
									service: service.to_string(),
									status,
									body_snippet: format!("Redirect -> {}", loc),
									severity: Severity::High,
								});
							}
						}
					}

					// Check Server/Headers for known services on error responses
					if status >= 400 {
						let server = headers
							.get("server")
							.and_then(|v| v.to_str().ok())
							.unwrap_or("");
						let powered = headers
							.get("x-powered-by")
							.and_then(|v| v.to_str().ok())
							.unwrap_or("");
						let combined = format!("{} {}", server, powered);
						if let Some(service) = Self::check_service_match(&combined) {
							return Some(TakeoverResult {
								subdomain: subdomain.to_string(),
								service: service.to_string(),
								status,
								body_snippet: format!("Server: {}, X-Powered-By: {}", server, powered),
								severity: Severity::High,
							});
						}
					}
				}
			}
		}
		None
	}
}

/// Internal result from probing a subdomain
struct TakeoverResult {
	subdomain: String,
	service: String,
	status: u16,
	body_snippet: String,
	severity: Severity,
}

#[async_trait]
impl Scanner for SubdomainTakeoverScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::SubdomainTakeover
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		_context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let domain = Self::extract_root_domain(target).ok_or_else(|| {
			JackSparrowError::InvalidTarget {
				url: target.to_string(),
			}
		})?;

		let subdomains = Self::generate_subdomains(&domain);
		let mut findings = Vec::new();

		for subdomain in &subdomains {
			if let Some(result) = self.probe_subdomain(subdomain).await {
				let mut finding = Finding::new(
					VulnerabilityType::SubdomainFound,
					result.severity,
					Confidence::Likely,
					format!(
						"Subdomain takeover possible via {} on {}",
						result.service, result.subdomain
					),
					format!("https://{}", result.subdomain),
					"subdomain-takeover".to_string(),
				);
				finding.description = format!(
					"The subdomain '{}' resolves and returns content from '{}' \
					 (HTTP {}). This suggests the subdomain points to an unclaimed \
					 or expired service, making it vulnerable to subdomain takeover.",
					result.subdomain, result.service, result.status
				);
				finding.evidence = Evidence {
					request: Some(format!("GET https://{}/ HTTP/1.1", result.subdomain)),
					response: Some(result.body_snippet),
					payload: None,
					pattern: Some(result.service.clone()),
					context: Some(format!("HTTP {}", result.status)),
				};
				finding.remediation = format!(
					"Remove the dangling DNS record for '{}' or reassign it to \
					 a valid resource. If the service is still in use, claim it.",
					result.subdomain
				);
				finding.references = vec![
					"https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Subdomain_Takeover"
						.to_string(),
					"https://owasp.org/www-community/attacks/Subdomain_Takeover".to_string(),
				];
				finding.cvss_score = Some(7.5);
				finding.cwe_id = Some("CWE-829".to_string());
				findings.push(finding);
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
		let scanner = SubdomainTakeoverScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::SubdomainTakeover);
	}

	#[test]
	fn test_takeover_services_list() {
		assert_eq!(TAKEOVER_SERVICES.len(), 20);
		assert!(TAKEOVER_SERVICES.iter().any(|(d, _)| d.contains("s3.amazonaws")));
		assert!(TAKEOVER_SERVICES.iter().any(|(d, _)| d.contains("herokuapp")));
		assert!(TAKEOVER_SERVICES.iter().any(|(d, _)| d.contains("github.io")));
	}

	#[test]
	fn test_takeover_signatures_list() {
		assert!(TAKEOVER_SIGNATURES.len() >= 9);
		assert!(TAKEOVER_SIGNATURES.iter().any(|(s, _)| s.contains("NoSuchBucket")));
		assert!(TAKEOVER_SIGNATURES.iter().any(|(s, _)| s.contains("No such app")));
	}

	#[test]
	fn test_new_scanner() {
		let config = JackSparrowConfig::default();
		let scanner = SubdomainTakeoverScanner::new(&config);
		assert_eq!(scanner.scanner_type(), ScannerType::SubdomainTakeover);
	}

	#[test]
	fn test_build_client() {
		let config = JackSparrowConfig::default();
		let scanner = SubdomainTakeoverScanner::new(&config);
		// Client was built successfully — just verify scanner exists
		assert_eq!(scanner.scanner_type(), ScannerType::SubdomainTakeover);
	}

	#[test]
	fn test_extract_root_domain() {
		assert_eq!(
			SubdomainTakeoverScanner::extract_root_domain("https://app.example.com"),
			Some("example.com".to_string())
		);
		assert_eq!(
			SubdomainTakeoverScanner::extract_root_domain("https://a.b.c.example.com"),
			Some("example.com".to_string())
		);
		assert_eq!(
			SubdomainTakeoverScanner::extract_root_domain("example.com"),
			Some("example.com".to_string())
		);
		assert_eq!(
			SubdomainTakeoverScanner::extract_root_domain("https://example.com:8080"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_generate_subdomains() {
		let subs = SubdomainTakeoverScanner::generate_subdomains("example.com");
		assert!(subs.contains(&"www.example.com".to_string()));
		assert!(subs.contains(&"api.example.com".to_string()));
		assert!(subs.contains(&"staging.example.com".to_string()));
		assert_eq!(subs.len(), BRUTE_SUBDOMAINS.len());
	}

	#[test]
	fn test_default_config() {
		let config = JackSparrowConfig::default();
		let scanner = SubdomainTakeoverScanner::new(&config);
		assert_eq!(scanner.scanner_type(), ScannerType::SubdomainTakeover);
	}
}

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashSet;
use url::Url;

/// Common subdomain prefixes to enumerate
const COMMON_SUBDOMAINS: &[&str] = &[
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "imap", "remote",
	"blog", "webdisk", "cpanel", "whm", "api", "dev", "staging", "test",
	"admin", "portal", "vpn", "shop", "store", "app", "cdn", "media",
	"static", "assets", "img", "images", "img1", "web", "gateway",
	"secure", "auth", "login", "sso", "id", "my", "intranet", "extranet",
	"proxy", "internal", "private", "backup", "db", "database", "sql",
	"git", "gitlab", "jenkins", "ci", "cd", "jira", "confluence",
	"monitor", "grafana", "kibana", "elastic", "search", "analytics",
	"status", "health", "docs", "wiki", "kb", "help", "support",
	"files", "upload", "download", "media", "video", "stream",
	"m", "mobile", "ios", "android", "beta", "alpha", "demo", "sandbox",
	"old", "new", "v1", "v2", "v3", "legacy", "archive",
	"ftp2", "email", "mx3", "relay", "autodiscover", "autoconfig",
];

/// Subdomain enumeration scanner
///
/// Discovers subdomains using:
/// 1. crt.sh Certificate Transparency logs (primary source)
/// 2. Common subdomain brute-force with DNS resolution
pub struct SubdomainEnumScanner;

impl SubdomainEnumScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Extract the root domain from a URL
	fn extract_root_domain(target: &str) -> Option<String> {
		let url = if target.starts_with("http") {
			Url::parse(target).ok()?
		} else {
			Url::parse(&format!("https://{}", target)).ok()?
		};
		let host = url.host_str()?;
		// Extract root domain (e.g., "example.com" from "sub.example.com")
		let parts: Vec<&str> = host.rsplit('.').collect();
		if parts.len() >= 2 {
			Some(format!("{}.{}", parts[1], parts[0]))
		} else {
			Some(host.to_string())
		}
	}

	/// Query crt.sh for certificate transparency logs
	async fn query_crtsh(
		client: &Client,
		domain: &str,
	) -> Result<Vec<String>, JackSparrowError> {
		let url = format!(
			"https://crt.sh/?q=%.{}&output=json",
			domain
		);

		let response = client.get(&url).send().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "subdomain-enum".to_string(),
				message: format!("crt.sh request failed: {}", e),
			}
		})?;

		if !response.status().is_success() {
			return Ok(Vec::new());
		}

		let text = response.text().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "subdomain-enum".to_string(),
				message: format!("crt.sh response read failed: {}", e),
			}
		})?;

		// Parse JSON array of objects with "name_value" field
		let entries: Vec<serde_json::Value> = serde_json::from_str(&text).map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "subdomain-enum".to_string(),
				message: format!("crt.sh JSON parse failed: {}", e),
			}
		})?;

		let mut subdomains = HashSet::new();
		for entry in &entries {
			if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
				// name_value can contain multiple domains separated by \n
				for line in name_value.split('\n') {
					let sub = line.trim().to_lowercase();
					// Only include subdomains of our target domain
					if sub.ends_with(&format!(".{}", domain)) && sub != domain {
						// Remove wildcard prefix
						let sub = sub.strip_prefix("*.").unwrap_or(&sub);
						subdomains.insert(sub.to_string());
					}
				}
			}
		}

		Ok(subdomains.into_iter().collect())
	}

	/// Brute-force common subdomain names via DNS resolution
	async fn bruteforce_subdomains(
		client: &Client,
		domain: &str,
	) -> Vec<String> {
		let mut found = Vec::new();

		// Use HTTP HEAD requests to check if subdomains exist
		// This is simpler than DNS resolution and works in any environment
		for sub in COMMON_SUBDOMAINS {
			let fqdn = format!("{}.{}", sub, domain);
			let url = format!("https://{}", fqdn);

			match client.head(&url).timeout(std::time::Duration::from_secs(3)).send().await {
				Ok(resp) if resp.status() != 404 => {
					let status = resp.status().as_u16();
					if status < 500 {
						found.push(fqdn);
					}
				}
				_ => {
					// Also try HTTP
					let url_http = format!("http://{}", fqdn);
					if let Ok(resp) = client.head(&url_http).timeout(std::time::Duration::from_secs(3)).send().await {
						if resp.status().as_u16() < 500 {
							found.push(fqdn);
						}
					}
				}
			}
		}

		found
	}
}

#[async_trait]
impl Scanner for SubdomainEnumScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::SubdomainEnum
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

		let client = Client::builder()
			.timeout(std::time::Duration::from_secs(30))
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "subdomain-enum".to_string(),
				message: e.to_string(),
			})?;

		// Phase 1: Query crt.sh for certificate transparency logs
		let crtsh_subdomains = Self::query_crtsh(&client, &domain).await.unwrap_or_default();

		// Phase 2: Brute-force common subdomains
		let bruteforce_subdomains = Self::bruteforce_subdomains(&client, &domain).await;

		// Merge and deduplicate
		let mut all_subdomains: HashSet<String> = HashSet::new();
		all_subdomains.extend(crtsh_subdomains);
		all_subdomains.extend(bruteforce_subdomains);

		let mut findings = Vec::new();

		for subdomain in &all_subdomains {
			let mut finding = Finding::new(
				VulnerabilityType::SubdomainFound,
				Severity::Info,
				Confidence::Confirmed,
				format!("Subdomain discovered: {}", subdomain),
				target.to_string(),
				"subdomain-enum".to_string(),
			);
			finding.description = format!(
				"Found subdomain '{}' for domain '{}'. \
				 Subdomains can expose additional attack surface, internal applications, \
				 or development environments.",
				subdomain, domain
			);
			finding.evidence = Evidence {
				request: Some(format!("crt.sh query + brute-force for *.{}", domain)),
				response: Some(format!("Discovered: {}", subdomain)),
				payload: None,
				pattern: Some(subdomain.clone()),
				context: None,
			};
			finding.remediation = "Review discovered subdomains for exposed services, \
				development environments, or misconfigured access controls. \
				Ensure all subdomains are behind appropriate authentication."
				.to_string();
			finding.references = vec![
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
					.to_string(),
			];
			finding.cvss_score = Some(0.0);
			finding.cwe_id = Some("CWE-200".to_string());
			findings.push(finding);
		}

		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_extract_root_domain_simple() {
		assert_eq!(
			SubdomainEnumScanner::extract_root_domain("https://www.example.com"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_extract_root_domain_deep_subdomain() {
		assert_eq!(
			SubdomainEnumScanner::extract_root_domain("https://a.b.c.example.com"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_extract_root_domain_no_subdomain() {
		assert_eq!(
			SubdomainEnumScanner::extract_root_domain("https://example.com"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_extract_root_domain_with_port() {
		assert_eq!(
			SubdomainEnumScanner::extract_root_domain("https://example.com:8080"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_extract_root_domain_no_protocol() {
		assert_eq!(
			SubdomainEnumScanner::extract_root_domain("www.example.com"),
			Some("example.com".to_string())
		);
	}

	#[test]
	fn test_common_subdomains_count() {
		assert!(COMMON_SUBDOMAINS.len() > 80);
	}
}

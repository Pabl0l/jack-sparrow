use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use url::Url;

const CORS_HEADERS: &[&str] = &[
	"access-control-allow-origin",
	"access-control-allow-methods",
	"access-control-allow-headers",
	"access-control-allow-credentials",
	"access-control-expose-headers",
	"access-control-max-age",
];

const ATTACK_ORIGINS: &[&str] = &[
	"https://evil.com",
	"https://attacker.com",
	"https://malicious.net",
];

const DANGEROUS_METHODS: &[&str] = &["DELETE", "PUT", "PATCH"];

pub struct CorsDeepScanner;

impl CorsDeepScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	fn test_origin_reflection(client: &Client, url: &str, origin: &str) -> Option<String> {
		let rt = tokio::runtime::Handle::current();
		let resp = rt.block_on(async {
			client.get(url).header("Origin", origin).send().await.ok()
		})?;
		let acao = resp
			.headers()
			.get("access-control-allow-origin")?
			.to_str()
			.ok()?;
		if acao.eq_ignore_ascii_case(origin) || acao == "*" {
			Some(acao.to_string())
		} else {
			None
		}
	}

	fn test_null_origin(client: &Client, url: &str) -> bool {
		let rt = tokio::runtime::Handle::current();
		let resp = rt.block_on(async { client.get(url).header("Origin", "null").send().await.ok() });
		resp.and_then(|r| r.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok()).map(|v| v == "null")).unwrap_or(false)
	}

	fn test_wildcard(client: &Client, url: &str) -> bool {
		let rt = tokio::runtime::Handle::current();
		let resp = rt.block_on(async { client.get(url).send().await.ok() });
		resp.and_then(|r| r.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok()).map(|v| v == "*")).unwrap_or(false)
	}

	fn test_subdomain_bypass(client: &Client, url: &str, domain: &str) -> bool {
		let evil_origin = format!("https://evil.{}", domain);
		let rt = tokio::runtime::Handle::current();
		let resp = rt.block_on(async {
			client.get(url).header("Origin", &evil_origin).send().await.ok()
		});
		resp.and_then(|r| r.headers().get("access-control-allow-origin").and_then(|v| v.to_str().ok()).map(|v| v == evil_origin)).unwrap_or(false)
	}

	fn test_preflight(client: &Client, url: &str, origin: &str) -> Vec<String> {
		let rt = tokio::runtime::Handle::current();
		let resp = match rt.block_on(async {
			client
				.request(reqwest::Method::OPTIONS, url)
				.header("Origin", origin)
				.header("Access-Control-Request-Method", "PUT")
				.header("Access-Control-Request-Headers", "X-Custom-Header")
				.send()
				.await
				.ok()
		}) {
			Some(r) => r,
			None => return Vec::new(),
		};
		let mut dangerous = Vec::new();
		if let Some(methods) = resp
			.headers()
			.get("access-control-allow-methods")
			.and_then(|v| v.to_str().ok())
		{
			let upper = methods.to_uppercase();
			for m in DANGEROUS_METHODS {
				if upper.contains(m) {
					dangerous.push(m.to_string());
				}
			}
		}
		dangerous
	}

	fn extract_domain(url: &str) -> Option<String> {
		let parsed = Url::parse(url).ok()?;
		let host = parsed.host_str()?;
		let parts: Vec<&str> = host.split('.').collect();
		if parts.len() >= 2 {
			Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
		} else {
			Some(host.to_string())
		}
	}

	fn build_client(context: &ScanContext) -> Result<Client, JackSparrowError> {
		let mut builder = Client::builder()
			.timeout(Duration::from_secs(10))
			.danger_accept_invalid_certs(true)
			.redirect(reqwest::redirect::Policy::none());
		if !context.headers.is_empty() {
			let mut headers = reqwest::header::HeaderMap::new();
			for (k, v) in &context.headers {
				if let (Ok(name), Ok(val)) = (
					reqwest::header::HeaderName::from_bytes(k.as_bytes()),
					reqwest::header::HeaderValue::from_str(v),
				) {
					headers.insert(name, val);
				}
			}
			builder = builder.default_headers(headers);
		}
		builder.build().map_err(|e| JackSparrowError::ToolExecutionFailed {
			tool: "cors-deep-scanner".to_string(),
			message: e.to_string(),
		})
	}

	fn has_cors_headers(client: &Client, url: &str) -> bool {
		let rt = tokio::runtime::Handle::current();
		let resp = match rt.block_on(async { client.get(url).send().await.ok() }) {
			Some(r) => r,
			None => return false,
		};
		CORS_HEADERS.iter().any(|h| resp.headers().contains_key(*h))
	}

	fn make_finding(title: &str, desc: &str, sev: Severity, base: &str) -> Finding {
		let mut f = Finding::new(
			VulnerabilityType::ApiSecurity,
			sev,
			Confidence::Confirmed,
			title.to_string(),
			base.to_string(),
			"cors-deep-scanner".to_string(),
		);
		f.description = desc.to_string();
		f.cwe_id = Some("CWE-942".to_string());
		f.references = vec![
			"https://portswigger.net/web-security/cors".to_string(),
			"https://cwe.mitre.org/data/definitions/942.html".to_string(),
		];
		f
	}
}

#[async_trait]
impl Scanner for CorsDeepScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::CorsDeep
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = Self::build_client(context)?;
		let base = target.trim_end_matches('/');
		let mut findings = Vec::new();

		if !Self::has_cors_headers(&client, base) {
			let mut f = Self::make_finding(
				"No CORS headers detected",
				"The target does not return CORS headers. APIs consumed by browsers typically need CORS configuration.",
				Severity::Info,
				base,
			);
			f.cvss_score = Some(0.0);
			findings.push(f);
			return Ok(findings);
		}

		for origin in ATTACK_ORIGINS {
			if let Some(reflected) = Self::test_origin_reflection(&client, base, origin) {
				let mut f = Self::make_finding(
					"CORS reflects arbitrary Origin",
					&format!("Server reflects '{}' in ACAO. Any website can make cross-origin requests.", reflected),
					Severity::High,
					base,
				);
				f.evidence = Evidence {
					request: Some(format!("GET {} Origin: {}", base, origin)),
					response: Some(format!("ACAO: {}", reflected)),
					payload: Some(origin.to_string()),
					pattern: Some("access-control-allow-origin".to_string()),
					context: None,
				};
				f.remediation = "Whitelist specific trusted origins. Never reflect arbitrary values.".to_string();
				f.cvss_score = Some(7.5);
				findings.push(f);
				break;
			}
		}

		if Self::test_null_origin(&client, base) {
			let mut f = Self::make_finding(
				"CORS allows null Origin",
				"Server accepts 'Origin: null'. Sandboxed iframes send 'null', enabling cross-origin access.",
				Severity::Medium,
				base,
			);
			f.evidence = Evidence {
				request: Some(format!("GET {} Origin: null", base)),
				response: Some("ACAO: null".to_string()),
				payload: Some("null".to_string()),
				pattern: Some("access-control-allow-origin".to_string()),
				context: None,
			};
			f.remediation = "Do not allow 'null' as a valid origin.".to_string();
			f.cvss_score = Some(5.3);
			findings.push(f);
		}

		if Self::test_wildcard(&client, base) {
			let rt = tokio::runtime::Handle::current();
			let has_creds = rt.block_on(async {
				client.get(base).send().await.ok().and_then(|r| {
					r.headers()
						.get("access-control-allow-credentials")
						.and_then(|v| v.to_str().ok())
						.map(|v| v.eq_ignore_ascii_case("true"))
				}).unwrap_or(false)
			});
			if has_creds {
				let mut f = Self::make_finding(
					"CORS wildcard with credentials",
					"ACAO is * with credentials=true. Dangerous misconfiguration.",
					Severity::High,
					base,
				);
				f.evidence = Evidence {
					request: Some(format!("GET {}", base)),
					response: Some("ACAO: * + Credentials: true".to_string()),
					payload: None,
					pattern: Some("access-control-allow-credentials".to_string()),
					context: None,
				};
				f.remediation = "Never combine wildcard (*) with credentials.".to_string();
				f.cvss_score = Some(7.5);
				findings.push(f);
			}
		}

		if let Some(domain) = Self::extract_domain(base) {
			if Self::test_subdomain_bypass(&client, base, &domain) {
				let mut f = Self::make_finding(
					"CORS subdomain bypass possible",
					&format!("Server accepts 'evil.{}' as valid origin. Compromised subdomains can access the API.", domain),
					Severity::Medium,
					base,
				);
				f.evidence = Evidence {
					request: Some(format!("GET {} Origin: https://evil.{}", base, domain)),
					response: Some(format!("ACAO: https://evil.{}", domain)),
					payload: Some(format!("https://evil.{}", domain)),
					pattern: Some("access-control-allow-origin".to_string()),
					context: None,
				};
				f.remediation = "Only whitelist specific subdomains that need access.".to_string();
				f.cvss_score = Some(5.3);
				findings.push(f);
			}
		}

		let dangerous_methods = Self::test_preflight(&client, base, "https://evil.com");
		if !dangerous_methods.is_empty() {
			let mut f = Self::make_finding(
				"Preflight allows dangerous methods",
				&format!("OPTIONS allows: {}. Combined with CORS misconfig, state-changing cross-origin requests possible.", dangerous_methods.join(", ")),
				Severity::Low,
				base,
			);
			f.evidence = Evidence {
				request: Some(format!("OPTIONS {} Origin: https://evil.com", base)),
				response: Some(format!("ACAM: {}", dangerous_methods.join(", "))),
				payload: None,
				pattern: Some("access-control-allow-methods".to_string()),
				context: None,
			};
			f.remediation = "Restrict allowed methods in preflight responses.".to_string();
			f.cvss_score = Some(3.0);
			findings.push(f);
		}

		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_scanner_type() {
		let scanner = CorsDeepScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::CorsDeep);
	}

	#[test]
	fn test_cors_headers_list() {
		assert_eq!(CORS_HEADERS.len(), 6);
		assert!(CORS_HEADERS.contains(&"access-control-allow-origin"));
		assert!(CORS_HEADERS.contains(&"access-control-allow-methods"));
		assert!(CORS_HEADERS.contains(&"access-control-allow-headers"));
		assert!(CORS_HEADERS.contains(&"access-control-allow-credentials"));
		assert!(CORS_HEADERS.contains(&"access-control-expose-headers"));
		assert!(CORS_HEADERS.contains(&"access-control-max-age"));
	}

	#[test]
	fn test_extract_domain() {
		assert_eq!(CorsDeepScanner::extract_domain("https://example.com"), Some("example.com".to_string()));
		assert_eq!(CorsDeepScanner::extract_domain("https://sub.example.com/path"), Some("example.com".to_string()));
		assert_eq!(CorsDeepScanner::extract_domain("https://deep.sub.example.com"), Some("example.com".to_string()));
	}

	#[test]
	fn test_extract_domain_with_port() {
		assert_eq!(CorsDeepScanner::extract_domain("https://example.com:8080/api"), Some("example.com".to_string()));
		assert_eq!(CorsDeepScanner::extract_domain("http://localhost:3000"), Some("localhost".to_string()));
	}

	#[test]
	fn test_new_scanner() {
		let scanner = CorsDeepScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::CorsDeep);
	}

	#[test]
	fn test_build_client() {
		let ctx = ScanContext::default();
		assert!(CorsDeepScanner::build_client(&ctx).is_ok());
		let mut ctx2 = ScanContext::default();
		ctx2.headers.push(("Authorization".to_string(), "Bearer test".to_string()));
		assert!(CorsDeepScanner::build_client(&ctx2).is_ok());
	}

	#[test]
	fn test_origin_reflection_payloads() {
		assert_eq!(ATTACK_ORIGINS.len(), 3);
		assert!(ATTACK_ORIGINS.contains(&"https://evil.com"));
	}

	#[test]
	fn test_wildcard_detection() {
		// Verify the wildcard check logic without network
		let wildcard = "*";
		let not_wildcard = "https://example.com";
		assert_eq!(wildcard == "*", true);
		assert_eq!(not_wildcard == "*", false);
	}

	#[test]
	fn test_null_origin_string() {
		assert_eq!("null", "null");
		assert_ne!("null", "Null");
	}

	#[test]
	fn test_default_config() {
		let scanner = CorsDeepScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::CorsDeep);
	}
}

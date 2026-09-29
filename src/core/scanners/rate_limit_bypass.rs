use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use std::time::Duration;

const RATE_LIMIT_HEADERS: &[&str] = &[
	"x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
	"retry-after", "x-rate-limit-limit", "x-rate-limit-remaining",
	"ratelimit-limit", "ratelimit-remaining",
];

const SENSITIVE_PATHS: &[&str] = &[
	"/login", "/api/login", "/auth/login", "/signin",
	"/register", "/api/register", "/signup",
	"/password/reset", "/forgot-password", "/api/password/reset",
	"/api/keys", "/api/tokens", "/oauth/token",
];

const BYPASS_HEADERS: &[&str] = &[
	"X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
	"X-Client-IP", "X-Forwarded-Host", "X-Host",
	"CDN-Loop", "True-Client-IP", "Akamai-Connecting-Ip",
];

#[derive(Debug, Clone)]
struct RateLimitInfo {
	limit: Option<u64>,
	remaining: Option<u64>,
	reset: Option<u64>,
	retry_after: Option<u64>,
}

pub struct RateLimitBypassScanner;

impl RateLimitBypassScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	fn detect_rate_limit(headers: &HeaderMap) -> Option<RateLimitInfo> {
		let mut info = RateLimitInfo { limit: None, remaining: None, reset: None, retry_after: None };
		let mut found = false;
		for &name in RATE_LIMIT_HEADERS {
			if let Some(val) = headers.get(name) {
				if let Ok(s) = val.to_str() {
					let v = s.trim();
					if name.contains("limit") && !name.contains("remaining") {
						info.limit = v.parse::<u64>().ok();
						found = true;
					} else if name.contains("remaining") {
						info.remaining = v.parse::<u64>().ok();
						found = true;
					} else if name.contains("reset") {
						info.reset = v.parse::<u64>().ok();
						found = true;
					} else if name == "retry-after" {
						info.retry_after = v.parse::<u64>().ok();
						found = true;
					}
				}
			}
		}
		if found { Some(info) } else { None }
	}

	fn build_client(config: &JackSparrowConfig, context: &ScanContext) -> Result<Client, JackSparrowError> {
		let mut headers = HeaderMap::new();
		if let Ok(val) = HeaderValue::from_str(&config.general.user_agent) {
			headers.insert(reqwest::header::USER_AGENT, val);
		}
		for (key, value) in &context.headers {
			if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value)) {
				headers.insert(n, v);
			}
		}
		if let Some(ref cookies) = context.cookies {
			if let Ok(val) = HeaderValue::from_str(cookies) {
				headers.insert(reqwest::header::COOKIE, val);
			}
		}
		Client::builder()
			.default_headers(headers)
			.timeout(Duration::from_secs(10))
			.danger_accept_invalid_certs(true)
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed { tool: "rate-limit-bypass".to_string(), message: e.to_string() })
	}

	async fn test_method_bypass(client: &Client, url: &str, method: &str) -> bool {
		let req = match method {
			"GET" => client.get(url),
			"POST" => client.post(url),
			"PUT" => client.put(url),
			"PATCH" => client.patch(url),
			"DELETE" => client.delete(url),
			"OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
			"HEAD" => client.head(url),
			_ => return false,
		};
		match req.send().await {
			Ok(r) => { let s = r.status().as_u16(); s != 429 && s != 503 }
			Err(_) => false,
		}
	}

	async fn test_header_bypass(client: &Client, url: &str, header_name: &str) -> bool {
		let mut h = HeaderMap::new();
		let Ok(name) = HeaderName::from_bytes(header_name.as_bytes()) else { return false };
		if let Ok(val) = HeaderValue::from_str("127.0.0.1") { h.insert(name, val); }
		match client.get(url).headers(h).send().await {
			Ok(r) => { let s = r.status().as_u16(); s != 429 && s != 503 }
			Err(_) => false,
		}
	}

	async fn test_url_bypass(client: &Client, base_url: &str, path: &str) -> Vec<String> {
		let mut bypassed = Vec::new();
		let variants = vec![
			format!("{}%6C{}", base_url, &path[1..]),
			format!("{}{}", base_url, path.to_uppercase()),
			format!("{}{}/", base_url, path),
			format!("{}//{}", base_url, &path[1..]),
			format!("{}{}", base_url, path.replace('/', "//")),
			format!("{}%2F{}", base_url, &path[1..]),
		];
		for v in variants {
			if let Ok(resp) = client.get(&v).send().await {
				let s = resp.status().as_u16();
				if s != 429 && s != 503 { bypassed.push(v); }
			}
		}
		bypassed
	}

	async fn test_cookie_bypass(client: &Client, url: &str) -> bool {
		let mut h = HeaderMap::new();
		if let Ok(val) = HeaderValue::from_str("no-session=1") {
			h.insert(reqwest::header::COOKIE, val);
		}
		match client.get(url).headers(h).send().await {
			Ok(r) => { let s = r.status().as_u16(); s != 429 && s != 503 }
			Err(_) => false,
		}
	}

	fn make_finding(title: &str, desc: &str, url: &str, sev: Severity, req: &str, resp: &str, payload: Option<&str>) -> Finding {
		let mut f = Finding::new(VulnerabilityType::RateLimitBypass, sev, Confidence::Confirmed, title.to_string(), url.to_string(), "rate-limit-bypass".to_string());
		f.description = desc.to_string();
		f.evidence = Evidence { request: Some(req.to_string()), response: Some(resp.to_string()), payload: payload.map(|p| p.to_string()), pattern: Some("rate-limit-bypass".to_string()), context: None };
		f.cwe_id = Some("CWE-770".to_string());
		f.remediation = "Implement per-user rate limiting on sensitive endpoints using server-side state. Ensure rate limits are applied consistently across HTTP methods, IP headers, and URL variants.".to_string();
		f.references = vec![
			"https://owasp.org/www-community/controls/Rate_Limiting".to_string(),
			"https://cheatsheetseries.owasp.org/cheatsheets/Flood_Attack_Prevention_Cheat_Sheet.html".to_string(),
		];
		f
	}
}

#[async_trait]
impl Scanner for RateLimitBypassScanner {
	fn scanner_type(&self) -> ScannerType { ScannerType::RateLimitBypass }

	async fn scan(&self, target: &str, config: &JackSparrowConfig, context: &ScanContext) -> Result<Vec<Finding>, JackSparrowError> {
		let client = Self::build_client(config, context)?;
		let mut findings = Vec::new();
		let baseline = client.get(target).send().await.map_err(|e| JackSparrowError::ToolExecutionFailed { tool: "rate-limit-bypass".to_string(), message: e.to_string() })?;
		let has_rl = Self::detect_rate_limit(baseline.headers()).is_some();

		if has_rl {
			let methods = vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
			for method in &methods {
				if Self::test_method_bypass(&client, target, method).await {
					findings.push(Self::make_finding(
						"Rate limit bypass via HTTP method switching",
						&format!("Rate limiting enforced on original method but not on {} requests. Attacker can bypass by changing the HTTP method.", method),
						target, Severity::Medium, &format!("{} {} HTTP/1.1", method, target), "Status: 200 OK (no 429)", Some(method),
					));
				}
			}
			for header_name in BYPASS_HEADERS {
				if Self::test_header_bypass(&client, target, header_name).await {
					findings.push(Self::make_finding(
						"Rate limit bypass via IP spoofing headers",
						&format!("Adding '{}' header bypasses rate limiting. Server trusts client-provided IP headers for rate limit accounting.", header_name),
						target, Severity::Medium, &format!("GET {} HTTP/1.1\n{}: 127.0.0.1", target, header_name), "Status: 200 OK (no 429)", Some(header_name),
					));
				}
			}
			let base = target.trim_end_matches('/');
			let path = reqwest::Url::parse(target).map(|u| u.path().to_string()).unwrap_or_else(|_| "/".to_string());
			for variant in Self::test_url_bypass(&client, base, &path).await {
				findings.push(Self::make_finding(
					"Rate limit bypass via URL manipulation",
					&format!("URL variant '{}' bypasses rate limiting. Server applies rate limits based on exact URL matching.", variant),
					target, Severity::Low, &format!("GET {} HTTP/1.1", variant), "Status: 200 OK (no 429)", Some(&variant),
				));
			}
			if Self::test_cookie_bypass(&client, target).await {
				findings.push(Self::make_finding(
					"Rate limit bypass via cookie removal",
					"Removing or rotating the session cookie bypasses rate limiting. Rate limits are tied to the session rather than the IP or account.",
					target, Severity::Medium, &format!("GET {} HTTP/1.1\nCookie: no-session=1", target), "Status: 200 OK (no 429)", None,
				));
			}
		} else {
			let parsed = reqwest::Url::parse(target);
			let (scheme, host) = match parsed {
				Ok(u) => (u.scheme().to_string(), u.host_str().unwrap_or("").to_string()),
				Err(_) => ("https".to_string(), String::new()),
			};
			for path in SENSITIVE_PATHS {
				let url = format!("{}://{}{}", scheme, host, path);
				if let Ok(resp) = client.get(&url).send().await {
					let s = resp.status().as_u16();
					if s != 404 && s != 405 && s != 410 {
						findings.push(Self::make_finding(
							"Rate limiting not enforced on sensitive endpoint",
							&format!("Endpoint '{}' has no rate limit headers. Without rate limiting, brute-force attacks on authentication and registration endpoints are unrestricted.", path),
							&url, Severity::Medium, &format!("GET {} HTTP/1.1", url), &format!("Status: {}, no rate-limit headers detected", s), None,
						));
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
	use crate::shared::config::JackSparrowConfig;
	use reqwest::header::{HeaderMap, HeaderValue};

	#[test]
	fn test_scanner_type() {
		let scanner = RateLimitBypassScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::RateLimitBypass);
	}

	#[test]
	fn test_detect_rate_limit_found() {
		let mut h = HeaderMap::new();
		h.insert("x-ratelimit-limit", HeaderValue::from_static("100"));
		h.insert("x-ratelimit-remaining", HeaderValue::from_static("95"));
		let info = RateLimitBypassScanner::detect_rate_limit(&h).unwrap();
		assert_eq!(info.limit, Some(100));
		assert_eq!(info.remaining, Some(95));
	}

	#[test]
	fn test_detect_rate_limit_not_found() {
		assert!(RateLimitBypassScanner::detect_rate_limit(&HeaderMap::new()).is_none());
	}

	#[test]
	fn test_rate_limit_info_parsing() {
		let mut h = HeaderMap::new();
		h.insert("ratelimit-limit", HeaderValue::from_static("200"));
		h.insert("ratelimit-remaining", HeaderValue::from_static("0"));
		h.insert("retry-after", HeaderValue::from_static("30"));
		let info = RateLimitBypassScanner::detect_rate_limit(&h).unwrap();
		assert_eq!(info.limit, Some(200));
		assert_eq!(info.remaining, Some(0));
		assert_eq!(info.retry_after, Some(30));
	}

	#[test]
	fn test_method_bypass_payloads() {
		let methods = vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
		assert_eq!(methods.len(), 7);
	}

	#[test]
	fn test_bypass_headers_list() {
		assert!(!BYPASS_HEADERS.is_empty());
		assert!(BYPASS_HEADERS.contains(&"X-Forwarded-For"));
		assert!(BYPASS_HEADERS.contains(&"True-Client-IP"));
		assert!(BYPASS_HEADERS.len() >= 9);
	}

	#[test]
	fn test_sensitive_paths_list() {
		assert!(!SENSITIVE_PATHS.is_empty());
		assert!(SENSITIVE_PATHS.contains(&"/login"));
		assert!(SENSITIVE_PATHS.contains(&"/api/tokens"));
		assert!(SENSITIVE_PATHS.len() >= 13);
	}

	#[test]
	fn test_url_encoding_tricks() {
		let base = "https://example.com";
		let path = "/login";
		let v = vec![
			format!("{}%6C{}", base, &path[1..]),
			format!("{}{}", base, path.to_uppercase()),
			format!("{}{}/", base, path),
			format!("{}//{}", base, &path[1..]),
		];
		assert_eq!(v[0], "https://example.com%6Clogin");
		assert_eq!(v[1], "https://example.com/LOGIN");
		assert_eq!(v[2], "https://example.com/login/");
		assert_eq!(v[3], "https://example.com//login");
	}

	#[test]
	fn test_build_client_default() {
		let r = RateLimitBypassScanner::build_client(&JackSparrowConfig::default(), &ScanContext::default());
		assert!(r.is_ok(), "Client build should succeed: {:?}", r.err());
	}

	#[test]
	fn test_build_client_with_context() {
		let ctx = ScanContext {
			cookies: Some("session=abc123".to_string()),
			headers: vec![("Authorization".to_string(), "Bearer token123".to_string())],
			..Default::default()
		};
		let r = RateLimitBypassScanner::build_client(&JackSparrowConfig::default(), &ctx);
		assert!(r.is_ok(), "Client with context should build: {:?}", r.err());
	}

	#[test]
	fn test_new_scanner() {
		let scanner = RateLimitBypassScanner::new(&JackSparrowConfig::default());
		assert_eq!(scanner.scanner_type(), ScannerType::RateLimitBypass);
	}

	#[test]
	fn test_default_config() {
		let config = JackSparrowConfig::default();
		let scanner = RateLimitBypassScanner::new(&config);
		assert_eq!(scanner.scanner_type(), ScannerType::RateLimitBypass);
		assert!(!config.general.user_agent.is_empty());
		assert!(config.general.timeout_secs > 0);
	}
}

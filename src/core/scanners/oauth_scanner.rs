use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::redirect;

const OIDC_DISCOVERY_PATHS: &[&str] = &[
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/openid-configuration",
];

const OAUTH_AUTH_ENDPOINTS: &[&str] = &[
	"/authorize",
	"/oauth/authorize",
	"/oauth2/authorize",
	"/auth/realms/master/protocol/openid-connect/auth",
	"/connect/authorize",
	"/adfs/oauth2/authorize",
];

const OAUTH_TOKEN_ENDPOINTS: &[&str] = &[
	"/oauth/token",
	"/oauth2/token",
	"/token",
	"/connect/token",
	"/auth/realms/master/protocol/openid-connect/token",
];

const OAUTH_HTML_INDICATORS: &[&str] = &[
	"oauth", "openid", "authorize", "client_id", "redirect_uri",
	"response_type", "code_challenge", "pkce", "oidc", "authorization_code",
];

pub struct OAuthScanner;

impl OAuthScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self { Self }

	pub fn is_oidc_discovery(body: &str) -> bool {
		let lower = body.to_lowercase();
		lower.contains("issuer") && lower.contains("authorization_endpoint") && lower.contains("token_endpoint")
	}

	pub fn extract_issuer(body: &str) -> Option<String> {
		let v: serde_json::Value = serde_json::from_str(body).ok()?;
		v.get("issuer")?.as_str().map(|s| s.to_string())
	}

	pub fn find_oauth_indicators(body: &str) -> Vec<String> {
		let lower = body.to_lowercase();
		OAUTH_HTML_INDICATORS.iter()
			.filter(|ind| lower.contains(*ind))
			.map(|ind| ind.to_string())
			.collect()
	}

	pub fn has_oauth_params(body: &str) -> bool {
		let lower = body.to_lowercase();
		lower.contains("client_id=") || lower.contains("redirect_uri=")
			|| lower.contains("response_type=") || lower.contains("code_challenge=")
	}

	pub fn check_missing_state(body: &str) -> Vec<String> {
		extract_oauth_links(body).into_iter()
			.filter(|l| l.to_lowercase().contains("/authorize") && !l.to_lowercase().contains("state="))
			.collect()
	}

	pub fn check_implicit_flow(body: &str) -> bool {
		let lower = body.to_lowercase();
		lower.contains("response_type=token") || lower.contains("response_type=id_token")
			|| lower.contains("responsetype=token") || lower.contains("responsetype=id_token")
	}

	pub fn check_weak_pkce(body: &str) -> bool {
		let lower = body.to_lowercase();
		if !lower.contains("code_challenge") { return true; }
		lower.contains("code_challenge_method=plain") || lower.contains("codechallengemethod=plain")
	}

	pub fn test_open_redirect(body: &str) -> Option<String> {
		extract_oauth_links(body).into_iter()
			.find(|l| l.contains("/authorize") && l.contains("redirect_uri="))
	}
}

fn build_client(context: &ScanContext) -> Result<reqwest::Client, JackSparrowError> {
	let mut default_headers = reqwest::header::HeaderMap::new();
	if let Some(ref cookie_str) = context.cookies {
		if let Ok(val) = reqwest::header::HeaderValue::from_str(cookie_str) {
			default_headers.insert(reqwest::header::COOKIE, val);
		}
	}
	for (key, value) in &context.headers {
		if let (Ok(name), Ok(val)) = (
			reqwest::header::HeaderName::from_bytes(key.as_bytes()),
			reqwest::header::HeaderValue::from_str(value),
		) {
			default_headers.insert(name, val);
		}
	}
	reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(10))
		.danger_accept_invalid_certs(true)
		.redirect(redirect::Policy::none())
		.default_headers(default_headers)
		.build()
		.map_err(JackSparrowError::Http)
}

fn extract_oauth_links(body: &str) -> Vec<String> {
	let mut links = Vec::new();
	for tag_match in body.match_indices("<a ") {
		let rest = &body[tag_match.0..];
		let end = rest.find('>').unwrap_or(rest.len());
		let tag = &rest[..end];
		if let Some(href_start) = tag.find("href=\"") {
			let after = &tag[href_start + 6..];
			if let Some(href_end) = after.find('"') {
				let href = &after[..href_end];
				let ll = href.to_lowercase();
				if ll.contains("/authorize") || ll.contains("oauth") {
					links.push(href.to_string());
				}
			}
		}
	}
	links
}

pub fn extract_client_id(url: &str) -> Option<String> {
	let parsed = url::Url::parse(url).ok()?;
	parsed.query_pairs().into_owned()
		.find(|(k, _)| k == "client_id")
		.map(|(_, v)| v)
}

fn make_finding(
	title: &str, url: &str, severity: Severity, confidence: Confidence,
	description: &str, remediation: &str, cvss: f64, cwe: &str,
) -> Finding {
	let mut f = Finding::new(
		VulnerabilityType::OAuthSecurity, severity, confidence,
		title.to_string(), url.to_string(), "oauth-scanner".to_string(),
	);
	f.description = description.to_string();
	f.remediation = remediation.to_string();
	f.cvss_score = Some(cvss);
	f.cwe_id = Some(cwe.to_string());
	f
}

#[async_trait]
impl Scanner for OAuthScanner {
	fn scanner_type(&self) -> ScannerType { ScannerType::OAuthSecurity }

	async fn scan(
		&self, target: &str, _config: &JackSparrowConfig, context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = build_client(context)?;
		let mut findings = Vec::new();
		let base = target.trim_end_matches('/');

		// 1. OIDC discovery
		for path in OIDC_DISCOVERY_PATHS {
			let url = format!("{}{}", base, path);
			let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => continue };
			if resp.status().as_u16() != 200 { continue; }
			if let Ok(body) = resp.text().await {
				if Self::is_oidc_discovery(&body) {
					let mut f = make_finding("OIDC Discovery endpoint exposed", &url,
						Severity::Info, Confidence::Confirmed,
						&format!("OIDC discovery document found at {}.", path),
						"Ensure the OIDC discovery endpoint is intended to be public.", 0.0, "CWE-16");
					f.evidence = Evidence {
						request: Some(format!("GET {} HTTP/1.1", path)),
						response: None, payload: None, pattern: None,
						context: Self::extract_issuer(&body).map(|i| format!("Issuer: {}", i)),
					};
					findings.push(f);
				}
			}
		}

		// 2. Authorization endpoints
		for path in OAUTH_AUTH_ENDPOINTS {
			let url = format!("{}{}", base, path);
			let resp = match client.get(&url).send().await { Ok(r) => r, Err(_) => continue };
			let status = resp.status().as_u16();
			if !(200..400).contains(&status) { continue; }
			if let Ok(body) = resp.text().await {
				let indicators = Self::find_oauth_indicators(&body);
				if indicators.is_empty() { continue; }

				let mut f = make_finding("OAuth authorization endpoint detected", &url,
					Severity::Info, Confidence::Likely,
					&format!("Authorization endpoint at {}. Indicators: {}", path, indicators.join(", ")),
					"Ensure authorization endpoints require proper authentication parameters.", 0.0, "CWE-16");
				f.evidence = Evidence {
					request: Some(format!("GET {} HTTP/1.1", path)),
					response: Some(format!("HTTP/{}", status)),
					payload: None, pattern: None,
					context: Some(body.chars().take(500).collect()),
				};
				findings.push(f);

				for link in Self::check_missing_state(&body) {
					let mut f2 = make_finding("Missing state parameter in OAuth link", &link,
						Severity::High, Confidence::Likely,
						"Authorization link lacks a `state` parameter, making it vulnerable to CSRF.",
						"Include a cryptographically random `state` parameter and validate it on callback.", 7.5, "CWE-352");
					f2.evidence = Evidence { request: None, response: None, payload: None,
						pattern: Some("state= missing".to_string()), context: None };
					findings.push(f2);
				}

				if Self::check_implicit_flow(&body) {
					let f3 = make_finding("Implicit OAuth flow detected", &url,
						Severity::Medium, Confidence::Likely,
						"Page contains response_type=token/id_token — deprecated implicit grant.",
						"Migrate to Authorization Code flow with PKCE (OAuth 2.1 deprecates implicit).", 5.0, "CWE-352");
					findings.push(f3);
				}

				if Self::check_weak_pkce(&body) {
					let f4 = make_finding("Weak or missing PKCE configuration", &url,
						Severity::Medium, Confidence::Likely,
						"No code_challenge or code_challenge_method=plain detected. Use S256.",
						"Use code_challenge_method=S256. Never use plain.", 5.0, "CWE-325");
					findings.push(f4);
				}

				if let Some(redirect_link) = Self::test_open_redirect(&body) {
					let mut f5 = make_finding("OAuth link with redirect_uri found", &redirect_link,
						Severity::Medium, Confidence::Possible,
						"Authorization link contains redirect_uri that may be vulnerable to open redirect.",
						"Validate redirect_uri against a strict allow-list server-side.", 6.1, "CWE-601");
					f5.evidence = Evidence { request: None, response: None,
						payload: Some(redirect_link), pattern: Some("redirect_uri".to_string()), context: None };
					findings.push(f5);
				}
			}
		}

		// 3. Token endpoints
		for path in OAUTH_TOKEN_ENDPOINTS {
			let url = format!("{}{}", base, path);
			let resp = match client.post(&url).send().await { Ok(r) => r, Err(_) => continue };
			let status = resp.status().as_u16();
			if status != 200 && status != 400 { continue; }
			if let Ok(body) = resp.text().await {
				let lower = body.to_lowercase();
				if lower.contains("access_token") || lower.contains("token_type") || lower.contains("error") {
					let mut f = make_finding("OAuth token endpoint detected", &url,
						Severity::Info, Confidence::Confirmed,
						&format!("Token endpoint at {} (HTTP {}).", path, status),
						"Ensure token endpoints enforce client authentication.", 0.0, "CWE-16");
					f.evidence = Evidence {
						request: Some(format!("POST {} HTTP/1.1", path)),
						response: Some(format!("HTTP/{}", status)),
						payload: None, pattern: None,
						context: Some(body.chars().take(500).collect()),
					};
					findings.push(f);
				}
			}
		}

		// 4. Target page OAuth indicators
		if let Ok(resp) = client.get(target).send().await {
			if let Ok(body) = resp.text().await {
				let indicators = Self::find_oauth_indicators(&body);
				if !indicators.is_empty() && !Self::has_oauth_params(&body) {
					let mut f = make_finding("OAuth-related content detected", target,
						Severity::Info, Confidence::Possible,
						&format!("Page contains OAuth/OIDC indicators: {}", indicators.join(", ")),
						"Review exposed OAuth configuration.", 0.0, "CWE-16");
					f.evidence = Evidence {
						request: Some("GET / HTTP/1.1".to_string()),
						response: None, payload: None, pattern: None,
						context: Some(body.chars().take(500).collect()),
					};
					findings.push(f);
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
	fn test_is_oidc_discovery_true() {
		let json = r#"{"issuer":"https://example.com","authorization_endpoint":"https://example.com/auth","token_endpoint":"https://example.com/token"}"#;
		assert!(OAuthScanner::is_oidc_discovery(json));
	}

	#[test]
	fn test_is_oidc_discovery_false() {
		assert!(!OAuthScanner::is_oidc_discovery(r#"{"name":"not oidc"}"#));
	}

	#[test]
	fn test_extract_issuer() {
		let json = r#"{"issuer":"https://id.example.com","authorization_endpoint":"/auth"}"#;
		assert_eq!(OAuthScanner::extract_issuer(json).unwrap(), "https://id.example.com");
	}

	#[test]
	fn test_extract_issuer_missing() {
		assert!(OAuthScanner::extract_issuer(r#"{"authorization_endpoint":"/auth"}"#).is_none());
	}

	#[test]
	fn test_find_oauth_indicators() {
		let html = r#"<html><body><a href="/authorize?client_id=abc">Login</a></body></html>"#;
		let ind = OAuthScanner::find_oauth_indicators(html);
		assert!(ind.contains(&"client_id".to_string()));
		assert!(ind.contains(&"authorize".to_string()));
	}

	#[test]
	fn test_has_oauth_params_true() {
		let html = r#"<a href="https://example.com/authorize?client_id=123&redirect_uri=https://app.com/callback&response_type=code">"#;
		assert!(OAuthScanner::has_oauth_params(html));
	}

	#[test]
	fn test_has_oauth_params_false() {
		assert!(!OAuthScanner::has_oauth_params(r#"<html><body>No oauth here</body></html>"#));
	}

	#[test]
	fn test_check_missing_state() {
		let body = r#"<a href="/authorize?client_id=abc&redirect_uri=https://app.com/cb">"#;
		assert_eq!(OAuthScanner::check_missing_state(body).len(), 1);
	}

	#[test]
	fn test_check_missing_state_with_state() {
		let body = r#"<a href="/authorize?client_id=abc&state=xyz&redirect_uri=https://app.com/cb">"#;
		assert!(OAuthScanner::check_missing_state(body).is_empty());
	}

	#[test]
	fn test_check_implicit_flow() {
		assert!(OAuthScanner::check_implicit_flow("response_type=token"));
		assert!(OAuthScanner::check_implicit_flow("response_type=id_token"));
		assert!(!OAuthScanner::check_implicit_flow("response_type=code"));
	}

	#[test]
	fn test_check_weak_pkce() {
		assert!(OAuthScanner::check_weak_pkce("no pkce here"));
		assert!(OAuthScanner::check_weak_pkce("code_challenge=abc&code_challenge_method=plain"));
		assert!(!OAuthScanner::check_weak_pkce("code_challenge=abc&code_challenge_method=S256"));
	}

	#[test]
	fn test_extract_client_id() {
		let url = "https://example.com/authorize?client_id=myapp&redirect_uri=https://app.com";
		assert_eq!(extract_client_id(url).unwrap(), "myapp");
		assert!(extract_client_id("https://example.com/authorize?redirect_uri=https://app.com").is_none());
	}

	#[test]
	fn test_scanner_type() {
		assert_eq!(OAuthScanner::new(&JackSparrowConfig::default()).scanner_type(), ScannerType::OAuthSecurity);
	}

	#[test]
	fn test_build_client_default() {
		assert!(build_client(&ScanContext::default()).is_ok());
	}

	#[test]
	fn test_build_client_with_context() {
		let ctx = ScanContext {
			cookies: Some("session=abc".to_string()),
			headers: vec![("Authorization".to_string(), "Bearer tok".to_string())],
			session: None,
		};
		assert!(build_client(&ctx).is_ok());
	}
}

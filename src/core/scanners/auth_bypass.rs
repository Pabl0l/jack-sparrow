use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
	("admin", "admin"), ("admin", "password"), ("admin", "123456"),
	("admin", "admin123"), ("root", "root"), ("root", "toor"),
	("root", "password"), ("test", "test"), ("guest", "guest"),
	("user", "user"), ("administrator", "administrator"), ("admin", ""),
];

const AUTH_BYPASS_HEADERS: &[(&str, &str)] = &[
	("X-Forwarded-For", "127.0.0.1"),
	("X-Forwarded-Host", "127.0.0.1"),
	("X-Real-IP", "127.0.0.1"),
	("X-Original-URL", "/admin"),
	("X-Rewrite-URL", "/admin"),
	("X-Custom-IP-Authorization", "127.0.0.1"),
	("X-Forwarded-Server", "127.0.0.1"),
	("X-Host", "127.0.0.1"),
];

const ADMIN_PATHS: &[&str] = &[
	"/admin", "/admin/", "/admin/dashboard", "/admin/login",
	"/administrator", "/admin-panel", "/admin/console",
	"/api/admin", "/api/users", "/api/config",
	"/debug", "/debug/vars", "/debug/pprof",
	"/.env", "/config", "/server-status",
	"/wp-admin", "/phpmyadmin", "/manager/html",
];

const LOGIN_PATHS: &[&str] = &[
	"/login", "/api/login", "/auth/login", "/api/auth/login",
	"/user/login", "/signin", "/api/signin", "/admin/login",
];

const IDOR_PARAMS: &[&str] = &["id", "user_id", "account_id", "uid", "profile_id"];
const IDOR_PATHS: &[&str] = &["/api/users", "/api/profile", "/api/accounts", "/api/orders"];

pub struct AuthBypassScanner {
	config: JackSparrowConfig,
}

impl AuthBypassScanner {
	pub fn new(config: &JackSparrowConfig) -> Self {
		Self { config: config.clone() }
	}

	async fn test_default_creds(client: &Client, url: &str, user: &str, pass: &str) -> bool {
		let body = serde_json::json!({"username": user, "password": pass});
		for path in LOGIN_PATHS {
			let resp = match client.post(format!("{}{}", url, path)).json(&body).send().await {
				Ok(r) => r, Err(_) => continue,
			};
			let status = resp.status().as_u16();
			if status == 200 || status == 302 {
				if let Ok(text) = resp.text().await {
					let lower = text.to_lowercase();
					if lower.contains("dashboard") || lower.contains("welcome")
						|| lower.contains("logout") || lower.contains("token")
						|| lower.contains("session") { return true; }
				}
			}
		}
		false
	}

	async fn test_forced_browsing(client: &Client, url: &str, path: &str) -> bool {
		let resp = match client.get(format!("{}{}", url, path)).send().await {
			Ok(r) => r, Err(_) => return false,
		};
		if resp.status().as_u16() != 200 { return false; }
		let text = resp.text().await.unwrap_or_default();
		let lower = text.to_lowercase();
		lower.contains("admin") || lower.contains("dashboard")
			|| lower.contains("configuration") || lower.contains("manage") || lower.contains("console")
	}

	async fn test_header_bypass(client: &Client, url: &str, header: &str, value: &str) -> bool {
		for path in ADMIN_PATHS {
			let resp = match client.get(format!("{}{}", url, path))
				.header(header, value).send().await {
				Ok(r) => r, Err(_) => continue,
			};
			if resp.status().as_u16() == 200 {
				let text = resp.text().await.unwrap_or_default();
				let lower = text.to_lowercase();
				if lower.contains("admin") || lower.contains("dashboard") || lower.contains("manage") {
					return true;
				}
			}
		}
		false
	}

	fn test_jwt_none_algorithm(token: &str) -> String {
		use base64::{Engine, engine::general_purpose::URL_SAFE};
		let parts: Vec<&str> = token.split('.').collect();
		if parts.len() != 3 { return token.to_string(); }
		let mut hdr: serde_json::Value = serde_json::from_slice(
			&URL_SAFE.decode(parts[0].as_bytes()).unwrap_or_default(),
		).unwrap_or(serde_json::json!({"typ":"JWT"}));
		hdr["alg"] = serde_json::json!("none");
		let h = URL_SAFE.encode(serde_json::to_vec(&hdr).unwrap_or_default());
		format!("{}.{}.{}", h, parts[1], URL_SAFE.encode(b""))
	}

	async fn test_cookie_tampering(client: &Client, url: &str) -> bool {
		let test_url = format!("{}/admin", url);
		for cookie_val in &["", "session=AAAA; token=fake"] {
			if let Ok(resp) = client.get(&test_url).header("Cookie", *cookie_val).send().await {
				if resp.status().as_u16() == 200 {
					let text = resp.text().await.unwrap_or_default();
					let lower = text.to_lowercase();
					if lower.contains("admin") || lower.contains("dashboard") { return true; }
				}
			}
		}
		false
	}

	async fn test_idor_bypass(client: &Client, url: &str, param: &str) -> bool {
		let mut prev_len: Option<usize> = None;
		for id in 1..=3 {
			if let Ok(resp) = client.get(format!("{}?{}={}", url, param, id)).send().await {
				if let Ok(text) = resp.text().await {
					if text.len() > 50 {
						if let Some(prev) = prev_len {
							if prev != text.len() { return true; }
						}
						prev_len = Some(text.len());
					}
				}
			}
		}
		false
	}
}

#[async_trait]
impl Scanner for AuthBypassScanner {
	fn scanner_type(&self) -> ScannerType { ScannerType::AuthBypass }

	async fn scan(
		&self, target: &str, _config: &JackSparrowConfig, context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let mut findings = Vec::new();
		let base = target.trim_end_matches('/');
		let client = build_client(context)?;
		let tool = "auth-bypass-scanner";

		// 1. Forced browsing
		for path in ADMIN_PATHS {
			if Self::test_forced_browsing(&client, base, path).await {
				let mut f = Finding::new(
					VulnerabilityType::ApiSecurity, Severity::Critical, Confidence::Confirmed,
					"Admin panel accessible without authentication".to_string(),
					format!("{}{}", base, path), tool.to_string(),
				);
				f.description = format!("Path {} is accessible without authentication, indicating a missing access control check.", path);
				f.evidence = Evidence {
					request: Some(format!("GET {} HTTP/1.1", path)),
					response: Some("HTTP/200".to_string()), payload: None,
					pattern: Some("admin|dashboard|manage".to_string()),
					context: Some(format!("{} returned 200 OK with admin content", path)),
				};
				f.cwe_id = Some("CWE-287".to_string());
				f.cvss_score = Some(9.8);
				f.remediation = "Enforce authentication on all admin paths. Implement proper access control checks.".to_string();
				f.references = vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Identity_and_Authentication_Testing/01-Testing_for_Broken_Authentication".to_string()];
				findings.push(f);
			}
		}

		// 2. Header injection
		for &(header, value) in AUTH_BYPASS_HEADERS {
			if Self::test_header_bypass(&client, base, header, value).await {
				let mut f = Finding::new(
					VulnerabilityType::ApiSecurity, Severity::Critical, Confidence::Confirmed,
					format!("Auth bypass via header injection [{}]", header),
					base.to_string(), tool.to_string(),
				);
				f.description = format!("The server trusts the '{}' header for access control. An attacker can inject it to bypass auth.", header);
				f.parameter = Some(header.to_string());
				f.evidence = Evidence {
					request: Some(format!("{}: {}", header, value)),
					response: Some("HTTP/200".to_string()),
					payload: Some(format!("{}: {}", header, value)), pattern: None,
					context: Some(format!("Header '{}: {}' bypasses access control", header, value)),
				};
				f.cwe_id = Some("CWE-287".to_string());
				f.cvss_score = Some(9.1);
				f.remediation = format!("Remove or validate the '{}' header server-side. Never trust proxy-injected headers.", header);
				f.references = vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Identity_and_Authentication_Testing/01-Testing_for_Broken_Authentication".to_string()];
				findings.push(f);
			}
		}

		// 3. Default credentials
		for &(user, pass) in DEFAULT_CREDENTIALS {
			if Self::test_default_creds(&client, base, user, pass).await {
				let mut f = Finding::new(
					VulnerabilityType::ApiSecurity, Severity::Critical, Confidence::Confirmed,
					format!("Default credentials accepted: {}:{}", user, pass),
					base.to_string(), tool.to_string(),
				);
				f.description = format!("Application accepts default credentials '{}:{}', allowing unauthorized access.", user, pass);
				f.parameter = Some("credentials".to_string());
				f.evidence = Evidence {
					request: Some(format!("POST /login {{\"username\":\"{}\",\"password\":\"{}\"}}", user, pass)),
					response: Some("HTTP/200 (login success)".to_string()),
					payload: Some(format!("{}:{}", user, pass)), pattern: None,
					context: Some("Response indicates successful authentication".to_string()),
				};
				f.cwe_id = Some("CWE-798".to_string());
				f.cvss_score = Some(9.8);
				f.remediation = "Remove all default credentials. Enforce strong password policies and require changes on first login.".to_string();
				f.references = vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Identity_and_Authentication_Testing/01-Testing_for_Broken_Authentication".to_string()];
				findings.push(f);
			}
		}

		// 4. Cookie tampering
		if Self::test_cookie_tampering(&client, base).await {
			let mut f = Finding::new(
				VulnerabilityType::ApiSecurity, Severity::High, Confidence::Likely,
				"Session cookie tampering possible".to_string(),
				base.to_string(), tool.to_string(),
			);
			f.description = "Application accepts empty or forged session cookies, indicating weak session validation.".to_string();
			f.parameter = Some("Cookie".to_string());
			f.evidence = Evidence {
				request: Some("GET /admin HTTP/1.1\r\nCookie: ".to_string()),
				response: Some("HTTP/200".to_string()),
				payload: Some("Empty/garbage cookie accepted".to_string()), pattern: None,
				context: Some("Server returned admin content with no/invalid cookie".to_string()),
			};
			f.cwe_id = Some("CWE-287".to_string());
			f.cvss_score = Some(7.5);
			f.remediation = "Validate session cookies server-side with signed tokens. Reject empty or malformed cookies.".to_string();
			f.references = vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes".to_string()];
			findings.push(f);
		}

		// 5. IDOR
		for path in IDOR_PATHS {
			for param in IDOR_PARAMS {
				let full_url = format!("{}{}", base, path);
				if Self::test_idor_bypass(&client, &full_url, param).await {
					let mut f = Finding::new(
						VulnerabilityType::ApiSecurity, Severity::High, Confidence::Likely,
						format!("IDOR via ID manipulation on {}", path),
						full_url, tool.to_string(),
					);
					f.description = format!("Sequential ID manipulation on '{}' at {} returns different data, indicating IDOR.", param, path);
					f.parameter = Some(param.to_string());
					f.evidence = Evidence {
						request: Some(format!("GET {}?{}=<id>", path, param)), response: None,
						payload: Some(format!("{}=1, {}=2, {}=3", param, param, param)), pattern: None,
						context: Some("Different response sizes indicate distinct records".to_string()),
					};
					f.cwe_id = Some("CWE-639".to_string());
					f.cvss_score = Some(7.5);
					f.remediation = "Implement proper authorization for every object access. Use indirect references or UUIDs.".to_string();
					f.references = vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References".to_string()];
					findings.push(f);
					break;
				}
			}
		}

		Ok(findings)
	}
}

fn build_client(context: &ScanContext) -> Result<Client, JackSparrowError> {
	let mut headers = reqwest::header::HeaderMap::new();
	if let Some(ref cookie_str) = context.cookies {
		if let Ok(val) = reqwest::header::HeaderValue::from_str(cookie_str) {
			headers.insert(reqwest::header::COOKIE, val);
		}
	}
	for (key, value) in &context.headers {
		if let (Ok(name), Ok(val)) = (
			reqwest::header::HeaderName::from_bytes(key.as_bytes()),
			reqwest::header::HeaderValue::from_str(value),
		) { headers.insert(name, val); }
	}
	Client::builder()
		.timeout(std::time::Duration::from_secs(10))
		.danger_accept_invalid_certs(true)
		.default_headers(headers)
		.build()
		.map_err(JackSparrowError::Http)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_scanner_type() {
		let s = AuthBypassScanner::new(&JackSparrowConfig::default());
		assert_eq!(s.scanner_type(), ScannerType::AuthBypass);
	}

	#[test]
	fn test_default_credentials_list() {
		assert_eq!(DEFAULT_CREDENTIALS.len(), 12);
		assert!(DEFAULT_CREDENTIALS.contains(&("admin", "admin")));
		assert!(DEFAULT_CREDENTIALS.contains(&("root", "toor")));
		assert!(DEFAULT_CREDENTIALS.contains(&("admin", "")));
	}

	#[test]
	fn test_auth_bypass_headers_list() {
		assert_eq!(AUTH_BYPASS_HEADERS.len(), 8);
		assert!(AUTH_BYPASS_HEADERS.iter().any(|(h, _)| *h == "X-Forwarded-For"));
		assert!(AUTH_BYPASS_HEADERS.iter().any(|(h, _)| *h == "X-Original-URL"));
	}

	#[test]
	fn test_admin_paths_list() {
		assert_eq!(ADMIN_PATHS.len(), 19);
		assert!(ADMIN_PATHS.contains(&"/admin"));
		assert!(ADMIN_PATHS.contains(&"/api/admin"));
		assert!(ADMIN_PATHS.contains(&"/.env"));
	}

	#[test]
	fn test_new_scanner() {
		let s = AuthBypassScanner::new(&JackSparrowConfig::default());
		assert_eq!(s.config.general.max_concurrent, 4);
	}

	#[test]
	fn test_build_client() {
		assert!(build_client(&ScanContext::default()).is_ok());
	}

	#[test]
	fn test_forced_browsing_payload() {
		let url = "https://example.com";
		let path = "/admin";
		assert_eq!(format!("{}{}", url, path), "https://example.com/admin");
	}

	#[test]
	fn test_header_bypass_payload() {
		assert_eq!(AUTH_BYPASS_HEADERS[0], ("X-Forwarded-For", "127.0.0.1"));
	}

	#[test]
	fn test_jwt_none_algorithm() {
		use base64::{Engine, engine::general_purpose::URL_SAFE};
		let hdr = URL_SAFE.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
		let pld = URL_SAFE.encode(b"{\"sub\":\"123\"}");
		let sig = URL_SAFE.encode(b"fakesig");
		let token = format!("{}.{}.{}", hdr, pld, sig);

		let forged = AuthBypassScanner::test_jwt_none_algorithm(&token);
		let parts: Vec<&str> = forged.split('.').collect();
		assert_eq!(parts.len(), 3);
		let decoded: serde_json::Value = serde_json::from_slice(
			&URL_SAFE.decode(parts[0].as_bytes()).unwrap(),
		).unwrap();
		assert_eq!(decoded["alg"], "none");
	}

	#[test]
	fn test_default_config() {
		let s = AuthBypassScanner::new(&JackSparrowConfig::default());
		assert_eq!(s.config.general.timeout_secs, 300);
	}
}

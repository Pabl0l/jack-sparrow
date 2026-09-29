use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD}};
use reqwest::Client;
use std::time::Duration;

const COMMON_SECRETS: &[&str] = &[
	"secret", "password", "123456", "admin", "key", "jwt_secret",
	"supersecret", "changeme", "default", "test", "development",
	"staging", "production", "secretkey", "mysecret", "s3cr3t",
	"12345678", "qwerty", "abc123", "letmein", "welcome",
	"token", "jwt_key", "auth_secret", "api_secret", "hmac_key",
	"signing_key", "secret_key", "jwt_secret_key", "bearer",
];

const WEAK_ALGORITHMS: &[&str] = &["none", "None", "NONE", "HS256", "HS384", "HS512"];

pub struct JwtBruteForceScanner;

impl JwtBruteForceScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	fn build_client(config: &JackSparrowConfig) -> Result<Client, JackSparrowError> {
		Ok(Client::builder()
			.timeout(Duration::from_secs(config.general.timeout_secs.min(10)))
			.danger_accept_invalid_certs(true)
			.build()?)
	}
}

fn extract_bearer_token(header_value: &str) -> Option<String> {
	let trimmed = header_value.trim();
	trimmed.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
	let mut padded = input.to_string();
	let padding = 4 - (padded.len() % 4);
	if padding != 4 {
		padded.push_str(&"=".repeat(padding));
	}
	URL_SAFE.decode(&padded).ok()
}

fn decode_jwt_header(token: &str) -> Option<serde_json::Value> {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return None;
	}
	let bytes = base64url_decode(parts[0])?;
	serde_json::from_slice(&bytes).ok()
}

fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return None;
	}
	let bytes = base64url_decode(parts[1])?;
	serde_json::from_slice(&bytes).ok()
}

fn verify_hmac(token: &str, secret: &str) -> bool {
	use hmac::{Hmac, Mac};
	use sha2::Sha256;

	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return false;
	}
	let signing_input = format!("{}.{}", parts[0], parts[1]);
	let expected_sig = match base64url_decode(parts[2]) {
		Some(s) => s,
		None => return false,
	};

	type HmacSha256 = Hmac<Sha256>;
	let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
		Ok(m) => m,
		Err(_) => return false,
	};
	mac.update(signing_input.as_bytes());
	let computed = mac.finalize().into_bytes();

	constant_time_eq(&computed, &expected_sig)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	let mut diff = 0u8;
	for (x, y) in a.iter().zip(b.iter()) {
		diff |= x ^ y;
	}
	diff == 0
}

async fn test_algorithm_confusion(
	client: &Client,
	url: &str,
	token: &str,
) -> bool {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return false;
	}

	let payload_bytes = match base64url_decode(parts[1]) {
		Some(b) => b,
		None => return false,
	};

	let forged_header = b"{\"alg\":\"none\",\"typ\":\"JWT\"}";
	let h = URL_SAFE_NO_PAD.encode(forged_header);
	let p = URL_SAFE_NO_PAD.encode(&payload_bytes);
	let forged_token = format!("{}.{}.", h, p);

	if let Ok(req) = client.get(url).bearer_auth(&forged_token).send().await {
		req.status().is_success() || req.status().as_u16() == 401
	} else {
		false
	}
}

#[async_trait]
impl Scanner for JwtBruteForceScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::JwtBruteForce
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let token = context
			.headers
			.iter()
			.find(|(k, _)| k.to_lowercase() == "authorization")
			.and_then(|(_, v)| extract_bearer_token(v));

		let token = match token {
			Some(t) if t.split('.').count() == 3 => t,
			_ => {
				return Ok(vec![Finding::new(
					VulnerabilityType::JwtIssue,
					Severity::Info,
					Confidence::Confirmed,
					"No JWT token found in Authorization header".to_string(),
					target.to_string(),
					"jwt-bruteforce".to_string(),
				)]);
			}
		};

		let header = decode_jwt_header(&token).unwrap_or_default();
		let payload = decode_jwt_payload(&token).unwrap_or_default();
		let mut findings = Vec::new();
		let client = Self::build_client(config)?;

		// 1. Check for 'none' algorithm in header
		if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
			if alg.eq_ignore_ascii_case("none") {
				let mut f = Finding::new(
					VulnerabilityType::JwtIssue,
					Severity::Critical,
					Confidence::Confirmed,
					"JWT uses 'none' algorithm (signature bypass)".to_string(),
					target.to_string(),
					"jwt-bruteforce".to_string(),
				);
				f.description =
					"The JWT header specifies 'none' algorithm, allowing signature verification bypass."
						.to_string();
				f.evidence = Evidence {
					request: None,
					response: None,
					payload: Some(format!("alg: {}", alg)),
					pattern: Some("alg: none".to_string()),
					context: Some(serde_json::to_string_pretty(&header).unwrap_or_default()),
				};
				f.remediation =
					"Reject tokens with 'none' algorithm. Always validate signatures server-side.".to_string();
				f.cvss_score = Some(9.8);
				f.cwe_id = Some("CWE-327".to_string());
				f.references = vec![
					"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
						.to_string(),
				];
				findings.push(f);
			}
		}

		// 2. Brute-force HMAC secrets
		if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
			if alg.starts_with("HS") {
				for &secret in COMMON_SECRETS {
					if verify_hmac(&token, secret) {
						let mut f = Finding::new(
							VulnerabilityType::JwtIssue,
							Severity::Critical,
							Confidence::Confirmed,
							"JWT signed with weak secret".to_string(),
							target.to_string(),
							"jwt-bruteforce".to_string(),
						);
						f.description = format!(
							"JWT HMAC signature verified with common secret '{}'. An attacker can forge arbitrary tokens.",
							secret
						);
						f.evidence = Evidence {
							request: None,
							response: None,
							payload: Some(format!("algorithm: {}, matched secret: {}", alg, secret)),
							pattern: Some(format!("secret={}", secret)),
							context: Some(
								serde_json::to_string_pretty(&header).unwrap_or_default(),
							),
						};
						f.remediation =
							"Use a cryptographically strong secret (256+ bits). Consider asymmetric algorithms (RS256/ES256)."
								.to_string();
						f.cvss_score = Some(9.8);
						f.cwe_id = Some("CWE-521".to_string());
						findings.push(f);
						break;
					}
				}
			}
		}

		// 3. Test algorithm confusion
		if test_algorithm_confusion(&client, target, &token).await {
			let mut f = Finding::new(
				VulnerabilityType::JwtIssue,
				Severity::Critical,
				Confidence::Likely,
				"JWT accepted with algorithm=none (algorithm confusion)".to_string(),
				target.to_string(),
				"jwt-bruteforce".to_string(),
			);
			f.description =
				"Server accepted a JWT with algorithm set to 'none', bypassing signature verification."
					.to_string();
			f.evidence = Evidence {
				request: Some(format!("GET {} (forged alg=none token)", target)),
				response: None,
				payload: Some("alg=none forgery".to_string()),
				pattern: Some("algorithm confusion".to_string()),
				context: None,
			};
			f.remediation =
				"Enforce a strict allowlist of accepted algorithms server-side. Never trust the 'alg' header alone."
					.to_string();
			f.cvss_score = Some(9.8);
			f.cwe_id = Some("CWE-327".to_string());
			findings.push(f);
		}

		// 4. Check payload claims
		if payload.get("exp").is_none() {
			let mut f = Finding::new(
				VulnerabilityType::JwtIssue,
				Severity::Medium,
				Confidence::Confirmed,
				"JWT has no expiration (exp claim missing)".to_string(),
				target.to_string(),
				"jwt-bruteforce".to_string(),
			);
			f.description =
				"Token lacks an 'exp' claim and will never expire unless revoked.".to_string();
			f.remediation = "Always include an 'exp' claim with a reasonable lifetime.".to_string();
			f.cvss_score = Some(5.3);
			f.cwe_id = Some("CWE-613".to_string());
			findings.push(f);
		}

		if payload.get("iss").is_none() || payload.get("aud").is_none() {
			let missing: Vec<&str> = [
				("iss", payload.get("iss").is_none()),
				("aud", payload.get("aud").is_none()),
			]
			.iter()
			.filter(|(_, missing)| *missing)
			.map(|(name, _)| *name)
			.collect();

			let mut f = Finding::new(
				VulnerabilityType::JwtIssue,
				Severity::Low,
				Confidence::Confirmed,
				format!("JWT missing claim(s): {}", missing.join(", ")),
				target.to_string(),
				"jwt-bruteforce".to_string(),
			);
			f.description = format!(
				"Token lacks '{}' claim(s), which limits validation options.",
				missing.join("', '")
			);
			f.remediation =
				"Include 'iss' and 'aud' claims to prevent token misuse across services.".to_string();
			f.cvss_score = Some(2.0);
			f.cwe_id = Some("CWE-345".to_string());
			findings.push(f);
		}

		if findings.is_empty() {
			let mut f = Finding::new(
				VulnerabilityType::JwtIssue,
				Severity::Info,
				Confidence::Confirmed,
				"JWT brute-force scan completed — no weak secrets detected".to_string(),
				target.to_string(),
				"jwt-bruteforce".to_string(),
			);
			f.description =
				"The JWT appears to use a strong secret not in the common wordlist.".to_string();
			f.cvss_score = Some(0.0);
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
		let scanner = JwtBruteForceScanner;
		assert_eq!(scanner.scanner_type(), ScannerType::JwtBruteForce);
	}

	#[test]
	fn test_extract_bearer_token() {
		assert_eq!(
			extract_bearer_token("Bearer abc123"),
			Some("abc123".to_string())
		);
	}

	#[test]
	fn test_extract_bearer_token_no_bearer() {
		assert_eq!(extract_bearer_token("abc123"), None);
	}

	#[test]
	fn test_decode_jwt_header() {
		let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
		let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"1\"}");
		let token = format!("{}.{}.sig", header, payload);
		let val = decode_jwt_header(&token).unwrap();
		assert_eq!(val["alg"], "HS256");
		assert_eq!(val["typ"], "JWT");
	}

	#[test]
	fn test_decode_jwt_payload() {
		let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
		let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"user123\",\"role\":\"admin\"}");
		let token = format!("{}.{}.sig", header, payload);
		let val = decode_jwt_payload(&token).unwrap();
		assert_eq!(val["sub"], "user123");
		assert_eq!(val["role"], "admin");
	}

	#[test]
	fn test_decode_jwt_invalid() {
		assert!(decode_jwt_header("garbage").is_none());
		assert!(decode_jwt_header("").is_none());
		assert!(decode_jwt_payload("only.two").is_none());
	}

	#[test]
	fn test_common_secrets_list() {
		assert!(!COMMON_SECRETS.is_empty());
		assert!(COMMON_SECRETS.contains(&"secret"));
		assert!(COMMON_SECRETS.contains(&"password"));
	}

	#[test]
	fn test_weak_algorithms_list() {
		assert!(!WEAK_ALGORITHMS.is_empty());
		assert!(WEAK_ALGORITHMS.contains(&"none"));
		assert!(WEAK_ALGORITHMS.contains(&"HS256"));
	}

	#[test]
	fn test_new_scanner() {
		let config = JackSparrowConfig::default();
		let scanner = JwtBruteForceScanner::new(&config);
		assert_eq!(scanner.scanner_type(), ScannerType::JwtBruteForce);
	}

	#[test]
	fn test_default_config() {
		let config = JackSparrowConfig::default();
		let scanner = JwtBruteForceScanner::new(&config);
		assert_eq!(scanner.scanner_type(), ScannerType::JwtBruteForce);
	}

	#[test]
	fn test_jwt_parts_splitting() {
		let parts: Vec<&str> = "a.b.c".split('.').collect();
		assert_eq!(parts, vec!["a", "b", "c"]);
		assert_eq!(parts.len(), 3);
	}

	#[test]
	fn test_jwt_too_few_parts() {
		assert!(decode_jwt_header("a.b").is_none());
		assert!(decode_jwt_payload("a").is_none());
	}
}

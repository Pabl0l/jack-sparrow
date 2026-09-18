use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE};
use serde_json::Value;
use std::collections::HashSet;

/// JWT header algorithm types and their risk levels
fn algorithm_risk(alg: &str) -> (Severity, &'static str, &'static str) {
	match alg {
		"none" => (
			Severity::Critical,
			"JWT uses 'none' algorithm — signature verification can be completely bypassed",
			"Reject tokens with 'none' algorithm. Always validate the signature server-side.",
		),
		"HS256" | "HS384" | "HS512" => (
			Severity::Low,
			"JWT uses HMAC algorithm — ensure the secret is strong and not leaked",
			"Consider using asymmetric algorithms (RS256/ES256) for better secret management.",
		),
		"RS256" | "RS384" | "RS512" => (
			Severity::Info,
			"JWT uses RSA algorithm — appropriate for most use cases",
			"",
		),
		"ES256" | "ES384" | "ES512" => (
			Severity::Info,
			"JWT uses ECDSA algorithm — strong and recommended",
			"",
		),
		"PS256" | "PS384" | "PS512" => (
			Severity::Info,
			"JWT uses RSA-PSS algorithm — strong and recommended",
			"",
		),
		"HS1" | "HS224" => (
			Severity::High,
			"JWT uses weak HMAC variant — vulnerable to brute-force attacks",
			"Upgrade to HS256 or stronger, or switch to asymmetric algorithms.",
		),
		_ => (
			Severity::Medium,
			"JWT uses unrecognized algorithm — may indicate a non-standard or custom implementation",
			"Verify the algorithm is properly supported and secure.",
		),
	}
}

/// Decode a Base64URL segment (with or without padding)
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
	// Add padding if needed
	let mut padded = input.to_string();
	let padding = 4 - (padded.len() % 4);
	if padding != 4 {
		padded.push_str(&"=".repeat(padding));
	}
	URL_SAFE.decode(&padded).ok()
}

/// Parse JWT and extract header/payload claims
fn parse_jwt(token: &str) -> Option<(Value, Value)> {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return None;
	}

	let header_bytes = base64url_decode(parts[0])?;
	let payload_bytes = base64url_decode(parts[1])?;

	let header: Value = serde_json::from_slice(&header_bytes).ok()?;
	let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

	Some((header, payload))
}

/// Calculate Shannon entropy of a byte slice (bits per byte).
/// Higher values indicate more randomness. Typical strong secrets > 4.0.
fn shannon_entropy(data: &[u8]) -> f64 {
	if data.is_empty() {
		return 0.0;
	}
	let mut freq = [0u64; 256];
	for &b in data {
		freq[b as usize] += 1;
	}
	let len = data.len() as f64;
	let mut entropy = 0.0;
	for &f in &freq {
		if f > 0 {
			let p = f as f64 / len;
			entropy -= p * p.log2();
		}
	}
	entropy
}

/// Top common JWT secrets found in the wild (from various breach analyses)
fn common_jwt_secrets() -> HashSet<&'static str> {
	HashSet::from([
		"secret", "password", "123456", "jwt_secret", "key", "changeme",
		"super-secret", "my-secret", "test", "admin", "secret123",
		"shhhhh", "keyboard cat", "abc123", "development", "staging",
		"production", "default", "null", "undefined", "nil",
		"your-256-bit-secret", "your-256bit-secret", "256-bit-secret",
		"symmetric-secret", "HS256-secret", "jwt-secret-key",
		"secret-key", "auth-secret", "token-secret",
	])
}

/// Check if a signature looks like a common weak secret
fn is_common_secret(sig_bytes: &[u8]) -> Option<&'static str> {
	let sig_str = String::from_utf8_lossy(sig_bytes).to_lowercase();
	let sig_trimmed = sig_str.trim();
	let secrets = common_jwt_secrets();
	for &secret in &secrets {
		if sig_trimmed == secret {
			return Some(secret);
		}
	}
	// Also check if it's a very short or purely alphanumeric sig
	if sig_trimmed.len() < 8 && sig_trimmed.chars().all(|c| c.is_alphanumeric()) {
		return Some("(short/weak signature)");
	}
	None
}

/// Check JWT for common security issues
fn analyze_jwt(token: &str) -> Vec<(Severity, String, String, String)> {
	let mut issues = Vec::new();

	let (header, payload) = match parse_jwt(token) {
		Some((h, p)) => (h, p),
		None => {
			issues.push((
				Severity::Medium,
				"Invalid JWT format".to_string(),
				"Token is not a valid JWT (failed to decode header/payload)".to_string(),
				"Ensure the token is a properly formatted JWT with three Base64URL-encoded segments.".to_string(),
			));
			return issues;
		}
	};

	// 1. Check algorithm
	if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
		let (severity, description, remediation) = algorithm_risk(alg);
		if severity != Severity::Info {
			issues.push((severity, format!("Algorithm: {}", alg), description.to_string(), remediation.to_string()));
		}

		// Check for algorithm confusion (alg in header vs expected)
		if let Some(_expected) = header.get("alg") {
			if alg == "none" {
				issues.push((
					Severity::Critical,
					"'none' algorithm accepted".to_string(),
					"The JWT header specifies 'none' algorithm, meaning no signature verification is performed.".to_string(),
					"Reject all tokens with 'none' algorithm. Implement strict algorithm validation on the server.".to_string(),
				));
			}
		}
	} else {
		issues.push((
			Severity::High,
			"Missing 'alg' header".to_string(),
			"The JWT header does not contain an 'alg' field.".to_string(),
			"Ensure all JWTs include a valid algorithm header.".to_string(),
		));
	}

	// 2. Check expiration
	if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		if exp < now {
			issues.push((
				Severity::Info,
				"Token is expired".to_string(),
				format!("Token expired at timestamp {} (current: {})", exp, now),
				"Expired tokens should be rejected by the server.".to_string(),
			));
		} else {
			let ttl = exp - now;
			if ttl > 86400 * 365 {
				issues.push((
					Severity::Medium,
					"Very long token expiration".to_string(),
					format!("Token has a TTL of {} days ({} seconds)", ttl / 86400, ttl),
					"Consider shorter token lifetimes (15-60 minutes) with refresh tokens.".to_string(),
				));
			}
		}
	} else {
		issues.push((
			Severity::Medium,
			"Missing 'exp' claim".to_string(),
			"The JWT does not contain an expiration claim.".to_string(),
			"Always include an 'exp' claim to limit token validity period.".to_string(),
		));
	}

	// 3. Check 'nbf' (not before)
	if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64()) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		if nbf > now + 300 {
			issues.push((
				Severity::Low,
				"Token not yet valid".to_string(),
				format!("Token 'nbf' is {} seconds in the future", nbf - now),
				"Ensure system clocks are synchronized.".to_string(),
			));
		}
	}

	// 4. Check for sensitive data in payload
	let sensitive_claims = ["password", "secret", "token", "api_key", "apikey", "private_key"];
	for claim in &sensitive_claims {
		if payload.get(*claim).is_some() {
			issues.push((
				Severity::High,
				format!("Sensitive data in JWT payload: '{}'", claim),
				"JWT payload contains potentially sensitive information that can be decoded by anyone.".to_string(),
				format!("Remove '{}' from JWT payload. JWTs are not encrypted — only signed.", claim),
			));
		}
	}

	// 5. Check 'iat' (issued at) for reasonable time
	if let Some(iat) = payload.get("iat").and_then(|v| v.as_u64()) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		if iat > now + 300 {
			issues.push((
				Severity::Low,
				"Token issued in the future".to_string(),
				format!("'iat' claim is {} seconds ahead of current time", iat - now),
				"Check for clock skew issues.".to_string(),
			));
		}
	}

	// 6. Check for 'jti' (unique ID) — good practice
	if payload.get("jti").is_none() {
		issues.push((
			Severity::Info,
			"No 'jti' claim".to_string(),
			"Token lacks a unique identifier for replay protection.".to_string(),
			"Consider adding a 'jti' claim for token revocation and replay prevention.".to_string(),
		));
	}

	// 7. Check for 'iss' (issuer) and 'aud' (audience)
	if payload.get("iss").is_none() {
		issues.push((
			Severity::Info,
			"No 'iss' claim".to_string(),
			"Token lacks an issuer claim.".to_string(),
			"Always include 'iss' to validate token origin.".to_string(),
		));
	}

	if payload.get("aud").is_none() {
		issues.push((
			Severity::Info,
			"No 'aud' claim".to_string(),
			"Token lacks an audience claim.".to_string(),
			"Always include 'aud' to prevent token misuse across services.".to_string(),
		));
	}

	// 8. Signature entropy analysis (for HMAC algorithms)
	if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
		if alg.starts_with("HS") && alg != "none" {
			let parts: Vec<&str> = token.split('.').collect();
			if parts.len() == 3 {
				if let Some(sig_bytes) = base64url_decode(parts[2]) {
					let entropy = shannon_entropy(&sig_bytes);

					// Check entropy
					if entropy < 3.0 && !sig_bytes.is_empty() {
						issues.push((
							Severity::High,
							"Low-entropy JWT signature".to_string(),
							format!(
								"Signature entropy: {:.2} bits/byte (threshold: 3.0). Low entropy suggests a weak or guessable secret.",
								entropy
							),
							"Use a cryptographically strong random secret of at least 256 bits (32 bytes). \
								Generate with: openssl rand -base64 32".to_string(),
						));
					} else if entropy < 4.0 && !sig_bytes.is_empty() {
						issues.push((
							Severity::Medium,
							"Moderate-entropy JWT signature".to_string(),
							format!(
								"Signature entropy: {:.2} bits/byte. Consider using a stronger secret.",
								entropy
							),
							"Aim for signature entropy > 4.0 bits/byte.".to_string(),
						));
					}

					// Check for common secrets
					if let Some(matched) = is_common_secret(&sig_bytes) {
						issues.push((
							Severity::Critical,
							format!("JWT signed with common/weak secret: '{}'", matched),
							"The JWT signature matches a commonly used or trivially guessable secret. \
								An attacker could forge tokens using this secret.".to_string(),
							"Immediately rotate the JWT signing secret to a strong, unique value. \
								Revoke all existing tokens signed with the compromised secret.".to_string(),
						));
					}
				}
			}
		}
	}

	issues
}

/// JWT Analysis scanner
///
/// Analyzes JWT tokens found in:
/// 1. Authorization headers (passed via context)
/// 2. Cookies
/// 3. Response bodies (if accessible)
///
/// Checks for:
/// - Algorithm weaknesses (none, weak HMAC)
/// - Expiration issues
/// - Sensitive data exposure
/// - Missing security claims
pub struct JwtAnalysisScanner;

impl JwtAnalysisScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Extract JWT tokens from various sources
	fn extract_tokens(context: &ScanContext) -> Vec<String> {
		let mut tokens = Vec::new();

		// Check headers for Authorization: Bearer <token>
		for (key, value) in &context.headers {
			if key.to_lowercase() == "authorization" {
				if let Some(token) = value.strip_prefix("Bearer ") {
					let token = token.trim().to_string();
					if token.contains('.') && token.split('.').count() == 3 {
						tokens.push(token);
					}
				}
			}
		}

		// Check cookies for JWT-like values
		if let Some(ref cookie_str) = context.cookies {
			for part in cookie_str.split(';') {
				let part = part.trim();
				if let Some((_, value)) = part.split_once('=') {
					let value = value.trim();
					if value.contains('.') && value.split('.').count() == 3 {
						tokens.push(value.to_string());
					}
				}
			}
		}

		tokens
	}
}

#[async_trait]
impl Scanner for JwtAnalysisScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::JwtAnalysis
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let tokens = Self::extract_tokens(context);

		if tokens.is_empty() {
			// No JWT tokens found — informational
			let mut finding = Finding::new(
				VulnerabilityType::JwtIssue,
				Severity::Info,
				Confidence::Confirmed,
				"No JWT tokens found in request".to_string(),
				target.to_string(),
				"jwt-scanner".to_string(),
			);
			finding.description = "No JWT tokens were found in the Authorization header or cookies. \
				To analyze JWT security, provide a token via --header 'Authorization: Bearer <token>' \
				or --cookie 'token=<jwt>'."
				.to_string();
			finding.evidence = Evidence {
				request: Some(format!("GET {} HTTP/1.1", target)),
				response: None,
				payload: None,
				pattern: None,
				context: Some("No JWT tokens detected in context".to_string()),
			};
			finding.remediation = "Provide JWT tokens via headers or cookies for analysis.".to_string();
			finding.cvss_score = Some(0.0);
			return Ok(vec![finding]);
		}

		let mut all_findings = Vec::new();

		for token in &tokens {
			let issues = analyze_jwt(token);

		for (severity, title, description, remediation) in issues {
			let confidence = match &severity {
				Severity::Critical | Severity::High => Confidence::Confirmed,
				Severity::Medium => Confidence::Likely,
				_ => Confidence::Possible,
			};

			let mut finding = Finding::new(
				VulnerabilityType::JwtIssue,
				severity.clone(),
					confidence,
					title,
					target.to_string(),
					"jwt-scanner".to_string(),
				);
				finding.description = description;
				finding.evidence = Evidence {
					request: Some(format!("GET {} HTTP/1.1 (with JWT)", target)),
					response: None,
					payload: Some(format!("JWT: {}...{}", &token[..token.len().min(20)], &token[token.len().saturating_sub(10)..])),
					pattern: None,
					context: Some(format!(
						"Header: {}",
						parse_jwt(token)
							.map(|(h, _)| serde_json::to_string_pretty(&h).unwrap_or_default())
							.unwrap_or_default()
					)),
				};
				finding.remediation = remediation;
				finding.references = vec![
					"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/".to_string(),
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens".to_string(),
				];

				// Set CVSS based on severity
				finding.cvss_score = match severity {
					Severity::Critical => Some(9.0),
					Severity::High => Some(7.5),
					Severity::Medium => Some(5.0),
					Severity::Low => Some(2.5),
					Severity::Info => Some(0.0),
				};
				finding.cwe_id = Some("CWE-327".to_string());

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
	fn test_base64url_decode() {
		// "hello" in base64url
		let result = base64url_decode("aGVsbG8");
		assert!(result.is_some());
		assert_eq!(String::from_utf8(result.unwrap()).unwrap(), "hello");
	}

	#[test]
	fn test_parse_jwt_valid() {
		// Header: {"alg":"HS256","typ":"JWT"}
		// Payload: {"sub":"1234567890","name":"John","exp":9999999999}
		// Using a real JWT structure (dummy signature)
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"sub\":\"1234567890\",\"name\":\"John\",\"exp\":9999999999}");
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"fake-sig");
		let token = format!("{}.{}.{}", header, payload, sig);

		let result = parse_jwt(&token);
		assert!(result.is_some());
		let (h, p) = result.unwrap();
		assert_eq!(h["alg"], "HS256");
		assert_eq!(p["sub"], "1234567890");
	}

	#[test]
	fn test_parse_jwt_invalid() {
		assert!(parse_jwt("not-a-jwt").is_none());
		assert!(parse_jwt("only.two").is_none());
		assert!(parse_jwt("").is_none());
	}

	#[test]
	fn test_algorithm_risk_none() {
		let (sev, desc, _) = algorithm_risk("none");
		assert_eq!(sev, Severity::Critical);
		assert!(desc.contains("bypass"));
	}

	#[test]
	fn test_algorithm_risk_hs256() {
		let (sev, _, _) = algorithm_risk("HS256");
		assert_eq!(sev, Severity::Low);
	}

	#[test]
	fn test_algorithm_risk_rs256() {
		let (sev, _, _) = algorithm_risk("RS256");
		assert_eq!(sev, Severity::Info);
	}

	#[test]
	fn test_analyze_jwt_expired() {
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"HS256\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"exp\":1000000000}");
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"x");
		let token = format!("{}.{}.{}", header, payload, sig);

		let issues = analyze_jwt(&token);
		assert!(issues.iter().any(|(s, t, _, _)| *s == Severity::Info && t.contains("expired")));
	}

	#[test]
	fn test_analyze_jwt_sensitive_data() {
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"HS256\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"password\":\"secret123\",\"exp\":9999999999}");
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"x");
		let token = format!("{}.{}.{}", header, payload, sig);

		let issues = analyze_jwt(&token);
		assert!(issues.iter().any(|(_, t, _, _)| t.contains("password")));
	}

	#[test]
	fn test_analyze_jwt_none_algorithm() {
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"none\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"sub\":\"123\"}");
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"x");
		let token = format!("{}.{}.{}", header, payload, sig);

		let issues = analyze_jwt(&token);
		assert!(issues.iter().any(|(s, _, _, _)| *s == Severity::Critical));
	}

	#[test]
	fn test_extract_tokens_from_bearer() {
		let context = ScanContext {
			cookies: None,
			headers: vec![(
				"Authorization".to_string(),
				"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc".to_string(),
			)]
			.into_iter()
			.collect(),
			session: None,
		};

		let tokens = JwtAnalysisScanner::extract_tokens(&context);
		assert_eq!(tokens.len(), 1);
	}

	#[test]
	fn test_extract_tokens_from_cookies() {
		let context = ScanContext {
			cookies: Some("session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc; other=value".to_string()),
			headers: Vec::new(),
			session: None,
		};

		let tokens = JwtAnalysisScanner::extract_tokens(&context);
		assert_eq!(tokens.len(), 1);
	}

	#[test]
	fn test_extract_tokens_empty() {
		let context = ScanContext {
			cookies: None,
			headers: Vec::new(),
			session: None,
		};

		let tokens = JwtAnalysisScanner::extract_tokens(&context);
		assert!(tokens.is_empty());
	}

	#[test]
	fn test_shannon_entropy_high() {
		// Random-looking bytes should have high entropy
		let data = b"\\x89\\xf0\\x12\\xab\\xcd\\xef\\x34\\x56";
		let entropy = shannon_entropy(data);
		assert!(entropy > 2.5, "Random data should have high entropy, got {}", entropy);
	}

	#[test]
	fn test_shannon_entropy_low() {
		// Repetitive data should have low entropy
		let data = b"aaaaaaaaaaaaaaaaaaaaaaaa";
		let entropy = shannon_entropy(data);
		assert_eq!(entropy, 0.0, "Repetitive data should have zero entropy");
	}

	#[test]
	fn test_shannon_entropy_empty() {
		assert_eq!(shannon_entropy(b""), 0.0);
	}

	#[test]
	fn test_is_common_secret_detected() {
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"secret");
		let decoded = base64url_decode(&sig).unwrap();
		assert!(is_common_secret(&decoded).is_some());
	}

	#[test]
	fn test_is_common_secret_unknown() {
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"xK9!mP2#qR7@vL4$");
		let decoded = base64url_decode(&sig).unwrap();
		assert!(is_common_secret(&decoded).is_none());
	}

	#[test]
	fn test_analyze_jwt_common_secret_warning() {
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"sub\":\"user123\",\"exp\":9999999999}");
		// Sign with "secret" — a common weak secret
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"secret");
		let token = format!("{}.{}.{}", header, payload, sig);

		let issues = analyze_jwt(&token);
		assert!(
			issues.iter().any(|(s, t, _, _)| *s == Severity::Critical && t.contains("common")),
			"Should detect common secret 'secret'"
		);
	}

	#[test]
	fn test_analyze_jwt_weak_signature_low_entropy() {
		let header = base64::engine::general_purpose::URL_SAFE.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
		let payload = base64::engine::general_purpose::URL_SAFE.encode(b"{\"sub\":\"user123\",\"exp\":9999999999}");
		// Sign with "abc" — low entropy, short
		let sig = base64::engine::general_purpose::URL_SAFE.encode(b"abc");
		let token = format!("{}.{}.{}", header, payload, sig);

		let issues = analyze_jwt(&token);
		// Should get either common secret or low entropy warning
		let has_weak = issues.iter().any(|(s, t, _, _)| {
			*s == Severity::High && (t.contains("entropy") || t.contains("common"))
		}) || issues.iter().any(|(s, t, _, _)| {
			*s == Severity::Critical && t.contains("common")
		});
		assert!(has_weak, "Should detect weak signature");
	}
}

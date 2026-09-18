use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;

/// Regex patterns for secret detection
fn secret_patterns() -> Vec<(&'static str, Regex, Severity, &'static str, &'static str)> {
	let mut patterns = Vec::new();

	// AWS Access Key
	if let Ok(re) = Regex::new(r#"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"#) {
		patterns.push(("AWS Access Key", re, Severity::High, "CWE-798", "Remove hardcoded AWS keys and use IAM roles or environment variables"));
	}

	// AWS Secret Key
	if let Ok(re) = Regex::new(r#"(?:aws.?secret.?access.?key|awssecret)["\s:=]+[A-Za-z0-9/+=]{40}"#) {
		patterns.push(("AWS Secret Key", re, Severity::Critical, "CWE-798", "Remove hardcoded AWS secret keys and use IAM roles or environment variables"));
	}

	// Google API Key
	if let Ok(re) = Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#) {
		patterns.push(("Google API Key", re, Severity::High, "CWE-798", "Restrict API key usage and move to server-side environment variables"));
	}

	// Google OAuth Client ID
	if let Ok(re) = Regex::new(r#"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"#) {
		patterns.push(("Google OAuth Client ID", re, Severity::Medium, "CWE-798", "Move OAuth credentials to server-side configuration"));
	}

	// Stripe API Key
	if let Ok(re) = Regex::new(r#"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"#) {
		patterns.push(("Stripe API Key", re, Severity::Critical, "CWE-798", "Remove hardcoded Stripe keys and use environment variables"));
	}

	// Stripe Secret Key
	if let Ok(re) = Regex::new(r#"sk_live_[0-9a-zA-Z]{24,}"#) {
		patterns.push(("Stripe Secret Key", re, Severity::Critical, "CWE-798", "Remove hardcoded Stripe secret key immediately"));
	}

	// GitHub Token
	if let Ok(re) = Regex::new(r#"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"#) {
		patterns.push(("GitHub Token", re, Severity::Critical, "CWE-798", "Revoke exposed GitHub token and use environment variables"));
	}

	// GitHub Fine-grained PAT
	if let Ok(re) = Regex::new(r#"github_pat_[A-Za-z0-9_]{82,}"#) {
		patterns.push(("GitHub PAT", re, Severity::Critical, "CWE-798", "Revoke exposed GitHub PAT immediately"));
	}

	// GitLab Token
	if let Ok(re) = Regex::new(r#"(?:glpat|glptt|gloas)-[A-Za-z0-9\-_]{20,}"#) {
		patterns.push(("GitLab Token", re, Severity::Critical, "CWE-798", "Revoke exposed GitLab token and use CI/CD variables"));
	}

	// Heroku API Key
	if let Ok(re) = Regex::new(r#"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#) {
		// This is a generic UUID pattern - we'll use it as a secondary check
		// Only flag if combined with "heroku" context
		patterns.push(("UUID Pattern (Generic)", re, Severity::Info, "CWE-200", "Review exposed identifiers"));
	}

	// Slack Token
	if let Ok(re) = Regex::new(r#"xox[bporas]-[0-9]{10,}-[a-zA-Z0-9-]+"#) {
		patterns.push(("Slack Token", re, Severity::Critical, "CWE-798", "Revoke exposed Slack token and rotate credentials"));
	}

	// Slack Webhook
	if let Ok(re) = Regex::new(r#"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}"#) {
		patterns.push(("Slack Webhook", re, Severity::High, "CWE-798", "Revoke exposed Slack webhook URL"));
	}

	// Telegram Bot Token
	if let Ok(re) = Regex::new(r#"[0-9]{9,10}:[A-Za-z0-9_\-]{35}"#) {
		patterns.push(("Telegram Bot Token", re, Severity::Critical, "CWE-798", "Revoke exposed Telegram bot token"));
	}

	// Twilio API Key
	if let Ok(re) = Regex::new(r#"SK[0-9a-fA-F]{32}"#) {
		patterns.push(("Twilio API Key", re, Severity::Critical, "CWE-798", "Revoke exposed Twilio API key"));
	}

	// SendGrid API Key
	if let Ok(re) = Regex::new(r#"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"#) {
		patterns.push(("SendGrid API Key", re, Severity::Critical, "CWE-798", "Revoke exposed SendGrid API key"));
	}

	// Mailgun API Key
	if let Ok(re) = Regex::new(r#"key-[0-9a-zA-Z]{32}"#) {
		patterns.push(("Mailgun API Key", re, Severity::High, "CWE-798", "Revoke exposed Mailgun API key"));
	}

	// Generic API Key patterns
	if let Ok(re) = Regex::new(r#"(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["']?[A-Za-z0-9_\-]{20,}["']?"#) {
		patterns.push(("Generic API Key", re, Severity::Medium, "CWE-798", "Review and rotate exposed API credentials"));
	}

	// Generic Secret patterns
	if let Ok(re) = Regex::new(r#"(?:secret|password|passwd|pwd)["\s:=]+["']?[^\s"']{8,}["']?"#) {
		patterns.push(("Generic Secret/Password", re, Severity::High, "CWE-798", "Remove hardcoded credentials and use secure storage"));
	}

	// JWT Token
	if let Ok(re) = Regex::new(r#"eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*"#) {
		patterns.push(("JWT Token", re, Severity::High, "CWE-798", "Do not expose JWT tokens in client-side code"));
	}

	// Private Key headers
	if let Ok(re) = Regex::new(r#"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"#) {
		patterns.push(("Private Key", re, Severity::Critical, "CWE-321", "Remove private keys from source code and use secure key management"));
	}

	// Base64 encoded secrets (long strings)
	if let Ok(re) = Regex::new(r#"[A-Za-z0-9+/]{40,}={0,2}"#) {
		patterns.push(("Long Base64 String", re, Severity::Low, "CWE-200", "Review long base64 strings for embedded secrets"));
	}

	// Connection strings
	if let Ok(re) = Regex::new(r#"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s"']+"#) {
		patterns.push(("Database Connection String", re, Severity::Critical, "CWE-798", "Remove connection strings from source code"));
	}

	// .env file content
	if let Ok(re) = Regex::new(r#"(?:^|\n)(?:APP_|DB_|MAIL_|AWS_|API_)[A-Z_]+=.+"#) {
		patterns.push(("Environment Variable", re, Severity::Medium, "CWE-200", "Do not expose environment variables in responses"));
	}

	// Password in URL
	if let Ok(re) = Regex::new(r#"(?:https?|ftp)://[^:]+:[^@]+@"#) {
		patterns.push(("Credential in URL", re, Severity::Critical, "CWE-798", "Remove credentials from URLs"));
	}

	patterns
}

pub struct SecretsScanner;

impl SecretsScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Scan body content for secrets
	fn scan_content(&self, content: &str, target: &str) -> Vec<Finding> {
		let mut findings = Vec::new();
		let patterns = secret_patterns();

		for (name, re, severity, cwe, remediation) in &patterns {
			for mat in re.find_iter(content) {
				let matched = mat.as_str();
				// Truncate long matches for display
				let display_match = if matched.len() > 80 {
					format!("{}...", &matched[..80])
				} else {
					matched.to_string()
				};

				// Find the line number
				let line_num = content[..mat.start()].matches('\n').count() + 1;

				let mut finding = Finding::new(
					VulnerabilityType::SecretExposed,
					severity.clone(),
					Confidence::Likely,
					format!("{} exposed", name),
					target.to_string(),
					"secrets-scanner".to_string(),
				);
				finding.description = format!(
					"{} detected at line {}. Matched pattern: {}",
					name, line_num, display_match
				);
				finding.evidence = Evidence {
					request: None,
					response: None,
					payload: Some(display_match),
					pattern: Some(name.to_string()),
					context: Some(format!("Line {}", line_num)),
				};
				finding.cwe_id = Some(cwe.to_string());
				finding.remediation = remediation.to_string();

				// Deduplicate by finding the same pattern in the same content
				let is_duplicate = findings.iter().any(|f: &Finding| {
					f.parameter == finding.parameter && f.title == finding.title
				});

				if !is_duplicate {
					findings.push(finding);
				}
			}
		}

		findings
	}

	/// Check for exposed .env files
	async fn check_env_files(
		&self,
		client: &Client,
		target: &str,
	) -> Vec<Finding> {
		let mut findings = Vec::new();
		let env_paths = [
			"/.env",
			"/.env.local",
			"/.env.production",
			"/.env.development",
			"/.env.bak",
			"/env.js",
			"/.config.js",
		];

		for path in &env_paths {
			let url = format!("{}{}", target.trim_end_matches('/'), path);
			if let Ok(response) = client.get(&url).send().await {
				if response.status().is_success() {
					if let Ok(body) = response.text().await {
						if body.contains('=') && (body.contains("API") || body.contains("KEY") || body.contains("SECRET") || body.contains("PASSWORD")) {
							let mut finding = Finding::new(
								VulnerabilityType::SecretExposed,
								Severity::High,
								Confidence::Confirmed,
								format!("Exposed configuration file: {}", path),
								url,
								"secrets-scanner".to_string(),
							);
							finding.description = format!(
								"Configuration file '{}' is publicly accessible and may contain secrets",
								path
							);
							finding.cwe_id = Some("CWE-200".to_string());
							finding.remediation = "Restrict access to configuration files and move secrets to secure storage".to_string();
							findings.push(finding);
						}
					}
				}
			}
		}

		findings
	}
}

#[async_trait]
impl Scanner for SecretsScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::Secrets
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
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
			.user_agent(&config.general.user_agent)
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "secrets-scanner".to_string(),
				message: e.to_string(),
			})?;

		// Fetch main page
		let response = client.get(target).send().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "secrets-scanner".to_string(),
				message: e.to_string(),
			}
		})?;

		let body = response.text().await.unwrap_or_default();

		// Scan main page content
		let mut findings = self.scan_content(&body, target);

		// Check for exposed .env files
		let env_findings = self.check_env_files(&client, target).await;
		findings.extend(env_findings);

		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_aws_key_detection() {
		let content = "AKIAIOSFODNN7EXAMPLE";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("AWS Access Key")));
	}

	#[test]
	fn test_stripe_key_detection() {
		let content = "sk_test_FAKE_4eC39HqLyjWDarjtT1zdp7dc_TEST";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("Stripe Secret Key")));
	}

	#[test]
	fn test_github_token_detection() {
		let content = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("GitHub Token")));
	}

	#[test]
	fn test_jwt_detection() {
		let content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("JWT Token")));
	}

	#[test]
	fn test_private_key_detection() {
		let content = "-----BEGIN RSA PRIVATE KEY-----";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("Private Key")));
	}

	#[test]
	fn test_slack_token_detection() {
		let content = "xoxb-TEST-123456789012-TEST-AbCdEfGhIjKlMnOpQrStUvWx";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("Slack Token")));
	}

	#[test]
	fn test_generic_api_key_detection() {
		let content = "api_key = \"abc123def456ghi789jkl012mno\"";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.iter().any(|f| f.title.contains("API Key")));
	}

	#[test]
	fn test_no_false_positive_on_short_string() {
		let content = "This is a normal sentence with no secrets.";
		let scanner = SecretsScanner;
		let findings = scanner.scan_content(content, "http://test.com");
		assert!(findings.is_empty());
	}
}

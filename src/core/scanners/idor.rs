use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

pub struct IdorScanner {
	config: JackSparrowConfig,
}

impl IdorScanner {
	pub fn new(config: &JackSparrowConfig) -> Self {
		Self {
			config: config.clone(),
		}
	}

	/// Test a parameter for IDOR vulnerability
	async fn test_parameter(
		&self,
		client: &Client,
		base_url: &str,
		param_name: &str,
		id: u64,
	) -> Result<Option<Finding>, JackSparrowError> {
		// Construct test URL with ID
		let test_url = format!("{}/{}?{}={}", base_url, param_name, param_name, id);

		// Send request
		let response = client.get(&test_url).send().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "idor-scanner".to_string(),
				message: e.to_string(),
			}
		})?;

		let status = response.status();
		let body = response.text().await.unwrap_or_default();

		// Check for signs of IDOR
		// Look for different content based on ID
		if status.is_success() && !body.is_empty() {
			// Check if response contains user-specific data
			let indicators = [
				"email",
				"phone",
				"address",
				"ssn",
				"credit_card",
				"password",
			];
			let has_sensitive_data = indicators
				.iter()
				.any(|&indicator| body.to_lowercase().contains(indicator));

			if has_sensitive_data {
				let mut finding = Finding::new(
					VulnerabilityType::Idor,
					Severity::High,
					Confidence::Likely,
					format!("Potential IDOR in parameter: {}", param_name),
					test_url.clone(),
					"idor-scanner".to_string(),
				);
				finding.parameter = Some(param_name.to_string());
				finding.evidence = Evidence {
					request: Some(format!("GET {} HTTP/1.1", test_url)),
					response: Some(format!("Status: {}", status)),
					payload: Some(format!("{}={}", param_name, id)),
					pattern: None,
					context: Some("Response contains sensitive data indicators".to_string()),
				};
				finding.cwe_id = Some("CWE-639".to_string());
				finding.cvss_score = Some(7.5);
				finding.remediation = "Implement proper access control checks".to_string();
				finding.references = vec![
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References".to_string(),
				];

				return Ok(Some(finding));
			}
		}

		Ok(None)
	}

	/// Test common parameter names
	async fn test_common_params(
		&self,
		client: &Client,
		base_url: &str,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let mut findings = Vec::new();
		let idor_config = &self.config.scanners.idor;

		for param_name in &idor_config.param_names {
			// Test a range of IDs
			let (start, end) = idor_config.id_range;
			for id in start..=std::cmp::min(end, start + 10) {
				if let Some(finding) = self
					.test_parameter(client, base_url, param_name, id)
					.await?
				{
					findings.push(finding);
					break; // Found one, move to next parameter
				}
			}
		}

		Ok(findings)
	}

	/// Test common API paths
	async fn test_common_paths(
		&self,
		client: &Client,
		base_url: &str,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let mut findings = Vec::new();
		let idor_config = &self.config.scanners.idor;

		for path in &idor_config.common_paths {
			let test_url = format!("{}{}", base_url, path);

			let response = client.get(&test_url).send().await.map_err(|e| {
				JackSparrowError::ToolExecutionFailed {
					tool: "idor-scanner".to_string(),
					message: e.to_string(),
				}
			})?;

			if response.status().is_success() {
				// Found a valid path, test for IDOR
				for param_name in &idor_config.param_names {
					let (start, end) = idor_config.id_range;
					for id in start..=std::cmp::min(end, start + 5) {
						let test_url = format!("{}?{}={}", test_url, param_name, id);
						let resp = client.get(&test_url).send().await.map_err(|e| {
							JackSparrowError::ToolExecutionFailed {
								tool: "idor-scanner".to_string(),
								message: e.to_string(),
							}
						})?;

						if resp.status().is_success() {
							let body = resp.text().await.unwrap_or_default();
							if !body.is_empty() && body.len() > 100 {
								let finding = Finding::new(
									VulnerabilityType::Idor,
									Severity::Medium,
									Confidence::Possible,
									format!("Potential IDOR in {} path", path),
									test_url,
									"idor-scanner".to_string(),
								);
								findings.push(finding);
								break;
							}
						}
					}
				}
			}
		}

		Ok(findings)
	}
}

#[async_trait]
impl Scanner for IdorScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::Idor
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		// Build reqwest client with auth headers
		let mut headers = reqwest::header::HeaderMap::new();
		for (key, value) in &context.headers {
			if let (Ok(name), Ok(val)) = (
				reqwest::header::HeaderName::from_bytes(key.as_bytes()),
				reqwest::header::HeaderValue::from_str(value),
			) {
				headers.insert(name, val);
			}
		}

		let mut client_builder = Client::builder();

		// Pass cookies via Cookie header
		if let Some(ref cookies) = context.cookies {
			if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
				headers.insert(reqwest::header::COOKIE, val);
			}
		}

		client_builder = client_builder.default_headers(headers);

		let client = client_builder.build().map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "idor-scanner".to_string(),
				message: e.to_string(),
			}
		})?;

		// Test common parameters
		let mut findings = self.test_common_params(&client, target).await?;

		// Test common paths
		let path_findings = self.test_common_paths(&client, target).await?;
		findings.extend(path_findings);

		Ok(findings)
	}
}

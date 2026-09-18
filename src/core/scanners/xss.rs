use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use dalfox_rs::{Dalfox, DalfoxResult};

pub struct XssScanner;

impl XssScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Convert dalfox findings to our Finding type
	fn convert_findings(&self, dalfox_result: DalfoxResult, target: &str) -> Vec<Finding> {
		let mut findings = Vec::new();

		for dalfox_finding in &dalfox_result.findings {
			// Determine XSS type based on available information
			let vuln_type =
				if dalfox_finding.poc.contains("sxss") || dalfox_finding.poc.contains("stored") {
					VulnerabilityType::XssStored
				} else if dalfox_finding.poc.contains("dom") {
					VulnerabilityType::XssDom
				} else {
					VulnerabilityType::XssReflected
				};

			// Map dalfox severity to our severity
			let severity = match dalfox_finding.severity {
				dalfox_rs::Severity::High => Severity::High,
				dalfox_rs::Severity::Medium => Severity::Medium,
				_ => Severity::Low,
			};

			let mut finding = Finding::new(
				vuln_type,
				severity,
				Confidence::Confirmed,
				format!("XSS in parameter: {}", dalfox_finding.param),
				target.to_string(),
				"dalfox".to_string(),
			);

			finding.parameter = Some(dalfox_finding.param.clone());
			finding.evidence = Evidence {
				request: None,
				response: None,
				payload: Some(dalfox_finding.poc.clone()),
				pattern: None,
				context: Some(dalfox_finding.data.clone()),
			};
			finding.cwe_id = Some("CWE-79".to_string());
			finding.cvss_score = Some(6.1);
			finding.remediation = "Encode output and validate input".to_string();
			finding.references = vec!["https://owasp.org/www-community/attacks/xss/".to_string()];

			findings.push(finding);
		}

		findings
	}
}

#[async_trait]
impl Scanner for XssScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::Xss
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let xss_config = &config.scanners.xss;

		// Build dalfox runner with chained builder pattern
		let builder = Dalfox::builder()
			.request_timeout(10)
			.scan_deadline(300)
			.workers(xss_config.workers as u32);

		// Apply configuration
		let builder = if xss_config.waf_evasion {
			builder.waf_evasion(true)
		} else {
			builder
		};

		let builder = if let Some(ref payloads) = xss_config.custom_payloads {
			builder.payload(payloads.to_str().unwrap_or(""))
		} else {
			builder
		};

		let builder = if let Some(ref callback) = xss_config.blind_callback {
			builder.blind_callback(callback.as_str())
		} else {
			builder
		};

		// Pass cookies to dalfox (--cookies flag in CLI, .cookie() in API)
		let builder = if let Some(ref cookies) = context.cookies {
			builder.cookie(cookies)
		} else {
			builder
		};

		// Set binary path if different from default
		let builder = if config.tools.dalfox_path != "dalfox" {
			builder.binary_path(&config.tools.dalfox_path)
		} else {
			builder
		};

		let runner = builder.build();

		// Execute scan
		let result: DalfoxResult =
			runner
				.scan_url(target)
				.await
				.map_err(|e| JackSparrowError::ToolExecutionFailed {
					tool: "dalfox".to_string(),
					message: e.to_string(),
				})?;

		// Convert findings
		let findings = self.convert_findings(result, target);

		Ok(findings)
	}
}

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use tempfile::NamedTempFile;

pub struct SqlInjectionScanner;

impl SqlInjectionScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Parse sqlmap JSON output into findings
	fn parse_sqlmap_output(&self, output: &str, target: &str) -> Vec<Finding> {
		let mut findings = Vec::new();

		// Try to parse as JSON first
		if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
			if let Some(data) = json.get("data") {
				if let Some(sqli) = data.get("sql injection") {
					if let Some(injection) = sqli.as_object() {
						for (param, details) in injection {
							let title = format!("SQL Injection in parameter: {}", param);
							let description = format!(
								"SQL Injection vulnerability detected in parameter '{}' using {} technique",
								param,
								details.get("title").unwrap_or(&serde_json::Value::String("unknown".to_string()))
							);

							let mut finding = Finding::new(
								VulnerabilityType::SqlInjection,
								Severity::High,
								Confidence::Confirmed,
								title,
								target.to_string(),
								"sqlmap".to_string(),
							);
							finding.description = description;
							finding.parameter = Some(param.clone());
							finding.evidence = Evidence {
								request: None,
								response: None,
								payload: details
									.get("payload")
									.and_then(|p| p.as_str())
									.map(|s| s.to_string()),
								pattern: None,
								context: None,
							};
							finding.cwe_id = Some("CWE-89".to_string());
							finding.cvss_score = Some(8.6);
							finding.remediation =
								"Use parameterized queries or prepared statements".to_string();
							finding.references =
								vec!["https://owasp.org/www-community/attacks/SQL_Injection"
									.to_string()];

							findings.push(finding);
						}
					}
				}
			}
		} else {
			// Fallback: parse text output
			let lines: Vec<&str> = output.lines().collect();
			for line in lines {
				if line.contains("Parameter:") {
					let param = line.split("Parameter:").nth(1).unwrap_or("").trim();
					let finding = Finding::new(
						VulnerabilityType::SqlInjection,
						Severity::High,
						Confidence::Likely,
						format!("Potential SQL Injection in parameter: {}", param),
						target.to_string(),
						"sqlmap".to_string(),
					);
					findings.push(finding);
				}
			}
		}

		findings
	}
}

#[async_trait]
impl Scanner for SqlInjectionScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::SqlInjection
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let sqlmap_path = &config.tools.sqlmap_path;

		// Check if sqlmap is available before trying to run it
		match std::process::Command::new(sqlmap_path)
			.arg("--version")
			.output()
		{
			Ok(_) => {} // sqlmap is available, continue
			Err(_) => {
				eprintln!(
					"WARNING: sqlmap not found at '{}'. SQL Injection scanner skipped.",
					sqlmap_path
				);
				return Ok(Vec::new());
			}
		}

		let sqli_config = &config.scanners.sqli;

		// Create temp file for sqlmap output
		let output_file =
			NamedTempFile::new().map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "sqlmap".to_string(),
				message: e.to_string(),
			})?;
		let output_path = output_file.path().to_path_buf();

		// Build sqlmap command
		let mut cmd = std::process::Command::new(sqlmap_path);
		cmd.arg("-u")
			.arg(target)
			.arg("--level")
			.arg(sqli_config.level.to_string())
			.arg("--risk")
			.arg(sqli_config.risk.to_string())
			.arg("--threads")
			.arg(sqli_config.threads.to_string())
			.arg("--batch")
			.arg("--output-dir")
			.arg(&output_path);

		// Pass cookies to sqlmap (--cookie flag)
		if let Some(ref cookies) = context.cookies {
			cmd.arg("--cookie").arg(cookies);
		}

		// Pass custom headers as --header flags
		for (key, value) in &context.headers {
			cmd.arg("--header").arg(format!("{}: {}", key, value));
		}

		// Add tamper scripts
		for tamper in &sqli_config.tamper {
			cmd.arg("--tamper").arg(tamper);
		}

		// Execute sqlmap
		let output = cmd
			.output()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "sqlmap".to_string(),
				message: e.to_string(),
			})?;

		let stdout = String::from_utf8_lossy(&output.stdout);
		let stderr = String::from_utf8_lossy(&output.stderr);

		// Parse output
		let findings = self.parse_sqlmap_output(&stdout, target);

		// Also check stderr for errors
		if !output.status.success() && !stderr.is_empty() {
			eprintln!("sqlmap stderr: {}", stderr);
		}

		Ok(findings)
	}
}

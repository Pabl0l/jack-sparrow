use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use tempfile::NamedTempFile;

pub struct SsrfScanner;

impl SsrfScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Create a Burp-style request file for ssrfmap
	fn create_request_file(
		&self,
		target: &str,
		context: &ScanContext,
	) -> Result<String, JackSparrowError> {
		// Parse URL and create a basic request
		let url = url::Url::parse(target)
			.map_err(|e| JackSparrowError::InvalidTarget { url: e.to_string() })?;

		let host = url.host_str().unwrap_or("localhost");
		let path = url.path();
		let query = url.query().unwrap_or("");

		let mut headers = format!(
			"GET {}?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: JackSparrow/0.2.0\r\nAccept: */*\r\nConnection: close",
			path, query, host
		);

		// Add cookies to request
		if let Some(ref cookies) = context.cookies {
			headers.push_str(&format!("\r\nCookie: {}", cookies));
		}

		// Add custom headers
		for (key, value) in &context.headers {
			headers.push_str(&format!("\r\n{}: {}", key, value));
		}

		headers.push_str("\r\n\r\n");
		Ok(headers)
	}

	/// Parse ssrfmap output into findings
	fn parse_ssrfmap_output(&self, output: &str, target: &str) -> Vec<Finding> {
		let mut findings = Vec::new();

		// Look for SSRF indicators in output
		let indicators = [
			"root:",
			"bin:",
			"daemon:",
			"127.0.0.1",
			"localhost",
			"metadata",
			"instance",
		];

		for line in output.lines() {
			for indicator in &indicators {
				if line.contains(indicator) {
					let finding = Finding::new(
						VulnerabilityType::Ssrf,
						Severity::High,
						Confidence::Confirmed,
						"SSRF vulnerability detected".to_string(),
						target.to_string(),
						"ssrfmap".to_string(),
					);
					findings.push(finding);
					return findings;
				}
			}
		}

		// Check for port scan results
		if output.contains("open") && output.contains("closed") {
			let finding = Finding::new(
				VulnerabilityType::Ssrf,
				Severity::Medium,
				Confidence::Likely,
				"SSRF with port scanning capability".to_string(),
				target.to_string(),
				"ssrfmap".to_string(),
			);
			findings.push(finding);
		}

		findings
	}
}

#[async_trait]
impl Scanner for SsrfScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::Ssrf
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let ssrfmap_path = &config.tools.ssrfmap_path;

		// Check if ssrfmap is available before trying to run it
		match std::process::Command::new(ssrfmap_path)
			.arg("--help")
			.output()
		{
			Ok(_) => {} // ssrfmap is available, continue
			Err(_) => {
				eprintln!(
					"WARNING: ssrfmap not found at '{}'. SSRF scanner skipped.",
					ssrfmap_path
				);
				return Ok(Vec::new());
			}
		}

		let ssrf_config = &config.scanners.ssrf;

		// Create request file (with cookies and headers)
		let request_content = self.create_request_file(target, context)?;
		let request_file =
			NamedTempFile::new().map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "ssrfmap".to_string(),
				message: e.to_string(),
			})?;
		std::fs::write(request_file.path(), &request_content).map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "ssrfmap".to_string(),
				message: e.to_string(),
			}
		})?;

		// Create output file
		let _output_file =
			NamedTempFile::new().map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "ssrfmap".to_string(),
				message: e.to_string(),
			})?;

		// Build ssrfmap command
		let mut cmd = std::process::Command::new(ssrfmap_path);
		cmd.arg("-r")
			.arg(request_file.path())
			.arg("-p")
			.arg("url") // Default parameter to fuzz
			.arg("-m")
			.arg(ssrf_config.modules.join(","))
			.arg("--level")
			.arg(ssrf_config.level.to_string());

		// Add target files for readfiles module
		if ssrf_config.modules.contains(&"readfiles".to_string()) {
			cmd.arg("--rfiles").arg(ssrf_config.target_files.join(","));
		}

		// Execute ssrfmap
		let output = cmd
			.output()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "ssrfmap".to_string(),
				message: e.to_string(),
			})?;

		let stdout = String::from_utf8_lossy(&output.stdout);
		let stderr = String::from_utf8_lossy(&output.stderr);

		// Parse output
		let findings = self.parse_ssrfmap_output(&stdout, target);

		// Also check stderr for errors
		if !output.status.success() && !stderr.is_empty() {
			eprintln!("ssrfmap stderr: {}", stderr);
		}

		Ok(findings)
	}
}

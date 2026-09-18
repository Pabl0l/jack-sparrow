use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for Jack Sparrow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JackSparrowConfig {
	/// General settings
	pub general: GeneralConfig,
	/// Scanner-specific settings
	pub scanners: ScannerConfig,
	/// Tool paths
	pub tools: ToolConfig,
	/// Output settings
	pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
	/// Maximum concurrent scans
	pub max_concurrent: usize,
	/// Request timeout in seconds
	pub timeout_secs: u64,
	/// User agent string
	pub user_agent: String,
	/// Verbose output
	pub verbose: bool,
	/// Rate limit per domain (requests per second, 0 = unlimited)
	pub rate_limit_rps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
	/// SQL Injection settings
	pub sqli: SqlInjectionConfig,
	/// XSS settings
	pub xss: XssConfig,
	/// IDOR settings
	pub idor: IdorConfig,
	/// SSRF settings
	pub ssrf: SsrfConfig,
	/// Supply Chain settings
	pub supply_chain: SupplyChainConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionConfig {
	/// sqlmap level (1-5)
	pub level: u8,
	/// sqlmap risk (1-3)
	pub risk: u8,
	/// Number of threads
	pub threads: u8,
	/// Use tamper scripts
	pub tamper: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssConfig {
	/// dalfox workers
	pub workers: usize,
	/// Enable WAF evasion
	pub waf_evasion: bool,
	/// Custom payloads file
	pub custom_payloads: Option<PathBuf>,
	/// Blind XSS callback URL
	pub blind_callback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorConfig {
	/// Parameter names to test
	pub param_names: Vec<String>,
	/// ID range to test
	pub id_range: (u64, u64),
	/// Response similarity threshold (0-1)
	pub similarity_threshold: f64,
	/// Include common object paths
	pub common_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfConfig {
	/// ssrfmap level (1-5)
	pub level: u8,
	/// Modules to enable
	pub modules: Vec<String>,
	/// Files to read (for readfiles module)
	pub target_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainConfig {
	/// Check npm dependencies
	pub check_npm: bool,
	/// Check pip dependencies
	pub check_pip: bool,
	/// Check cargo dependencies
	pub check_cargo: bool,
	/// Severity threshold to report
	pub severity_threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
	/// Path to sqlmap
	pub sqlmap_path: String,
	/// Path to dalfox
	pub dalfox_path: String,
	/// Path to ssrfmap
	pub ssrfmap_path: String,
	/// Path to npm
	pub npm_path: String,
	/// Path to pip-audit
	pub pip_audit_path: String,
	/// Path to cargo-audit
	pub cargo_audit_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
	/// Output directory for reports
	pub output_dir: PathBuf,
	/// Output format (json, html, markdown)
	pub format: String,
	/// Include raw evidence in report
	pub include_evidence: bool,
	/// Include request/response in report
	pub include_requests: bool,
}

impl Default for JackSparrowConfig {
	fn default() -> Self {
		Self {
			general: GeneralConfig {
				max_concurrent: 4,
				timeout_secs: 300,
				user_agent: "JackSparrow/0.2.0".to_string(),
				verbose: false,
				rate_limit_rps: 10.0,
			},
			scanners: ScannerConfig {
				sqli: SqlInjectionConfig {
					level: 3,
					risk: 1,
					threads: 4,
					tamper: Vec::new(),
				},
				xss: XssConfig {
					workers: 50,
					waf_evasion: false,
					custom_payloads: None,
					blind_callback: None,
				},
				idor: IdorConfig {
					param_names: vec![
						"id".to_string(),
						"user_id".to_string(),
						"account_id".to_string(),
						"item_id".to_string(),
						"order_id".to_string(),
					],
					id_range: (1, 100),
					similarity_threshold: 0.8,
					common_paths: vec![
						"/api/users".to_string(),
						"/api/products".to_string(),
						"/api/orders".to_string(),
					],
				},
				ssrf: SsrfConfig {
					level: 2,
					modules: vec!["readfiles".to_string(), "portscan".to_string()],
					target_files: vec!["/etc/passwd".to_string(), "/etc/hostname".to_string()],
				},
				supply_chain: SupplyChainConfig {
					check_npm: true,
					check_pip: true,
					check_cargo: true,
					severity_threshold: "medium".to_string(),
				},
			},
			tools: ToolConfig {
				sqlmap_path: "sqlmap".to_string(),
				dalfox_path: "dalfox".to_string(),
				ssrfmap_path: "ssrfmap".to_string(),
				npm_path: "npm".to_string(),
				pip_audit_path: "pip-audit".to_string(),
				cargo_audit_path: "cargo-audit".to_string(),
			},
			output: OutputConfig {
				output_dir: PathBuf::from("./reports"),
				format: "json".to_string(),
				include_evidence: true,
				include_requests: false,
			},
		}
	}
}

/// Validation error details
#[derive(Debug, Clone)]
pub struct ValidationError {
	pub field: String,
	pub message: String,
}

impl std::fmt::Display for ValidationError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "config.{}: {}", self.field, self.message)
	}
}

impl JackSparrowConfig {
	/// Load configuration from TOML file
	pub fn from_file(path: &PathBuf) -> Result<Self, crate::shared::error::JackSparrowError> {
		let content = std::fs::read_to_string(path)?;
		let config: JackSparrowConfig = toml::from_str(&content).map_err(|e| {
			crate::shared::error::JackSparrowError::ConfigError {
				message: e.to_string(),
			}
		})?;
		config.validate()?;
		Ok(config)
	}

	/// Save configuration to TOML file
	pub fn to_file(&self, path: &PathBuf) -> Result<(), crate::shared::error::JackSparrowError> {
		self.validate()?;
		let content = toml::to_string_pretty(self).map_err(|e| {
			crate::shared::error::JackSparrowError::ConfigError {
				message: e.to_string(),
			}
		})?;
		std::fs::write(path, content)?;
		Ok(())
	}

	/// Validate configuration values are within acceptable ranges.
	///
	/// Returns `Ok(())` if valid, or `ConfigError` with details of all invalid fields.
	pub fn validate(&self) -> Result<(), crate::shared::error::JackSparrowError> {
		let mut errors = Vec::new();

		// General config
		if self.general.max_concurrent == 0 {
			errors.push(ValidationError {
				field: "general.max_concurrent".into(),
				message: "must be >= 1".into(),
			});
		}
		if self.general.max_concurrent > 64 {
			errors.push(ValidationError {
				field: "general.max_concurrent".into(),
				message: "must be <= 64 (resource safety)".into(),
			});
		}
		if self.general.timeout_secs == 0 {
			errors.push(ValidationError {
				field: "general.timeout_secs".into(),
				message: "must be >= 1".into(),
			});
		}
		if self.general.timeout_secs > 3600 {
			errors.push(ValidationError {
				field: "general.timeout_secs".into(),
				message: "must be <= 3600 (1 hour max)".into(),
			});
		}
		if self.general.user_agent.is_empty() {
			errors.push(ValidationError {
				field: "general.user_agent".into(),
				message: "must not be empty".into(),
			});
		}
		if self.general.rate_limit_rps < 0.0 {
			errors.push(ValidationError {
				field: "general.rate_limit_rps".into(),
				message: "must be >= 0.0".into(),
			});
		}

		// SQLi config
		if self.scanners.sqli.level == 0 || self.scanners.sqli.level > 5 {
			errors.push(ValidationError {
				field: "scanners.sqli.level".into(),
				message: "must be 1-5".into(),
			});
		}
		if self.scanners.sqli.risk == 0 || self.scanners.sqli.risk > 3 {
			errors.push(ValidationError {
				field: "scanners.sqli.risk".into(),
				message: "must be 1-3".into(),
			});
		}
		if self.scanners.sqli.threads == 0 {
			errors.push(ValidationError {
				field: "scanners.sqli.threads".into(),
				message: "must be >= 1".into(),
			});
		}

		// XSS config
		if self.scanners.xss.workers == 0 {
			errors.push(ValidationError {
				field: "scanners.xss.workers".into(),
				message: "must be >= 1".into(),
			});
		}

		// IDOR config
		if self.scanners.idor.id_range.0 > self.scanners.idor.id_range.1 {
			errors.push(ValidationError {
				field: "scanners.idor.id_range".into(),
				message: "start must be <= end".into(),
			});
		}
		if self.scanners.idor.similarity_threshold < 0.0
			|| self.scanners.idor.similarity_threshold > 1.0
		{
			errors.push(ValidationError {
				field: "scanners.idor.similarity_threshold".into(),
				message: "must be 0.0-1.0".into(),
			});
		}

		// SSRF config
		if self.scanners.ssrf.level == 0 || self.scanners.ssrf.level > 5 {
			errors.push(ValidationError {
				field: "scanners.ssrf.level".into(),
				message: "must be 1-5".into(),
			});
		}

		// Supply chain config
		let valid_thresholds = ["critical", "high", "medium", "low", "info"];
		if !valid_thresholds.contains(&self.scanners.supply_chain.severity_threshold.as_str()) {
			errors.push(ValidationError {
				field: "scanners.supply_chain.severity_threshold".into(),
				message: format!(
					"must be one of: {}",
					valid_thresholds.join(", ")
				),
			});
		}

		// Output config
		let valid_formats = ["json", "html", "markdown"];
		if !valid_formats.contains(&self.output.format.as_str()) {
			errors.push(ValidationError {
				field: "output.format".into(),
				message: format!("must be one of: {}", valid_formats.join(", ")),
			});
		}

		if errors.is_empty() {
			Ok(())
		} else {
			let msg: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
			Err(crate::shared::error::JackSparrowError::ConfigError {
				message: msg.join("; "),
			})
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_config_is_valid() {
		let config = JackSparrowConfig::default();
		assert!(config.validate().is_ok());
	}

	#[test]
	fn validate_rejects_zero_concurrent() {
		let mut config = JackSparrowConfig::default();
		config.general.max_concurrent = 0;
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_extreme_concurrent() {
		let mut config = JackSparrowConfig::default();
		config.general.max_concurrent = 100;
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_invalid_sqli_level() {
		let mut config = JackSparrowConfig::default();
		config.scanners.sqli.level = 10;
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_invalid_sqli_risk() {
		let mut config = JackSparrowConfig::default();
		config.scanners.sqli.risk = 0;
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_inverted_idor_range() {
		let mut config = JackSparrowConfig::default();
		config.scanners.idor.id_range = (100, 1);
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_out_of_range_similarity() {
		let mut config = JackSparrowConfig::default();
		config.scanners.idor.similarity_threshold = 1.5;
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_invalid_format() {
		let mut config = JackSparrowConfig::default();
		config.output.format = "xml".to_string();
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_rejects_invalid_severity_threshold() {
		let mut config = JackSparrowConfig::default();
		config.scanners.supply_chain.severity_threshold = "urgent".to_string();
		assert!(config.validate().is_err());
	}

	#[test]
	fn validate_accepts_all_valid_thresholds() {
		for threshold in &["critical", "high", "medium", "low", "info"] {
			let mut config = JackSparrowConfig::default();
			config.scanners.supply_chain.severity_threshold = threshold.to_string();
			assert!(config.validate().is_ok(), "Failed for threshold: {}", threshold);
		}
	}
}

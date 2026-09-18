use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use std::path::Path;
use std::process::Command;

pub struct SupplyChainScanner {
	config: JackSparrowConfig,
}

impl SupplyChainScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Detect the ecosystem of a project
    pub fn detect_ecosystem(&self, path: &Path) -> Vec<String> {
        let mut ecosystems = Vec::new();

        if path.join("package.json").exists() || path.join("package-lock.json").exists() {
            ecosystems.push("npm".to_string());
        }

        if path.join("requirements.txt").exists()
            || path.join("Pipfile").exists()
            || path.join("pyproject.toml").exists()
        {
            ecosystems.push("pip".to_string());
        }

        if path.join("Cargo.toml").exists() {
            ecosystems.push("cargo".to_string());
        }

        if path.join("go.mod").exists() {
            ecosystems.push("go".to_string());
        }

        ecosystems
    }

    /// Run npm audit
    fn run_npm_audit(&self, path: &Path) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        let output = Command::new(&self.config.tools.npm_path)
            .arg("audit")
            .arg("--json")
            .current_dir(path)
            .output()
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "npm".to_string(),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(vulnerabilities) = json.get("vulnerabilities") {
                if let Some(vulns) = vulnerabilities.as_object() {
                    for (name, details) in vulns {
                        let severity = match details.get("severity").and_then(|s| s.as_str()) {
                            Some("critical") => Severity::Critical,
                            Some("high") => Severity::High,
                            Some("moderate") => Severity::Medium,
                            Some("low") => Severity::Low,
                            _ => Severity::Info,
                        };

                        let mut finding = Finding::new(
                            VulnerabilityType::SupplyChainDependency,
                            severity,
                            Confidence::Confirmed,
                            format!("Vulnerable dependency: {}", name),
                            path.to_string_lossy().to_string(),
                            "npm-audit".to_string(),
                        );

                        finding.description = details
                            .get("via")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown vulnerability")
                            .to_string();

                        finding.evidence = Evidence {
                            request: None,
                            response: None,
                            payload: None,
                            pattern: None,
                            context: Some(
                                serde_json::to_string_pretty(details).unwrap_or_default(),
                            ),
                        };

                        findings.push(finding);
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Run pip-audit
    fn run_pip_audit(&self, path: &Path) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        let output = Command::new(&self.config.tools.pip_audit_path)
            .arg("--format")
            .arg("json")
            .current_dir(path)
            .output()
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "pip-audit".to_string(),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(dependencies) = json.get("dependencies") {
                if let Some(deps) = dependencies.as_array() {
                    for dep in deps {
                        if let Some(vulns) = dep.get("vulns").and_then(|v| v.as_array()) {
                            if !vulns.is_empty() {
                                let name = dep
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");
                                let version = dep
                                    .get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");

                                let finding = Finding::new(
                                    VulnerabilityType::SupplyChainDependency,
                                    Severity::High,
                                    Confidence::Confirmed,
                                    format!("Vulnerable Python package: {} {}", name, version),
                                    path.to_string_lossy().to_string(),
                                    "pip-audit".to_string(),
                                );

                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Run cargo audit
    fn run_cargo_audit(&self, path: &Path) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        let output = Command::new(&self.config.tools.cargo_audit_path)
            .arg("audit")
            .arg("--json")
            .current_dir(path)
            .output()
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "cargo-audit".to_string(),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(vulnerabilities) = json.get("vulnerabilities") {
                if let Some(vulns) = vulnerabilities.get("list") {
                    if let Some(vulns_array) = vulns.as_array() {
                        for vuln in vulns_array {
                            let pkg = vuln
                                .get("package")
                                .and_then(|p| p.as_str())
                                .unwrap_or("unknown");
                            let version = vuln
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            let severity = match vuln
                                .get("cvss")
                                .and_then(|c| c.get("score"))
                                .and_then(|s| s.as_f64())
                            {
                                Some(score) if score >= 9.0 => Severity::Critical,
                                Some(score) if score >= 7.0 => Severity::High,
                                Some(score) if score >= 4.0 => Severity::Medium,
                                _ => Severity::Low,
                            };

                            let finding = Finding::new(
                                VulnerabilityType::SupplyChainDependency,
                                severity,
                                Confidence::Confirmed,
                                format!("Vulnerable Rust crate: {} {}", pkg, version),
                                path.to_string_lossy().to_string(),
                                "cargo-audit".to_string(),
                            );

                            findings.push(finding);
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[async_trait]
impl Scanner for SupplyChainScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::SupplyChain
    }

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		_context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
        let path = Path::new(target);
        let supply_config = &config.scanners.supply_chain;

        // Detect ecosystems
        let ecosystems = self.detect_ecosystem(path);

        let mut findings = Vec::new();

        // Run audits based on detected ecosystems
        for ecosystem in &ecosystems {
            match ecosystem.as_str() {
                "npm" if supply_config.check_npm => {
                    findings.extend(self.run_npm_audit(path)?);
                }
                "pip" if supply_config.check_pip => {
                    findings.extend(self.run_pip_audit(path)?);
                }
                "cargo" if supply_config.check_cargo => {
                    findings.extend(self.run_cargo_audit(path)?);
                }
                _ => {}
            }
        }

        // If no ecosystem detected, try all enabled checks
        if ecosystems.is_empty() {
            if supply_config.check_npm {
                if let Ok(new_findings) = self.run_npm_audit(path) {
                    findings.extend(new_findings);
                }
            }
            if supply_config.check_pip {
                if let Ok(new_findings) = self.run_pip_audit(path) {
                    findings.extend(new_findings);
                }
            }
            if supply_config.check_cargo {
                if let Ok(new_findings) = self.run_cargo_audit(path) {
                    findings.extend(new_findings);
                }
            }
        }

        Ok(findings)
    }
}

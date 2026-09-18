#![allow(dead_code)]

use crate::shared::config::ToolConfig;
use crate::shared::error::JackSparrowError;
use std::process::Command;

/// Check if a tool is available in the system
pub fn check_tool(_tool_name: &str, tool_path: &str) -> Result<bool, JackSparrowError> {
    let output = Command::new(tool_path).arg("--version").output();

    match output {
        Ok(output) => Ok(output.status.success()),
        Err(_) => Ok(false),
    }
}

/// Verify all required tools are installed
pub fn verify_all_tools(config: &ToolConfig) -> Result<Vec<String>, JackSparrowError> {
    let mut missing = Vec::new();

    let tools = vec![
        ("sqlmap", &config.sqlmap_path),
        ("dalfox", &config.dalfox_path),
        ("ssrfmap", &config.ssrfmap_path),
        ("npm", &config.npm_path),
        ("pip-audit", &config.pip_audit_path),
        ("cargo-audit", &config.cargo_audit_path),
    ];

    for (name, path) in tools {
        if !check_tool(name, path)? {
            missing.push(name.to_string());
        }
    }

    Ok(missing)
}

/// Get version of a tool
pub fn get_tool_version(tool_path: &str) -> Result<String, JackSparrowError> {
    let output = Command::new(tool_path)
        .arg("--version")
        .output()
        .map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: tool_path.to_string(),
            message: e.to_string(),
        })?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim().to_string())
    } else {
        Err(JackSparrowError::ToolExecutionFailed {
            tool: tool_path.to_string(),
            message: "Failed to get version".to_string(),
        })
    }
}

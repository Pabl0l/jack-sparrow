#![allow(dead_code)]

use thiserror::Error;

/// Errors that can occur in Jack Sparrow
#[derive(Error, Debug)]
pub enum JackSparrowError {
    #[error("Tool not found: {tool}. Please install it first.")]
    ToolNotFound { tool: String },

    #[error("Tool execution failed: {tool} - {message}")]
    ToolExecutionFailed { tool: String, message: String },

    #[error("Invalid target URL: {url}")]
    InvalidTarget { url: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Playwright error: {0}")]
    Playwright(String),

    #[error("Scan cancelled by user")]
    Cancelled,

    #[error("Timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("No findings detected")]
    NoFindings,

    #[error("Lab environment error: {message}")]
    LabError { message: String },
}

impl JackSparrowError {
    /// Create a tool not found error
    pub fn tool_not_found(tool: &str) -> Self {
        JackSparrowError::ToolNotFound {
            tool: tool.to_string(),
        }
    }

    /// Create a tool execution failed error
    pub fn tool_execution_failed(tool: &str, message: &str) -> Self {
        JackSparrowError::ToolExecutionFailed {
            tool: tool.to_string(),
            message: message.to_string(),
        }
    }
}

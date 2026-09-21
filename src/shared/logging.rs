#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

/// A single audit log entry recording an HTTP request/response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the request
    pub timestamp: DateTime<Utc>,
    /// Scanner that made the request
    pub scanner: String,
    /// HTTP method
    pub method: String,
    /// Request URL
    pub url: String,
    /// Request headers (sanitized — no auth tokens)
    pub request_headers: Vec<(String, String)>,
    /// Request body size in bytes
    pub request_body_size: Option<usize>,
    /// Response status code
    pub response_status: Option<u16>,
    /// Response headers
    pub response_headers: Vec<(String, String)>,
    /// Response body size in bytes
    pub response_body_size: Option<usize>,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Whether the request was retried
    pub retry_count: u32,
    /// Error message if the request failed
    pub error: Option<String>,
    /// Severity of the finding (if this request produced one)
    pub finding_severity: Option<String>,
}

/// Complete audit log for a scan session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAuditLog {
    /// Scan session ID
    pub session_id: String,
    /// Target URL
    pub target: String,
    /// Scan start time
    pub started_at: DateTime<Utc>,
    /// Scan end time
    pub ended_at: Option<DateTime<Utc>>,
    /// All HTTP entries
    pub entries: Vec<AuditEntry>,
    /// Total requests made
    pub total_requests: usize,
    /// Total retries
    pub total_retries: usize,
    /// Total errors
    pub total_errors: usize,
}

impl ScanAuditLog {
    pub fn new(session_id: &str, target: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            target: target.to_string(),
            started_at: Utc::now(),
            ended_at: None,
            entries: Vec::new(),
            total_requests: 0,
            total_retries: 0,
            total_errors: 0,
        }
    }

    /// Record an HTTP request/response
    pub fn record(&mut self, entry: AuditEntry) {
        if entry.error.is_some() {
            self.total_errors += 1;
        }
        self.total_retries += entry.retry_count as usize;
        self.total_requests += 1;
        self.entries.push(entry);
    }

    /// Mark the scan as completed
    pub fn finish(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    /// Get summary statistics
    pub fn summary(&self) -> AuditSummary {
        let scanners: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.scanner.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let avg_duration = if self.entries.is_empty() {
            0.0
        } else {
            self.entries.iter().map(|e| e.duration_ms as f64).sum::<f64>()
                / self.entries.len() as f64
        };

        let status_counts = self
            .entries
            .iter()
            .filter_map(|e| e.response_status)
            .fold(std::collections::HashMap::new(), |mut acc, s| {
                *acc.entry(s).or_insert(0) += 1;
                acc
            });

        AuditSummary {
            session_id: self.session_id.clone(),
            target: self.target.clone(),
            total_requests: self.total_requests,
            total_retries: self.total_retries,
            total_errors: self.total_errors,
            unique_scanners: scanners,
            avg_request_duration_ms: avg_duration,
            status_code_distribution: status_counts,
        }
    }

    /// Save audit log to JSON file
    pub fn save(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }
}

/// Summary of audit log statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub session_id: String,
    pub target: String,
    pub total_requests: usize,
    pub total_retries: usize,
    pub total_errors: usize,
    pub unique_scanners: Vec<String>,
    pub avg_request_duration_ms: f64,
    pub status_code_distribution: std::collections::HashMap<u16, usize>,
}

/// Thread-safe audit logger for concurrent scanner use
pub struct AuditLogger {
    log: Mutex<ScanAuditLog>,
}

impl AuditLogger {
    pub fn new(session_id: &str, target: &str) -> Self {
        Self {
            log: Mutex::new(ScanAuditLog::new(session_id, target)),
        }
    }

    /// Record an entry (thread-safe)
    pub fn record(&self, entry: AuditEntry) {
        if let Ok(mut log) = self.log.lock() {
            log.record(entry);
        }
    }

    /// Record a request with timing
    pub fn record_request(
        &self,
        scanner: &str,
        method: &str,
        url: &str,
        status: Option<u16>,
        duration_ms: u64,
        retry_count: u32,
        error: Option<String>,
        request_body_size: Option<usize>,
        response_body_size: Option<usize>,
    ) {
        self.record(AuditEntry {
            timestamp: Utc::now(),
            scanner: scanner.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            request_headers: Vec::new(),
            request_body_size,
            response_status: status,
            response_headers: Vec::new(),
            response_body_size,
            duration_ms,
            retry_count,
            error,
            finding_severity: None,
        });
    }

    /// Get a snapshot of the current log
    pub fn snapshot(&self) -> Option<ScanAuditLog> {
        self.log.lock().ok().map(|guard| (*guard).clone())
    }

    /// Save to file
    pub fn save(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        if let Ok(log) = self.log.lock() {
            log.save(path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to acquire audit log lock",
            ))
        }
    }

    /// Finish the scan and return the complete log
    pub fn finish(&self) -> Option<ScanAuditLog> {
        if let Ok(mut log) = self.log.lock() {
            log.finish();
            Some(log.clone())
        } else {
            None
        }
    }
}

/// Sanitize headers by removing sensitive values
pub fn sanitize_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let sensitive_keys = [
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    ];

    headers
        .iter()
        .map(|(k, v)| {
            if sensitive_keys.contains(&k.to_lowercase().as_str()) {
                (k.clone(), "[REDACTED]".to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// Initialize structured logging with tracing
pub fn init_logging(verbose: bool, log_file: Option<&str>) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let env_filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    if let Some(path) = log_file {
        match std::fs::File::create(path) {
            Ok(file) => {
                fmt()
                    .with_env_filter(env_filter)
                    .with_target(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .init();
            }
            Err(_) => {
                fmt()
                    .with_env_filter(env_filter)
                    .with_target(false)
                    .init();
            }
        }
    } else {
        fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_new() {
        let log = ScanAuditLog::new("session-1", "http://example.com");
        assert_eq!(log.session_id, "session-1");
        assert_eq!(log.target, "http://example.com");
        assert!(log.entries.is_empty());
        assert_eq!(log.total_requests, 0);
    }

    #[test]
    fn test_audit_log_record() {
        let mut log = ScanAuditLog::new("s1", "http://test.com");
        log.record(AuditEntry {
            timestamp: Utc::now(),
            scanner: "headers".to_string(),
            method: "GET".to_string(),
            url: "http://test.com".to_string(),
            request_headers: vec![],
            request_body_size: None,
            response_status: Some(200),
            response_headers: vec![],
            response_body_size: Some(1024),
            duration_ms: 150,
            retry_count: 0,
            error: None,
            finding_severity: None,
        });
        assert_eq!(log.total_requests, 1);
        assert_eq!(log.total_errors, 0);
    }

    #[test]
    fn test_audit_log_record_error() {
        let mut log = ScanAuditLog::new("s1", "http://test.com");
        log.record(AuditEntry {
            timestamp: Utc::now(),
            scanner: "ssti".to_string(),
            method: "POST".to_string(),
            url: "http://test.com/render".to_string(),
            request_headers: vec![],
            request_body_size: Some(100),
            response_status: None,
            response_headers: vec![],
            response_body_size: None,
            duration_ms: 5000,
            retry_count: 3,
            error: Some("Connection refused".to_string()),
            finding_severity: None,
        });
        assert_eq!(log.total_requests, 1);
        assert_eq!(log.total_errors, 1);
        assert_eq!(log.total_retries, 3);
    }

    #[test]
    fn test_audit_log_finish() {
        let mut log = ScanAuditLog::new("s1", "http://test.com");
        assert!(log.ended_at.is_none());
        log.finish();
        assert!(log.ended_at.is_some());
    }

    #[test]
    fn test_audit_log_summary() {
        let mut log = ScanAuditLog::new("s1", "http://test.com");
        log.record(AuditEntry {
            timestamp: Utc::now(),
            scanner: "headers".to_string(),
            method: "GET".to_string(),
            url: "http://test.com".to_string(),
            request_headers: vec![],
            request_body_size: None,
            response_status: Some(200),
            response_headers: vec![],
            response_body_size: None,
            duration_ms: 100,
            retry_count: 0,
            error: None,
            finding_severity: None,
        });
        log.record(AuditEntry {
            timestamp: Utc::now(),
            scanner: "headers".to_string(),
            method: "GET".to_string(),
            url: "http://test.com/login".to_string(),
            request_headers: vec![],
            request_body_size: None,
            response_status: Some(404),
            response_headers: vec![],
            response_body_size: None,
            duration_ms: 200,
            retry_count: 0,
            error: None,
            finding_severity: None,
        });

        let summary = log.summary();
        assert_eq!(summary.total_requests, 2);
        assert!(summary.unique_scanners.contains(&"headers".to_string()));
        assert_eq!(summary.avg_request_duration_ms, 150.0);
    }

    #[test]
    fn test_sanitize_headers() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer secret123".to_string()),
            ("Cookie".to_string(), "session=abc".to_string()),
            ("X-Custom".to_string(), "value".to_string()),
        ];

        let sanitized = sanitize_headers(&headers);
        assert_eq!(sanitized[0].1, "application/json");
        assert_eq!(sanitized[1].1, "[REDACTED]");
        assert_eq!(sanitized[2].1, "[REDACTED]");
        assert_eq!(sanitized[3].1, "value");
    }

    #[test]
    fn test_audit_logger_thread_safe() {
        let logger = AuditLogger::new("s1", "http://test.com");
        logger.record_request("headers", "GET", "http://test.com", Some(200), 100, 0, None, None, None);
        logger.record_request("ssti", "POST", "http://test.com/r", Some(500), 5000, 2, Some("timeout".to_string()), None, None);

        let snapshot = logger.snapshot().unwrap();
        assert_eq!(snapshot.total_requests, 2);
        assert_eq!(snapshot.total_errors, 1);
    }
}

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a finding
pub type FindingId = Uuid;

/// Vulnerability types supported by Jack Sparrow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
	/// SQL Injection (error-based, blind, time-based)
	SqlInjection,
	/// Cross-Site Scripting (reflected, stored, DOM-based)
	XssReflected,
	XssStored,
	XssDom,
	/// Insecure Direct Object Reference
	Idor,
	/// Server-Side Request Forgery
	Ssrf,
	/// Software Supply Chain vulnerabilities
	SupplyChainDependency,
	SupplyChainMalicious,
	/// Missing or weak security header
	SecurityHeader,
	/// Technology fingerprint (informational)
	TechFingerprint,
	/// Exposed secret or credential
	SecretExposed,
	/// Subdomain discovered
	SubdomainFound,
	/// WAF/CDN detected
	WafDetected,
	/// JWT security issue
	JwtIssue,
	/// GraphQL introspection/schema issue
	GraphQLIntrospection,
	/// API security issue (CORS, methods, errors, rate limiting)
	ApiSecurity,
	/// XML External Entity injection
	Xxe,
	/// Server-Side Template Injection
	Ssti,
	/// Form injection (SQLi/XSS/SSTI via POST body)
	FormInjection,
	/// Cross-Site Request Forgery
	Csrf,
	/// Unrestricted file upload
	FileUpload,
}

impl std::fmt::Display for VulnerabilityType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			VulnerabilityType::SqlInjection => write!(f, "SQL Injection"),
			VulnerabilityType::XssReflected => write!(f, "Reflected XSS"),
			VulnerabilityType::XssStored => write!(f, "Stored XSS"),
			VulnerabilityType::XssDom => write!(f, "DOM XSS"),
			VulnerabilityType::Idor => write!(f, "IDOR"),
			VulnerabilityType::Ssrf => write!(f, "SSRF"),
			VulnerabilityType::SupplyChainDependency => write!(f, "Dependency Vulnerability"),
			VulnerabilityType::SupplyChainMalicious => write!(f, "Malicious Package"),
			VulnerabilityType::SecurityHeader => write!(f, "Security Header"),
			VulnerabilityType::TechFingerprint => write!(f, "Technology Fingerprint"),
			VulnerabilityType::SecretExposed => write!(f, "Exposed Secret"),
			VulnerabilityType::SubdomainFound => write!(f, "Subdomain Discovered"),
			VulnerabilityType::WafDetected => write!(f, "WAF Detected"),
			VulnerabilityType::JwtIssue => write!(f, "JWT Issue"),
			VulnerabilityType::GraphQLIntrospection => write!(f, "GraphQL Introspection"),
			VulnerabilityType::ApiSecurity => write!(f, "API Security"),
			VulnerabilityType::Xxe => write!(f, "XML External Entity"),
			VulnerabilityType::Ssti => write!(f, "Server-Side Template Injection"),
			VulnerabilityType::FormInjection => write!(f, "Form Injection"),
			VulnerabilityType::Csrf => write!(f, "Cross-Site Request Forgery"),
			VulnerabilityType::FileUpload => write!(f, "Unrestricted File Upload"),
		}
	}
}

/// Severity levels following CVSS-like classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Get numeric rank for sorting
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Confidence level in the finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Confirmed vulnerability
    Confirmed,
    /// Likely vulnerability
    Likely,
    /// Possible vulnerability
    Possible,
    /// False positive
    FalsePositive,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "Confirmed"),
            Confidence::Likely => write!(f, "Likely"),
            Confidence::Possible => write!(f, "Possible"),
            Confidence::FalsePositive => write!(f, "False Positive"),
        }
    }
}

/// Evidence of a vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// HTTP request that triggered the finding
    pub request: Option<String>,
    /// HTTP response containing the vulnerability
    pub response: Option<String>,
    /// Payload used to trigger the vulnerability
    pub payload: Option<String>,
    /// Specific pattern that matched
    pub pattern: Option<String>,
    /// Additional context
    pub context: Option<String>,
}

/// A vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub vulnerability_type: VulnerabilityType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub url: String,
    pub parameter: Option<String>,
    pub evidence: Evidence,
    pub remediation: String,
    pub references: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub cvss_score: Option<f64>,
    pub cwe_id: Option<String>,
    pub tool_source: String,
}

impl Finding {
    /// Create a new finding with defaults
    pub fn new(
        vulnerability_type: VulnerabilityType,
        severity: Severity,
        confidence: Confidence,
        title: String,
        url: String,
        tool_source: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            vulnerability_type,
            severity,
            confidence,
            title,
            description: String::new(),
            url,
            parameter: None,
            evidence: Evidence {
                request: None,
                response: None,
                payload: None,
                pattern: None,
                context: None,
            },
            remediation: String::new(),
            references: Vec::new(),
            timestamp: Utc::now(),
            cvss_score: None,
            cwe_id: None,
            tool_source,
        }
    }
}

/// Scan results summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub findings: Vec<Finding>,
    pub scan_duration_ms: u64,
    pub tools_used: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

impl ScanResults {
    pub fn new(target: String) -> Self {
        Self {
            target,
            findings: Vec::new(),
            scan_duration_ms: 0,
            tools_used: Vec::new(),
            timestamp: Utc::now(),
        }
    }

    /// Get findings by severity
    pub fn by_severity(&self, severity: &Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == *severity)
            .collect()
    }

    /// Get finding count by severity
    pub fn count_by_severity(&self) -> std::collections::HashMap<Severity, usize> {
        let mut counts = std::collections::HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        counts
    }
}

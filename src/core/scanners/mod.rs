use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::Finding;
use async_trait::async_trait;

/// Scanner types available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerType {
	SqlInjection,
	Xss,
	XssStored,
	XssDom,
	Idor,
	Ssrf,
	SupplyChain,
	SecurityHeaders,
	TechFingerprint,
	Secrets,
	SubdomainEnum,
	WafDetection,
	JwtAnalysis,
	GraphQLIntrospection,
	ApiSecurity,
	CloudMetadata,
	Xxe,
	Ssti,
}

impl std::fmt::Display for ScannerType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ScannerType::SqlInjection => write!(f, "SQL Injection"),
			ScannerType::Xss => write!(f, "XSS"),
			ScannerType::XssStored => write!(f, "Stored XSS"),
			ScannerType::XssDom => write!(f, "DOM XSS"),
			ScannerType::Idor => write!(f, "IDOR"),
			ScannerType::Ssrf => write!(f, "SSRF"),
			ScannerType::SupplyChain => write!(f, "Supply Chain"),
			ScannerType::SecurityHeaders => write!(f, "Security Headers"),
			ScannerType::TechFingerprint => write!(f, "Tech Fingerprint"),
			ScannerType::Secrets => write!(f, "Secrets"),
			ScannerType::SubdomainEnum => write!(f, "Subdomain Enumeration"),
			ScannerType::WafDetection => write!(f, "WAF Detection"),
			ScannerType::JwtAnalysis => write!(f, "JWT Analysis"),
			ScannerType::GraphQLIntrospection => write!(f, "GraphQL Introspection"),
			ScannerType::ApiSecurity => write!(f, "API Security"),
			ScannerType::CloudMetadata => write!(f, "Cloud Metadata SSRF"),
			ScannerType::Xxe => write!(f, "XXE"),
			ScannerType::Ssti => write!(f, "SSTI"),
		}
	}
}

/// Trait for all vulnerability scanners
#[async_trait]
pub trait Scanner: Send + Sync {
	/// Get the scanner type
	#[allow(dead_code)]
	fn scanner_type(&self) -> ScannerType;

	/// Scan a target for vulnerabilities.
	///
	/// `context` carries auth info (cookies, headers) so scanners
	/// can test authenticated endpoints.
	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError>;
}

pub mod api_security;
pub mod cloud_metadata;
pub mod crawl_integration;
pub mod dom_xss;
pub mod graphql;
pub mod headers;
pub mod idor;
pub mod jwt;
pub mod secrets;
pub mod sqli;
pub mod sqli_native;
pub mod ssti;
pub mod ssrf;
pub mod ssrf_native;
pub mod stored_xss;
pub mod subdomain;
pub mod supply_chain;
pub mod tech_fingerprint;
pub mod waf;
pub mod xss;
pub mod xxe;

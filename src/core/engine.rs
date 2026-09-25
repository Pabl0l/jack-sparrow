#![allow(dead_code)]

use crate::core::crawler::engine::CrawlResults;
use crate::core::scanners::crawl_integration::CrawlTargetExtractor;
use crate::core::scanners::dom_xss::DomXssScanner;
use crate::core::scanners::headers::SecurityHeadersScanner;
use crate::core::scanners::idor::IdorScanner;
use crate::core::scanners::jwt::JwtAnalysisScanner;
use crate::core::scanners::secrets::SecretsScanner;
use crate::core::scanners::stored_xss::StoredXssScanner;
use crate::core::scanners::subdomain::SubdomainEnumScanner;
use crate::core::scanners::supply_chain::SupplyChainScanner;
use crate::core::scanners::tech_fingerprint::TechFingerprintScanner;
use crate::core::scanners::waf::WafDetectionScanner;
use crate::core::scanners::graphql::GraphQLIntrospectionScanner;
use crate::core::scanners::api_security::ApiSecurityScanner;
use crate::core::scanners::cloud_metadata::CloudMetadataScanner;
use crate::core::scanners::xxe::XxeScanner;
use crate::core::scanners::ssti::SstiScanner;
use crate::core::scanners::xss::XssScanner;
use crate::core::scanners::sqli_native::NativeSqlScanner;
use crate::core::scanners::ssrf_native::NativeSsrfScanner;
use crate::core::scanners::file_upload::FileUploadScanner;
use crate::core::scanners::csrf::CsrfScanner;
use crate::core::scanners::form_injection::FormInjectionScanner;
use crate::core::scanners::crawl_integration::{ParamType, ScanParam, ScanTarget, TargetType};
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Finding, ScanResults};
use crate::shared::tool_checker;
use futures::future::join_all;
use std::time::Instant;

/// Main scan engine that orchestrates all scanners concurrently
pub struct ScanEngine {
	config: JackSparrowConfig,
}

impl ScanEngine {
	pub fn new(config: JackSparrowConfig) -> Self {
		Self { config }
	}

	/// Verify that required external tools are available before scanning.
	///
	/// Returns a list of warnings (missing tools that some scanners need).
	/// Does NOT fail — scanners handle missing tools gracefully.
	pub fn verify_tools(&self) -> Vec<String> {
		let mut warnings = Vec::new();

		let tools_to_check: Vec<(&str, &str)> = vec![
			("sqlmap", &self.config.tools.sqlmap_path),
			("dalfox", &self.config.tools.dalfox_path),
			("ssrfmap", &self.config.tools.ssrfmap_path),
		];

		for (name, path) in tools_to_check {
			if let Ok(false) = tool_checker::check_tool(name, path) {
				warnings.push(format!(
					"WARNING: {} not found at '{}'. {} scanner will be skipped.",
					name,
					path,
					match name {
						"sqlmap" => "SQL Injection",
						"dalfox" => "XSS",
						"ssrfmap" => "SSRF",
						_ => name,
					}
				));
			}
		}

		warnings
	}

	/// Run a scan against a target — scanners execute concurrently.
	///
	/// Automatically verifies tools before scanning and warns about missing ones.
	pub async fn scan(
		&mut self,
		target: &str,
		checks: &str,
		context: &ScanContext,
		concurrency: usize,
		timeout: u64,
	) -> Result<ScanResults, JackSparrowError> {
		// Pre-scan: validate target URL
		if !target.starts_with("http://") && !target.starts_with("https://") {
			return Err(JackSparrowError::InvalidTarget {
				url: target.to_string(),
			});
		}

		// Pre-scan: verify tools
		let warnings = self.verify_tools();
		for w in &warnings {
			eprintln!("{}", w);
		}

		// Pre-scan: warn about Stored XSS without crawl context
		if checks.contains("xss") && !checks.contains("xss-reflected") {
			eprintln!(
				"NOTE: Stored XSS and DOM XSS require crawl context. \
				 Use 'xss-reflected' for basic XSS or provide a session file."
			);
		}

		let start = Instant::now();
		let scanner_types = self.parse_checks(checks)?;

		// Build concurrent scanner futures
		let futures: Vec<_> = scanner_types
			.iter()
			.map(|scanner_type| {
				let config = self.config.clone();
				let target = target.to_string();
				let context = context.clone();
				let st = *scanner_type;

				async move { run_scanner(st, &target, &config, &context).await }
			})
			.collect();

		// Execute all scanners concurrently with timeout
		let scan_fut = async {
			if concurrency <= 1 || futures.len() <= 1 {
				let mut all_findings = Vec::new();
				for f in futures {
					all_findings.extend(f.await?);
				}
				Ok::<_, JackSparrowError>(all_findings)
			} else {
				let results = join_all(futures).await;
				let mut all_findings = Vec::new();
				for result in results {
					all_findings.extend(result?);
				}
				Ok::<_, JackSparrowError>(all_findings)
			}
		};

		let findings = tokio::time::timeout(tokio::time::Duration::from_secs(timeout), scan_fut)
			.await
			.map_err(|_| JackSparrowError::Timeout {
				timeout_ms: timeout * 1000,
			})??;

		let mut results = ScanResults::new(target.to_string());
		results.findings = findings;
		results.tools_used = scanner_types.iter().map(|st| st.to_string()).collect();
		results.scan_duration_ms = start.elapsed().as_millis() as u64;

		Ok(results)
	}

	/// Parse check string into scanner types
	fn parse_checks(&self, checks: &str) -> Result<Vec<ScannerType>, JackSparrowError> {
		if checks == "all" {
			return Ok(vec![
				ScannerType::SqlInjection,
				ScannerType::Xss,
				ScannerType::XssStored,
				ScannerType::XssDom,
				ScannerType::Idor,
				ScannerType::Ssrf,
				ScannerType::SupplyChain,
				ScannerType::SecurityHeaders,
				ScannerType::TechFingerprint,
				ScannerType::Secrets,
				ScannerType::SubdomainEnum,
				ScannerType::WafDetection,
				ScannerType::JwtAnalysis,
				ScannerType::GraphQLIntrospection,
				ScannerType::ApiSecurity,
				ScannerType::CloudMetadata,
				ScannerType::Xxe,
				ScannerType::Ssti,
				ScannerType::FormInjection,
				ScannerType::Csrf,
				ScannerType::FileUpload,
			]);
		}

		let mut types = Vec::new();
		for check in checks.split(',') {
			let check = check.trim().to_lowercase();
			match check.as_str() {
				"sqli" => types.push(ScannerType::SqlInjection),
				"xss" => {
					types.push(ScannerType::Xss);
					types.push(ScannerType::XssStored);
					types.push(ScannerType::XssDom);
				}
				"xss-reflected" | "reflected-xss" => types.push(ScannerType::Xss),
				"xss-stored" | "stored-xss" => types.push(ScannerType::XssStored),
				"xss-dom" | "dom-xss" => types.push(ScannerType::XssDom),
				"idor" => types.push(ScannerType::Idor),
				"ssrf" => types.push(ScannerType::Ssrf),
				"supply-chain" | "supplychain" => types.push(ScannerType::SupplyChain),
				"headers" | "security-headers" | "securityheaders" => {
					types.push(ScannerType::SecurityHeaders)
				}
				"tech" | "fingerprint" | "tech-fingerprint" => types.push(ScannerType::TechFingerprint),
				"secrets" | "secret" => types.push(ScannerType::Secrets),
				"subdomains" | "subdomain" | "enum" => types.push(ScannerType::SubdomainEnum),
				"waf" | "firewall" => types.push(ScannerType::WafDetection),
				"jwt" | "jwt-analysis" => types.push(ScannerType::JwtAnalysis),
			"graphql" | "gql" | "introspection" => types.push(ScannerType::GraphQLIntrospection),
			"api" | "api-security" | "rest" => types.push(ScannerType::ApiSecurity),
			"cloud-metadata" | "cloud" | "imds" => types.push(ScannerType::CloudMetadata),
			"xxe" | "xml-external" => types.push(ScannerType::Xxe),
			"ssti" | "template-injection" => types.push(ScannerType::Ssti),
			"form" | "form-injection" | "post" => types.push(ScannerType::FormInjection),
			"csrf" | "cross-site-request-forgery" => types.push(ScannerType::Csrf),
			"upload" | "file-upload" => types.push(ScannerType::FileUpload),
			_ => {
				return Err(JackSparrowError::ConfigError {
					message: format!(
						"Unknown check: '{}'. Valid: sqli, xss, xss-reflected, xss-stored, xss-dom, idor, ssrf, supply-chain, headers, tech, secrets, subdomains, waf, jwt, graphql, api, cloud-metadata, xxe, ssti, form, csrf, upload, all",
						check
					),
				});
			}
		}
	}

	if types.is_empty() {
		return Err(JackSparrowError::ConfigError {
			message: "No valid checks specified".to_string(),
		});
	}

	Ok(types)
}

	/// Run a scan using crawl results to discover targets automatically.
	///
	/// Scanners execute concurrently against crawl-discovered targets.
	pub async fn scan_with_crawl(
		&mut self,
		crawl_results: &CrawlResults,
		checks: &str,
		context: &ScanContext,
		concurrency: usize,
		timeout: u64,
	) -> Result<ScanResults, JackSparrowError> {
		let start = Instant::now();
		let scanner_types = self.parse_checks(checks)?;
		let all_targets = CrawlTargetExtractor::extract_targets(crawl_results);

		// Build concurrent futures for each scanner type
		let futures: Vec<_> = scanner_types
			.iter()
			.map(|scanner_type| {
				let config = self.config.clone();
				let context = context.clone();
				let crawl = crawl_results.clone();
				let targets = all_targets.clone();
				let st = *scanner_type;

				async move {
					let scanner_targets = CrawlTargetExtractor::targets_for_scanner(&targets, st);
					match st {
						ScannerType::XssStored => {
							let scanner = StoredXssScanner::new(&config);
							scanner.scan_with_crawl(&crawl, &context).await
						}
						ScannerType::XssDom => {
							let scanner = DomXssScanner::new(&config);
							scanner.scan_with_crawl(&crawl, &context).await
						}
						ScannerType::SecurityHeaders => {
							let scanner = SecurityHeadersScanner::new(&config);
							scanner.scan(crawl.target.as_str(), &config, &context).await
						}
						ScannerType::TechFingerprint => {
							let scanner = TechFingerprintScanner::new(&config);
							scanner.scan(crawl.target.as_str(), &config, &context).await
						}
						_ => {
							// Scanners that work per-URL
							let urls = CrawlTargetExtractor::targets_to_urls(&scanner_targets);
							let mut findings = Vec::new();
							for url in &urls {
								let f = run_scanner(st, url, &config, &context).await?;
								findings.extend(f);
							}
							Ok(findings)
						}
					}
				}
			})
			.collect();

		// Execute all scanners concurrently
		let scan_fut = async {
			if concurrency <= 1 || futures.len() <= 1 {
				let mut all_findings = Vec::new();
				for f in futures {
					all_findings.extend(f.await?);
				}
				Ok::<_, JackSparrowError>(all_findings)
			} else {
				let results = join_all(futures).await;
				let mut all_findings = Vec::new();
				for result in results {
					all_findings.extend(result?);
				}
				Ok::<_, JackSparrowError>(all_findings)
			}
		};

		let findings = tokio::time::timeout(tokio::time::Duration::from_secs(timeout), scan_fut)
			.await
			.map_err(|_| JackSparrowError::Timeout {
				timeout_ms: timeout * 1000,
			})??;

		let mut results = ScanResults::new(crawl_results.target.to_string());
		results.findings = findings;
		results.tools_used = scanner_types.iter().map(|st| st.to_string()).collect();
		results.scan_duration_ms = start.elapsed().as_millis() as u64;

		Ok(results)
	}
}

/// Discover forms from a target URL by fetching HTML and parsing <form> tags.
/// Returns ScanTarget objects suitable for FormInjection and CSRF scanners.
async fn discover_form_targets(
	target_url: &str,
	context: &ScanContext,
) -> Vec<ScanTarget> {
	let mut default_headers = reqwest::header::HeaderMap::new();

	// Apply cookies from context
	if let Some(ref cookies) = context.cookies {
		if let Ok(cookie_value) = reqwest::header::HeaderValue::from_str(cookies) {
			default_headers.insert(reqwest::header::COOKIE, cookie_value);
		}
	}

	// Apply custom headers from context
	for (key, value) in &context.headers {
		if let (Ok(k), Ok(v)) = (
			reqwest::header::HeaderName::from_bytes(key.as_bytes()),
			reqwest::header::HeaderValue::from_str(value),
		) {
			default_headers.insert(k, v);
		}
	}

	let client = match reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(10))
		.danger_accept_invalid_certs(true)
		.default_headers(default_headers)
		.build()
	{
		Ok(c) => c,
		Err(_) => return Vec::new(),
	};

	let resp = match client.get(target_url).send().await {
		Ok(r) => r,
		Err(_) => return Vec::new(),
	};

	let html = match resp.text().await {
		Ok(t) => t,
		Err(_) => return Vec::new(),
	};

	let mut targets = Vec::new();

	// Parse all <form> tags from the HTML
	let document = scraper::Html::parse_document(&html);
	let form_selector = scraper::Selector::parse("form").unwrap();

	for form_el in document.select(&form_selector) {
		let action = form_el
			.attr("action")
			.unwrap_or("/")
			.to_string();

		let method_str = form_el
			.attr("method")
			.unwrap_or("GET")
			.to_uppercase();

		let method = crate::core::crawler::parser::Method::from_str(&method_str);

		// Resolve relative action URLs
		// Action "#" or "" means submit to current page
		let form_url_str = if action == "#" || action.is_empty() || action == "." {
			// Strip fragment from target URL — use only the page URL
			target_url.split('#').next().unwrap_or(target_url).to_string()
		} else if action.starts_with("http") {
			action.split('#').next().unwrap_or(&action).to_string()
		} else if action.starts_with('/') {
			if let Ok(parsed) = url::Url::parse(target_url) {
				format!("{}://{}{}", parsed.scheme(), parsed.authority(), action)
			} else {
				format!("{}{}", target_url.trim_end_matches('/'), action)
			}
		} else {
			format!("{}/{}", target_url.trim_end_matches('/'), action)
		};

		let form_url = match url::Url::parse(&form_url_str) {
			Ok(u) => u,
			Err(_) => continue,
		};

		// Extract form fields
		let input_selector = scraper::Selector::parse("input, textarea, select").unwrap();
		let mut params = Vec::new();

		for input_el in form_el.select(&input_selector) {
			let name = match input_el.attr("name") {
				Some(n) => n.to_string(),
				None => continue,
			};

			let input_type = input_el.attr("type").unwrap_or("text");
			let value = input_el.attr("value").map(|v| v.to_string());
			let is_hidden = input_type == "hidden";

			let param_type = match method_str.as_str() {
				"POST" => ParamType::Body,
				_ => ParamType::Query,
			};

			params.push(ScanParam {
				name,
				param_type,
				value,
				is_hidden,
			});
		}

		if !params.is_empty() {
			targets.push(ScanTarget {
				url: form_url,
				method,
				target_type: TargetType::Form,
				params,
				source_url: Some(target_url.to_string()),
				depth: 0,
			});
		}
	}

	targets
}

/// Run a single scanner against a target — used by concurrent futures
async fn run_scanner(
	scanner_type: ScannerType,
	target: &str,
	config: &JackSparrowConfig,
	context: &ScanContext,
) -> Result<Vec<Finding>, JackSparrowError> {
	match scanner_type {
		ScannerType::SqlInjection => {
			// Use native scanner (no external tools needed)
			let scanner = NativeSqlScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Xss => {
			let scanner = XssScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::XssStored => {
			// Stored XSS requires crawl context — skipped in basic scan mode
			Ok(Vec::new())
		}
		ScannerType::XssDom => {
			let scanner = DomXssScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Idor => {
			let scanner = IdorScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Ssrf => {
			// Use native scanner (no external tools needed)
			let scanner = NativeSsrfScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::SupplyChain => {
			let scanner = SupplyChainScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::SecurityHeaders => {
			let scanner = SecurityHeadersScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::TechFingerprint => {
			let scanner = TechFingerprintScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Secrets => {
			let scanner = SecretsScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::SubdomainEnum => {
			let scanner = SubdomainEnumScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::WafDetection => {
			let scanner = WafDetectionScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::JwtAnalysis => {
			let scanner = JwtAnalysisScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::GraphQLIntrospection => {
			let scanner = GraphQLIntrospectionScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::ApiSecurity => {
			let scanner = ApiSecurityScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::CloudMetadata => {
			let scanner = CloudMetadataScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Xxe => {
			let scanner = XxeScanner::new(config);
			scanner.scan(target, config, context).await
		}
		ScannerType::Ssti => {
			let scanner = SstiScanner::new(config);
			scanner.scan(target, config, context).await
		}
	ScannerType::FormInjection => {
		// Auto-discover forms from target URL, then run injection tests
		let targets = discover_form_targets(target, context).await;
		if targets.is_empty() {
			Ok(Vec::new())
		} else {
			let scanner = FormInjectionScanner::new(config);
			scanner.scan_with_targets(&targets.iter().collect::<Vec<_>>(), context).await
		}
		}
		ScannerType::Csrf => {
			// Auto-discover forms from target URL, then run CSRF tests
			let targets = discover_form_targets(target, context).await;
			if targets.is_empty() {
				Ok(Vec::new())
			} else {
				let scanner = CsrfScanner::new(config);
				scanner.scan_with_targets(&targets.iter().collect::<Vec<_>>(), context).await
			}
		}
		ScannerType::FileUpload => {
			let scanner = FileUploadScanner::new(config);
			scanner.scan(target, config, context).await
		}
	}
}

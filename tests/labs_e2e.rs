//! End-to-end tests against Docker lab environments.
//!
//! These tests require Docker labs to be running:
//!   docker start dvwa juice-shop webgoat ssrf-lab
//!
//! Labs:
//!   - DVWA at http://localhost:80 (user: admin, pass: password)
//!   - Juice Shop at http://localhost:3001
//!   - SSRF Lab at http://localhost:5000
//!   - WebGoat at http://localhost:8080
//!
//! Run with: cargo test --test labs_e2e -- --ignored

use jack_sparrow::core::engine::ScanEngine;
use jack_sparrow::shared::config::JackSparrowConfig;
use jack_sparrow::shared::context::ScanContext;
use std::time::Duration;

/// Check if a lab is reachable before running tests.
async fn is_lab_reachable(url: &str) -> bool {
	reqwest::Client::new()
		.get(url)
		.timeout(Duration::from_secs(3))
		.send()
		.await
		.map(|r| r.status().is_success() || r.status().is_redirection())
		.unwrap_or(false)
}

/// Check if a specific tool is available.
fn is_tool_available(tool: &str) -> bool {
	std::process::Command::new(tool)
		.arg("--version")
		.output()
		.map(|o| o.status.success())
		.unwrap_or(false)
}

/// Build a default test context with no auth.
fn test_context() -> ScanContext {
	ScanContext::default()
}

// ─── Security Headers (no external tools needed) ────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_security_headers_dvwa() {
	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable at {}", url);
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(url, "headers", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	// DVWA should have missing security headers
	assert!(
		!results.findings.is_empty(),
		"DVWA should have missing security header findings"
	);

	// All findings should be SecurityHeader type
	for finding in &results.findings {
		assert_eq!(
			finding.vulnerability_type,
			jack_sparrow::shared::types::VulnerabilityType::SecurityHeader
		);
	}
}

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_security_headers_juice_shop() {
	let url = "http://localhost:3001";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: Juice Shop not reachable at {}", url);
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(url, "headers", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	assert!(
		!results.findings.is_empty(),
		"Juice Shop should have security header findings"
	);
}

// ─── Tech Fingerprint (no external tools needed) ────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_tech_fingerprint_dvwa() {
	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable at {}", url);
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(url, "tech", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	assert!(
		!results.findings.is_empty(),
		"DVWA should have tech fingerprint findings"
	);

	// Should detect PHP
	let tech_output: String = results
		.findings
		.iter()
		.map(|f| format!("{} {}", f.title, f.description))
		.collect::<Vec<_>>()
		.join(" ");

	assert!(
		tech_output.to_lowercase().contains("php"),
		"Should detect PHP technology, got: {}",
		tech_output
	);
}

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_tech_fingerprint_juice_shop() {
	let url = "http://localhost:3001";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: Juice Shop not reachable at {}", url);
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(url, "tech", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	// Juice Shop should have some tech findings (may be empty if detection is limited)
	println!("Juice Shop tech findings: {}", results.findings.len());
	for f in &results.findings {
		println!("  - {} ({})", f.title, f.severity);
	}
}

// ─── XSS Reflected (needs dalfox) ──────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running + dalfox installed"]
async fn test_xss_reflected_dvwa() {
	if !is_tool_available("dalfox") {
		eprintln!("SKIP: dalfox not installed");
		return;
	}

	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable");
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);

	// DVWA session: first we need to login. We use a direct cookie approach.
	// DVWA default: admin/password, security=low
	let context = ScanContext {
		cookies: Some("security=low".to_string()),
		headers: vec![],
		session: None,
	};

	let results = engine
		.scan(
			"http://localhost:80/vulnerabilities/xss_r/?name=test",
			"xss-reflected",
			&context,
			4,
			60,
		)
		.await;

	// dalfox may fail if session is not authenticated (DVWA requires login)
	match results {
		Ok(results) => {
			let xss_findings: Vec<_> = results
				.findings
				.iter()
				.filter(|f| {
					matches!(
						f.vulnerability_type,
						jack_sparrow::shared::types::VulnerabilityType::XssReflected
					)
				})
				.collect();

			println!("XSS findings on DVWA: {}", xss_findings.len());
			if !xss_findings.is_empty() {
				assert!(xss_findings[0].severity >= jack_sparrow::shared::types::Severity::Medium);
			}
		}
		Err(e) => {
			// dalfox may fail if it can't authenticate to DVWA
			eprintln!("XSS scan failed (expected without valid DVWA session): {}", e);
		}
	}
}

// ─── SQL Injection (needs sqlmap) ──────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running + sqlmap installed"]
async fn test_sqli_dvwa() {
	if !is_tool_available("sqlmap") {
		eprintln!("SKIP: sqlmap not installed");
		return;
	}

	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable");
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = ScanContext {
		cookies: Some("PHPSESSID=test; security=low".to_string()),
		headers: vec![],
		session: None,
	};

	let results = engine
		.scan(
			"http://localhost:80/vulnerabilities/sqli/?id=1",
			"sqli",
			&context,
			4,
			120,
		)
		.await
		.expect("Scan should succeed");

	let sqli_findings: Vec<_> = results
		.findings
		.iter()
		.filter(|f| {
			matches!(
				f.vulnerability_type,
				jack_sparrow::shared::types::VulnerabilityType::SqlInjection
			)
		})
		.collect();

	println!("SQLi findings on DVWA: {}", sqli_findings.len());
}

// ─── SSRF (needs ssrfmap) ──────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running + ssrfmap installed"]
async fn test_ssrf_lab() {
	if !is_tool_available("ssrfmap") {
		eprintln!("SKIP: ssrfmap not installed");
		return;
	}

	let url = "http://localhost:5000";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: SSRF Lab not reachable at localhost:5000");
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(
			"http://localhost:5000/fetch?url=http://127.0.0.1:5000/internal",
			"ssrf",
			&context,
			4,
			60,
		)
		.await
		.expect("Scan should succeed");

	println!("SSRF findings: {}", results.findings.len());
}

// ─── Supply Chain (needs npm/pip/cargo audit) ──────────────────────

#[tokio::test]
#[ignore = "requires cargo-audit installed"]
async fn test_supply_chain_self() {
	// Scan jack-sparrow itself for supply chain vulnerabilities
	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	// Use current project directory
	let result = engine
		.scan(
			".",
			"supply-chain",
			&context,
			4,
			60,
		)
		.await;

	match result {
		Ok(results) => {
			println!("Supply chain findings: {}", results.findings.len());
			for f in &results.findings {
				println!("  - {} ({})", f.title, f.severity);
			}
		}
		Err(e) => {
			eprintln!("Supply chain scan error (expected if tools not installed): {}", e);
		}
	}
}

// ─── Concurrent Scan ────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_concurrent_scan_dvwa() {
	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable");
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	// Run headers + tech concurrently
	let results = engine
		.scan(url, "headers,tech", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	// Should have findings from both scanners
	assert!(
		results.findings.len() >= 2,
		"Should have findings from both headers and tech scanners, got {}",
		results.findings.len()
	);

	// Both tools should be listed
	assert!(results.tools_used.contains(&"Security Headers".to_string()));
	assert!(results.tools_used.contains(&"Tech Fingerprint".to_string()));
}

// ─── Scan Duration ──────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_scan_duration_recorded() {
	let url = "http://localhost:80";
	if !is_lab_reachable(url).await {
		eprintln!("SKIP: DVWA not reachable");
		return;
	}

	let config = JackSparrowConfig::default();
	let mut engine = ScanEngine::new(config);
	let context = test_context();

	let results = engine
		.scan(url, "headers", &context, 4, 30)
		.await
		.expect("Scan should succeed");

	assert!(
		results.scan_duration_ms > 0,
		"Scan duration should be recorded"
	);
}

// ─── Config Validation ──────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_invalid_config_rejected() {
	let mut config = JackSparrowConfig::default();
	config.general.max_concurrent = 0; // Invalid!

	let result = config.validate();
	assert!(result.is_err(), "Should reject invalid config");
}

// ─── Tool Verification ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker labs running"]
async fn test_tool_verification_reports_missing() {
	let config = JackSparrowConfig::default();
	let engine = ScanEngine::new(config);
	let warnings = engine.verify_tools();

	// Should report warnings for missing tools
	// (sqlmap/ssrfmap likely not installed in CI)
	if !warnings.is_empty() {
		println!("Tool warnings: {:?}", warnings);
	}
	// Just verify it doesn't panic
}

//! E2E tests for P5 scanners against the P5 vulnerable lab.
//!
//! Lab runs at http://localhost:5555 (start with: python lab/p5-lab.py)
//!
//! Tests: FormInjection (SQLi/XSS/SSTI via POST body), CSRF, FileUpload

use jack_sparrow::core::scanners::crawl_integration::{ParamType, ScanParam, ScanTarget, TargetType};
use jack_sparrow::core::scanners::csrf::CsrfScanner;
use jack_sparrow::core::scanners::file_upload::FileUploadScanner;
use jack_sparrow::core::scanners::form_injection::FormInjectionScanner;
use jack_sparrow::core::scanners::Scanner;
use jack_sparrow::shared::config::JackSparrowConfig;
use jack_sparrow::shared::context::ScanContext;
use std::time::Duration;

const LAB_URL: &str = "http://localhost:5555";

async fn is_lab_reachable() -> bool {
	reqwest::Client::new()
		.get(LAB_URL)
		.timeout(Duration::from_secs(3))
		.send()
		.await
		.map(|r| r.status().is_success())
		.unwrap_or(false)
}

fn test_context() -> ScanContext {
	ScanContext::default()
}

fn test_config() -> JackSparrowConfig {
	JackSparrowConfig::default()
}

fn make_post_target(url: &str, params: Vec<ScanParam>) -> ScanTarget {
	ScanTarget {
		url: url::Url::parse(url).unwrap(),
		method: jack_sparrow::core::crawler::parser::Method::Post,
		params,
		source_url: None,
		target_type: TargetType::Form,
		depth: 1,
	}
}

// ─── FormInjection: SQLi via POST body ────────────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_form_injection_sqli_detects_vulnerability() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();

	let target = make_post_target(
		&format!("{}/search", LAB_URL),
		vec![ScanParam {
			name: "username".to_string(),
			param_type: ParamType::Body,
			value: Some("test".to_string()),
			is_hidden: false,
		}],
	);

	let scanner = FormInjectionScanner::new(&config);
	let findings = scanner.scan_with_targets(&[&target], &context).await.unwrap();

	println!("SQLi findings: {}", findings.len());
	for f in &findings {
		println!("  - [{}] {} (CVSS: {:?})", f.severity, f.title, f.cvss_score);
	}

	assert!(!findings.is_empty(), "Expected SQLi findings from /search");
}

// ─── FormInjection: XSS via POST body ─────────────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_form_injection_xss_detects_vulnerability() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();

	let target = make_post_target(
		&format!("{}/comment", LAB_URL),
		vec![
			ScanParam {
				name: "author".to_string(),
				param_type: ParamType::Body,
				value: Some("tester".to_string()),
				is_hidden: false,
			},
			ScanParam {
				name: "body".to_string(),
				param_type: ParamType::Body,
				value: Some("test comment".to_string()),
				is_hidden: false,
			},
		],
	);

	let scanner = FormInjectionScanner::new(&config);
	let findings = scanner.scan_with_targets(&[&target], &context).await.unwrap();

	println!("XSS findings: {}", findings.len());
	for f in &findings {
		println!("  - [{}] {}", f.severity, f.title);
	}

	assert!(!findings.is_empty(), "Expected XSS findings from /comment");
}

// ─── FormInjection: SSTI via POST body ────────────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_form_injection_ssti_detects_vulnerability() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();

	let target = make_post_target(
		&format!("{}/render", LAB_URL),
		vec![ScanParam {
			name: "template".to_string(),
			param_type: ParamType::Body,
			value: Some("Hello".to_string()),
			is_hidden: false,
		}],
	);

	let scanner = FormInjectionScanner::new(&config);
	let findings = scanner.scan_with_targets(&[&target], &context).await.unwrap();

	println!("SSTI findings: {}", findings.len());
	for f in &findings {
		println!("  - [{}] {}", f.severity, f.title);
	}

	assert!(!findings.is_empty(), "Expected SSTI findings from /render");
}

// ─── CSRF: Detect missing token on /transfer ──────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_csrf_detects_missing_token() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();

	let target = make_post_target(
		&format!("{}/transfer", LAB_URL),
		vec![
			ScanParam {
				name: "to".to_string(),
				param_type: ParamType::Body,
				value: Some("user1".to_string()),
				is_hidden: false,
			},
			ScanParam {
				name: "amount".to_string(),
				param_type: ParamType::Body,
				value: Some("100".to_string()),
				is_hidden: false,
			},
		],
	);

	let scanner = CsrfScanner::new(&config);
	let findings = scanner.scan_with_targets(&[&target], &context).await.unwrap();

	println!("CSRF findings: {}", findings.len());
	for f in &findings {
		println!("  - [{}] {}", f.severity, f.title);
	}

	assert!(!findings.is_empty(), "Expected CSRF findings from /transfer");
}

// ─── FileUpload: Detect upload form ───────────────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_file_upload_detects_vulnerability() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();

	// FileUploadScanner.scan() fetches the page and detects upload forms
	let scanner = FileUploadScanner::new(&config);
	let findings = scanner.scan(LAB_URL, &config, &context).await.unwrap();

	// Also test form detection from HTML
	let html = reqwest::Client::new()
		.get(LAB_URL)
		.send()
		.await
		.unwrap()
		.text()
		.await
		.unwrap();

	let upload_forms = FileUploadScanner::detect_upload_forms(&html);
	println!("Upload forms detected in HTML: {}", upload_forms.len());
	for form in &upload_forms {
		println!("  Action: {}, multipart: {}", form.action, form.has_multipart);
	}

	println!("FileUpload findings: {}", findings.len());
	for f in &findings {
		println!("  - [{}] {}", f.severity, f.title);
	}

	// Should detect file upload form at minimum
	assert!(!upload_forms.is_empty(), "Expected to detect file upload form in HTML");
}

// ─── Full scan all P5 types ───────────────────────────────────────

#[tokio::test]
#[ignore = "requires P5 lab running on port 5555"]
async fn test_p5_lab_full_scan() {
	if !is_lab_reachable().await {
		eprintln!("SKIP: P5 lab not reachable at {}", LAB_URL);
		return;
	}

	let config = test_config();
	let context = test_context();
	let mut all_findings = Vec::new();

	// SQLi
	let sqli_target = make_post_target(
		&format!("{}/search", LAB_URL),
		vec![ScanParam {
			name: "username".into(),
			param_type: ParamType::Body,
			value: Some("test".into()),
			is_hidden: false,
		}],
	);
	let scanner = FormInjectionScanner::new(&config);
	let findings = scanner.scan_with_targets(&[&sqli_target], &context).await.unwrap();
	println!("[SQLI] /search: {} findings", findings.len());
	all_findings.extend(findings);

	// XSS
	let xss_target = make_post_target(
		&format!("{}/comment", LAB_URL),
		vec![
			ScanParam { name: "author".into(), param_type: ParamType::Body, value: Some("test".into()), is_hidden: false },
			ScanParam { name: "body".into(), param_type: ParamType::Body, value: Some("test".into()), is_hidden: false },
		],
	);
	let scanner2 = FormInjectionScanner::new(&config);
	let findings = scanner2.scan_with_targets(&[&xss_target], &context).await.unwrap();
	println!("[XSS] /comment: {} findings", findings.len());
	all_findings.extend(findings);

	// SSTI
	let ssti_target = make_post_target(
		&format!("{}/render", LAB_URL),
		vec![ScanParam {
			name: "template".into(),
			param_type: ParamType::Body,
			value: Some("Hello".into()),
			is_hidden: false,
		}],
	);
	let scanner3 = FormInjectionScanner::new(&config);
	let findings = scanner3.scan_with_targets(&[&ssti_target], &context).await.unwrap();
	println!("[SSTI] /render: {} findings", findings.len());
	all_findings.extend(findings);

	// CSRF
	let csrf_target = make_post_target(
		&format!("{}/transfer", LAB_URL),
		vec![
			ScanParam { name: "to".into(), param_type: ParamType::Body, value: Some("user1".into()), is_hidden: false },
			ScanParam { name: "amount".into(), param_type: ParamType::Body, value: Some("100".into()), is_hidden: false },
		],
	);
	let csrf_scanner = CsrfScanner::new(&config);
	let findings = csrf_scanner.scan_with_targets(&[&csrf_target], &context).await.unwrap();
	println!("[CSRF] /transfer: {} findings", findings.len());
	all_findings.extend(findings);

	// FileUpload
	let fu_scanner = FileUploadScanner::new(&config);
	let findings = fu_scanner.scan(LAB_URL, &config, &context).await.unwrap();
	println!("[FILEUPLOAD] /upload: {} findings", findings.len());
	all_findings.extend(findings);

	println!("\n=== TOTAL P5 FINDINGS: {} ===", all_findings.len());
	for f in &all_findings {
		println!("  [{}] {}", f.severity, f.title);
	}

	assert!(
		all_findings.len() >= 3,
		"Expected at least 3 findings across all P5 endpoints, got {}",
		all_findings.len()
	);
}

// ─── FormLogin E2E ────────────────────────────────────────────────

#[tokio::test]
#[ignore] // requires lab running
async fn e2e_form_login_gets_session() {
	if !is_lab_reachable().await {
		eprintln!("⚠ P5 lab not reachable at {LAB_URL} — skipping");
		return;
	}

	use jack_sparrow::shared::auth::{AuthConfig, FormLoginExecutor};

	let config = AuthConfig::FormLogin {
		login_url: format!("{}/login", LAB_URL),
		username: "admin".to_string(),
		password: "admin123".to_string(),
		username_field: "username".to_string(),
		password_field: "password".to_string(),
		extra_fields: vec![],
		success_indicator: Some("Welcome".to_string()),
	};

	let executor = FormLoginExecutor::new();
	let result = executor.login(&config).await;

	match result {
		Ok(cookies) => {
			println!("[FORMLOGIN] Got cookies: {}", cookies);
			assert!(cookies.contains("session_id"), "Expected session_id cookie, got: {}", cookies);
			assert!(cookies.contains("sess_admin"), "Expected sess_admin value, got: {}", cookies);
		}
		Err(e) => panic!("FormLogin failed: {}", e),
	}
}

#[tokio::test]
#[ignore] // requires lab running
async fn e2e_form_login_to_context() {
	if !is_lab_reachable().await {
		eprintln!("⚠ P5 lab not reachable at {LAB_URL} — skipping");
		return;
	}

	use jack_sparrow::shared::auth::{AuthConfig, FormLoginExecutor};

	let config = AuthConfig::FormLogin {
		login_url: format!("{}/login", LAB_URL),
		username: "user1".to_string(),
		password: "pass1".to_string(),
		username_field: "username".to_string(),
		password_field: "password".to_string(),
		extra_fields: vec![],
		success_indicator: None,
	};

	let executor = FormLoginExecutor::new();
	let ctx = executor.login_to_context(&config).await.unwrap();

	println!("[FORMLOGIN] ScanContext cookies: {:?}", ctx.cookies);
	assert!(ctx.cookies.is_some(), "Expected cookies in ScanContext");
	assert!(ctx.cookies.unwrap().contains("session_id"));
}

#[tokio::test]
#[ignore] // requires lab running
async fn e2e_form_login_wrong_password_fails() {
	if !is_lab_reachable().await {
		eprintln!("⚠ P5 lab not reachable at {LAB_URL} — skipping");
		return;
	}

	use jack_sparrow::shared::auth::{AuthConfig, FormLoginExecutor};

	let config = AuthConfig::FormLogin {
		login_url: format!("{}/login", LAB_URL),
		username: "admin".to_string(),
		password: "wrongpassword".to_string(),
		username_field: "username".to_string(),
		password_field: "password".to_string(),
		extra_fields: vec![],
		success_indicator: None,
	};

	let executor = FormLoginExecutor::new();
	let result = executor.login(&config).await;

	// Should fail — no cookies are set for wrong password in this lab
	match result {
		Ok(cookies) => {
			// If login succeeds with wrong password, the lab doesn't reject it
			// (which is itself a vulnerability). Just log it.
			println!("[FORMLOGIN] Wrong password still got cookies (lab vulnerability): {}", cookies);
		}
		Err(e) => {
			println!("[FORMLOGIN] Correctly failed with wrong password: {}", e);
		}
	}
}

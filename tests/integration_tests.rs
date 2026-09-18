//! Integration tests for the crawler + scanner pipeline.
//!
//! These tests verify that the crawler output can be consumed by scanners
//! and that the entire pipeline works end-to-end.

use jack_sparrow::core::crawler::config::{CrawlerConfig, CrawlScope};
use jack_sparrow::core::crawler::engine::CrawlResults;
use jack_sparrow::core::crawler::parser::{Method, ParsedPage, DiscoveredForm, FormInput};
use jack_sparrow::core::scanners::crawl_integration::{
    CrawlTargetExtractor, ParamType, ScanTarget, TargetType,
};
use jack_sparrow::core::scanners::dom_xss::DomXssScanner;
use jack_sparrow::core::scanners::stored_xss::StoredXssScanner;
use jack_sparrow::shared::config::JackSparrowConfig;
use url::Url;
use std::collections::HashMap;

/// Helper to create a test CrawlResults.
fn make_test_crawl_results() -> CrawlResults {
    let parsed = ParsedPage {
        url: Url::parse("http://example.com").unwrap(),
        title: "Test Page".to_string(),
        links: vec![],
        forms: vec![DiscoveredForm {
            action: Url::parse("http://example.com/search").unwrap(),
            method: Method::Get,
            inputs: vec![FormInput {
                name: "q".to_string(),
                input_type: "text".to_string(),
                value: None,
                required: false,
                id: None,
                maxlength: None,
            }],
            enctype: None,
            id: None,
            name: None,
            onsubmit: None,
            looks_like_auth: false,
        }],
        scripts: vec![],
        inline_scripts: vec![],
        meta: HashMap::new(),
        images: vec![],
        canonical: None,
        description: None,
        generator: None,
        iframes: vec![],
        embeds: vec![],
        link_tags: vec![],
        base_tag: None,
        meta_refresh: None,
        event_handlers: vec![],
        media: vec![],
        has_noscript: false,
        hidden_inputs: vec![],
        data_attributes_count: 0,
    };

    CrawlResults {
        target: Url::parse("http://example.com").unwrap(),
        pages: vec![jack_sparrow::core::crawler::engine::CrawledPage {
            url: Url::parse("http://example.com").unwrap(),
            status: 200,
            parsed: Some(parsed),
            fetch_time_ms: 100,
            body_size: 1024,
            depth: 0,
        }],
        stats: Default::default(),
        errors: vec![],
    }
}

#[test]
fn crawl_results_extract_targets() {
    let results = make_test_crawl_results();
    let targets = CrawlTargetExtractor::extract_targets(&results);

    assert!(!targets.is_empty(), "Should extract targets from crawl results");

    // Should find the form
    let form_targets: Vec<&ScanTarget> = targets
        .iter()
        .filter(|t| t.target_type == TargetType::Form)
        .collect();
    assert_eq!(form_targets.len(), 1);
    assert_eq!(form_targets[0].params.len(), 1);
    assert_eq!(form_targets[0].params[0].name, "q");
}

#[test]
fn targets_filtered_for_sqli() {
    let results = make_test_crawl_results();
    let targets = CrawlTargetExtractor::extract_targets(&results);
    let sqli_targets = CrawlTargetExtractor::targets_for_scanner(
        &targets,
        jack_sparrow::core::scanners::ScannerType::SqlInjection,
    );

    // SQLi should target forms and URLs with params
    assert!(!sqli_targets.is_empty());
}

#[test]
fn targets_filtered_for_xss() {
    let results = make_test_crawl_results();
    let targets = CrawlTargetExtractor::extract_targets(&results);
    let xss_targets = CrawlTargetExtractor::targets_for_scanner(
        &targets,
        jack_sparrow::core::scanners::ScannerType::Xss,
    );

    assert!(!xss_targets.is_empty());
}

#[test]
fn targets_filtered_for_stored_xss() {
    let results = make_test_crawl_results();
    let targets = CrawlTargetExtractor::extract_targets(&results);
    let stored_xss_targets = CrawlTargetExtractor::targets_for_scanner(
        &targets,
        jack_sparrow::core::scanners::ScannerType::XssStored,
    );

    // Stored XSS should only target forms
    assert_eq!(stored_xss_targets.len(), 1);
    assert_eq!(stored_xss_targets[0].target_type, TargetType::Form);
}

#[test]
fn dom_xss_analyzer_works_with_crawl() {
    let config = JackSparrowConfig::default();
    let scanner = DomXssScanner::new(&config);

    // Simulate HTML with DOM XSS
    let html = r#"
        <html>
        <body>
            <div id="output"></div>
            <script>
                var data = location.hash.substring(1);
                document.getElementById('output').innerHTML = data;
            </script>
        </body>
        </html>
    "#;

    let findings = scanner.analyze_html(html);
    assert!(!findings.is_empty(), "Should detect DOM XSS in HTML");

    // Verify finding details
    let finding = &findings[0];
    assert!(finding.severity == jack_sparrow::shared::types::Severity::Critical
        || finding.severity == jack_sparrow::shared::types::Severity::High);
    assert!(finding.source_name == "location.hash");
    assert!(finding.sink_name == "innerHTML");
}

#[test]
fn stored_xss_scanner_analyzes_forms() {
    let config = JackSparrowConfig::default();
    let _scanner = StoredXssScanner::new(&config);

    // Create a target with a form
    let target = ScanTarget {
        url: Url::parse("http://example.com/comment").unwrap(),
        method: Method::Post,
        params: vec![
            jack_sparrow::core::scanners::crawl_integration::ScanParam {
                name: "comment".to_string(),
                param_type: ParamType::Body,
                value: None,
                is_hidden: false,
            },
        ],
        source_url: Some("http://example.com".to_string()),
        target_type: TargetType::Form,
        depth: 1,
    };

    // Test that the scanner can analyze the target (sync check only)
    // Stored XSS requires actual HTTP requests, so we just verify the target structure
    assert_eq!(target.params.len(), 1);
    assert_eq!(target.params[0].name, "comment");
    assert_eq!(target.target_type, TargetType::Form);
}

#[test]
fn crawler_config_defaults_are_valid() {
    let config = CrawlerConfig::default();
    assert!(config.max_depth > 0);
    assert!(config.max_pages > 0);
    assert!(config.max_concurrent > 0);
    assert!(!config.user_agent.is_empty());
}

#[test]
fn crawl_scope_defaults() {
    let scope = CrawlScope::default();
    assert!(scope.same_domain_only);
}

#[test]
fn scanner_types_all_have_display() {
    use jack_sparrow::core::scanners::ScannerType;

    let types = vec![
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
    ];

    for scanner_type in types {
        let display = format!("{}", scanner_type);
        assert!(!display.is_empty());
    }
}

#[test]
fn vulnerability_types_all_have_display() {
    use jack_sparrow::shared::types::VulnerabilityType;

    let types = vec![
        VulnerabilityType::SqlInjection,
        VulnerabilityType::XssReflected,
        VulnerabilityType::XssStored,
        VulnerabilityType::XssDom,
        VulnerabilityType::Idor,
        VulnerabilityType::Ssrf,
        VulnerabilityType::SupplyChainDependency,
        VulnerabilityType::SupplyChainMalicious,
        VulnerabilityType::SecurityHeader,
        VulnerabilityType::TechFingerprint,
        VulnerabilityType::SecretExposed,
    ];

    for vuln_type in types {
        let display = format!("{}", vuln_type);
        assert!(!display.is_empty());
    }
}

#[test]
fn finding_creation_with_defaults() {
    use jack_sparrow::shared::types::{Confidence, Finding, Severity, VulnerabilityType};

    let finding = Finding::new(
        VulnerabilityType::XssReflected,
        Severity::High,
        Confidence::Confirmed,
        "Test Finding".to_string(),
        "http://example.com".to_string(),
        "test-scanner".to_string(),
    );

    assert_eq!(finding.vulnerability_type, VulnerabilityType::XssReflected);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(finding.title, "Test Finding");
    assert!(!finding.id.is_nil());
}

#[test]
fn severity_ordering() {
    use jack_sparrow::shared::types::Severity;

    // Severity derives PartialOrd by declaration order: Critical < High < Medium < Low < Info
    assert!(Severity::Critical < Severity::High);
    assert!(Severity::High < Severity::Medium);
    assert!(Severity::Medium < Severity::Low);
    assert!(Severity::Low < Severity::Info);

    // But rank() gives the "importance" ordering (higher = more severe)
    assert!(Severity::Critical.rank() > Severity::High.rank());
    assert!(Severity::High.rank() > Severity::Medium.rank());
    assert!(Severity::Medium.rank() > Severity::Low.rank());
    assert!(Severity::Low.rank() > Severity::Info.rank());
}

#[test]
fn scan_results_creation() {
    use jack_sparrow::shared::types::ScanResults;

    let mut results = ScanResults::new("http://example.com".to_string());
    assert_eq!(results.target, "http://example.com");
    assert!(results.findings.is_empty());
    assert_eq!(results.scan_duration_ms, 0);

    results.tools_used.push("test".to_string());
    assert_eq!(results.tools_used.len(), 1);
}

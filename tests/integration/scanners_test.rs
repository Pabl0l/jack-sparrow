use jack_sparrow::core::scanners::idor::IdorScanner;
use jack_sparrow::core::scanners::supply_chain::SupplyChainScanner;
use jack_sparrow::core::scanners::{Scanner, ScannerType};
use jack_sparrow::shared::config::JackSparrowConfig;
use jack_sparrow::shared::types::{Severity, VulnerabilityType};

#[tokio::test]
async fn test_idor_scanner_type() {
    let config = JackSparrowConfig::default();
    let scanner = IdorScanner::new(&config);
    assert_eq!(scanner.scanner_type(), ScannerType::Idor);
}

#[tokio::test]
async fn test_supply_chain_scanner_type() {
    let config = JackSparrowConfig::default();
    let scanner = SupplyChainScanner::new(&config);
    assert_eq!(scanner.scanner_type(), ScannerType::SupplyChain);
}

#[tokio::test]
async fn test_supply_chain_detect_ecosystem_cargo() {
    let config = JackSparrowConfig::default();
    let scanner = SupplyChainScanner::new(&config);
    // Test against current project (has Cargo.toml)
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ecosystems = scanner.detect_ecosystem(path);
    assert!(ecosystems.contains(&"cargo".to_string()));
}

#[test]
fn test_config_default_values() {
    let config = JackSparrowConfig::default();
    assert_eq!(config.general.max_concurrent, 4);
    assert_eq!(config.general.timeout_secs, 300);
    assert_eq!(config.scanners.sqli.level, 3);
    assert_eq!(config.scanners.sqli.risk, 1);
    assert_eq!(config.scanners.xss.workers, 50);
    assert_eq!(config.scanners.idor.id_range, (1, 100));
    assert_eq!(config.scanners.ssrf.level, 2);
    assert!(config.scanners.supply_chain.check_npm);
    assert!(config.scanners.supply_chain.check_pip);
    assert!(config.scanners.supply_chain.check_cargo);
}

#[test]
fn test_config_serialization() {
    let config = JackSparrowConfig::default();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    assert!(toml_str.contains("max_concurrent"));
    assert!(toml_str.contains("sqlmap"));

    let deserialized: JackSparrowConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        deserialized.general.max_concurrent,
        config.general.max_concurrent
    );
}

#[test]
fn test_finding_creation() {
    use jack_sparrow::shared::types::{Confidence, Finding};

    let finding = Finding::new(
        VulnerabilityType::SqlInjection,
        Severity::High,
        Confidence::Confirmed,
        "Test Finding".to_string(),
        "http://test.com".to_string(),
        "test-tool".to_string(),
    );

    assert_eq!(finding.vulnerability_type, VulnerabilityType::SqlInjection);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(finding.title, "Test Finding");
    assert_eq!(finding.url, "http://test.com");
    assert_eq!(finding.tool_source, "test-tool");
    assert!(!finding.id.is_nil());
}

#[test]
fn test_severity_ranking() {
    assert!(Severity::Critical.rank() > Severity::High.rank());
    assert!(Severity::High.rank() > Severity::Medium.rank());
    assert!(Severity::Medium.rank() > Severity::Low.rank());
    assert!(Severity::Low.rank() > Severity::Info.rank());
}

#[test]
fn test_vulnerability_type_display() {
    assert_eq!(VulnerabilityType::SqlInjection.to_string(), "SQL Injection");
    assert_eq!(VulnerabilityType::XssReflected.to_string(), "Reflected XSS");
    assert_eq!(VulnerabilityType::XssStored.to_string(), "Stored XSS");
    assert_eq!(VulnerabilityType::XssDom.to_string(), "DOM XSS");
    assert_eq!(VulnerabilityType::Idor.to_string(), "IDOR");
    assert_eq!(VulnerabilityType::Ssrf.to_string(), "SSRF");
    assert_eq!(
        VulnerabilityType::SupplyChainDependency.to_string(),
        "Dependency Vulnerability"
    );
    assert_eq!(
        VulnerabilityType::SupplyChainMalicious.to_string(),
        "Malicious Package"
    );
}

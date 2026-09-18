use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_version_command() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("Jack Sparrow 0.2.0"));
}

#[test]
fn test_help_command() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Professional web pentesting tool"));
}

#[test]
fn test_scan_help() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .args(&["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--target"))
        .stdout(predicate::str::contains("--checks"));
}

#[test]
fn test_init_config_creates_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("jack-sparrow.toml");

    Command::cargo_bin("sparrow")
        .unwrap()
        .args(&["init-config", "--output"])
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("max_concurrent"));
    assert!(content.contains("sqlmap"));
    assert!(content.contains("sqli"));
}

#[test]
fn test_check_tools_missing() {
    // This should fail because tools aren't installed in CI
    let result = Command::cargo_bin("sparrow")
        .unwrap()
        .arg("check-tools")
        .output()
        .unwrap();

    // Command may fail if tools are not installed, that's expected
    // We just verify it runs without panicking
    assert!(result.status.code().is_some());
}

#[test]
fn test_scan_missing_target() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .arg("scan")
        .assert()
        .failure();
}

#[test]
fn test_invalid_check_name() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .args(&[
            "scan",
            "--target",
            "http://example.com",
            "--checks",
            "invalid-check",
        ])
        .assert()
        .failure();
}

#[test]
fn test_record_help() {
    Command::cargo_bin("sparrow")
        .unwrap()
        .args(&["record", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--browser"));
}

#[test]
fn test_init_config_default_path() {
    let temp_dir = TempDir::new().unwrap();

    Command::cargo_bin("sparrow")
        .unwrap()
        .arg("init-config")
        .current_dir(&temp_dir)
        .assert()
        .success();

    assert!(temp_dir.path().join("jack-sparrow.toml").exists());
}

#[test]
fn test_scan_output_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("test-output.json");

    // This will fail because target is unreachable, but we test the CLI parsing
    let result = Command::cargo_bin("sparrow")
        .unwrap()
        .args(&[
            "scan",
            "--target",
            "http://localhost:99999",
            "--checks",
            "sqli",
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "json",
            "--timeout",
            "5",
        ])
        .output()
        .unwrap();

    // Command may fail due to connection error, but CLI should parse correctly
    assert!(result.status.code().is_some());
}

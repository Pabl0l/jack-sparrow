use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use url::Url;

/// Native SQL Injection scanner — no external tools required.
///
/// Detects: error-based, boolean-blind, and time-based SQLi.
pub struct NativeSqlScanner;

impl NativeSqlScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Build HTTP client with context headers/cookies
	fn build_client(&self, context: &ScanContext) -> Result<Client, JackSparrowError> {
		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert(
			"User-Agent",
			reqwest::header::HeaderValue::from_static("JackSparrow/0.4.0"),
		);
		for (key, value) in &context.headers {
			if let (Ok(k), Ok(v)) = (
				reqwest::header::HeaderName::from_bytes(key.as_bytes()),
				reqwest::header::HeaderValue::from_str(value),
			) {
				headers.insert(k, v);
			}
		}
		let client = Client::builder()
			.default_headers(headers)
			.danger_accept_invalid_certs(true)
			.timeout(std::time::Duration::from_secs(10))
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "native-sqli".to_string(),
				message: e.to_string(),
			})?;
		Ok(client)
	}

	/// Extract query parameters from URL
	fn extract_params(url_str: &str) -> Vec<(String, String)> {
		if let Ok(url) = Url::parse(url_str) {
			url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
		} else {
			Vec::new()
		}
	}

	/// Build URL with modified parameter
	fn build_url(base: &str, param: &str, value: &str) -> Result<String, JackSparrowError> {
		let mut url = Url::parse(base).map_err(|e| JackSparrowError::InvalidTarget { url: e.to_string() })?;
		let mut pairs: Vec<(String, String)> = url.query_pairs()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect();
		// Replace or add the target parameter
		let mut found = false;
		for (k, v) in &mut pairs {
			if k == param {
				*v = value.to_string();
				found = true;
				break;
			}
		}
		if !found {
			pairs.push((param.to_string(), value.to_string()));
		}
		url.query_pairs_mut().clear();
		for (k, v) in &pairs {
			url.query_pairs_mut().append_pair(k, v);
		}
		Ok(url.to_string())
	}

	/// Fetch URL and return (status, body, elapsed_ms)
	async fn fetch(
		&self,
		client: &Client,
		url: &str,
		context: &ScanContext,
	) -> Result<(u16, String, u128), JackSparrowError> {
		let start = std::time::Instant::now();
		let mut req = client.get(url);
		if let Some(ref cookies) = context.cookies {
			req = req.header("Cookie", cookies.as_str());
		}
		let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
			tool: "native-sqli".to_string(),
			message: e.to_string(),
		})?;
		let status = resp.status().as_u16();
		let body = resp.text().await.unwrap_or_default();
		let elapsed = start.elapsed().as_millis();
		Ok((status, body, elapsed))
	}

	/// Detect SQL error messages in response body
	fn has_sql_error(body: &str) -> Option<String> {
		let error_patterns = [
			// MySQL
			"you have an error in your sql syntax",
			"warning: mysql",
			"unclosed quotation mark",
			"mysql_fetch",
			"mysql_num_rows",
			"pg_query",
			"pg_exec",
			// PostgreSQL
			"ERROR: syntax error at or near",
			"ERROR: unterminated quoted string",
			// MSSQL
			"Unclosed quotation mark after the character string",
			"Microsoft OLE DB Provider for SQL Server",
			"ODBC SQL Server Driver",
			// Oracle
			"ORA-01756",
			"ORA-00933",
			"quoted string not properly terminated",
			// SQLite
			"SQLITE_ERROR",
			"SQLITE_CONSTRAINT",
			// Generic
			"sql syntax",
			"syntax error",
			"unexpected end of sql command",
			"invalid query",
			"sql command not properly ended",
			"sqlstate",
		];
		let body_lower = body.to_lowercase();
		for pattern in &error_patterns {
			if body_lower.contains(&pattern.to_lowercase()) {
				return Some(pattern.to_string());
			}
		}
		None
	}

	/// Detect database type from error message
	fn detect_db_type(body: &str) -> &'static str {
		let body_lower = body.to_lowercase();
		if body_lower.contains("mysql") || body_lower.contains("mariadb") || body_lower.contains("mysql_fetch") || body_lower.contains("mysql_num_rows") {
			"MySQL/MariaDB"
		} else if body_lower.contains("pg_query") || body_lower.contains("postgresql") || body_lower.contains("pg_exec") || body_lower.contains("psql") {
			"PostgreSQL"
		} else if body_lower.contains("microsoft") || body_lower.contains("sql server") || body_lower.contains("odbc") || body_lower.contains("unclosed quotation mark") {
			"Microsoft SQL Server"
		} else if body_lower.contains("ora-") || body_lower.contains("oracle") {
			"Oracle"
		} else if body_lower.contains("sqlite") {
			"SQLite"
		} else if body_lower.contains("syntax error at or near") {
			"PostgreSQL" // PostgreSQL-specific error format
		} else {
			"Unknown"
		}
	}
}

#[async_trait]
impl Scanner for NativeSqlScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::SqlInjection
	}

	async fn scan(
		&self,
		target: &str,
		_config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = self.build_client(context)?;
		let params = Self::extract_params(target);

		if params.is_empty() {
			// No parameters to test — try POST body with common param names
			return Ok(Vec::new());
		}

		let mut findings = Vec::new();

		// SQLi payloads organized by technique
		let error_payloads = [
			// Error-based
			("'\"", "Error-based single quote"),
			("\"", "Error-based double quote"),
			("' OR '1'='1", "OR tautology"),
			("' OR '1'='1' --", "OR tautology with comment"),
			("1' ORDER BY 100--", "ORDER BY column count"),
			("' UNION SELECT NULL--", "UNION NULL"),
			("' AND 1=CONVERT(int, (SELECT @@version))--", "MSSQL convert"),
			("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))--", "MySQL extractvalue"),
			("' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version)), 1)--", "MySQL updatexml"),
		];

		let bool_true_payload = "' OR '1'='1";
		let bool_false_payload = "' OR '1'='2";

		let time_payloads = [
			// Time-based (seconds to wait)
			("' OR SLEEP(3)--", 3u64, "MySQL SLEEP"),
			("'; WAITFOR DELAY '0:0:3'--", 3, "MSSQL WAITFOR"),
			("' OR pg_sleep(3)--", 3, "PostgreSQL pg_sleep"),
			("1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3, "MySQL subquery SLEEP"),
		];

		for (param_name, _param_value) in &params {
			// === ERROR-BASED SQLi ===
			for (payload, technique) in &error_payloads {
				let inject_url = Self::build_url(target, param_name, payload)?;
				if let Ok((status, body, _elapsed)) = self.fetch(&client, &inject_url, context).await {
					if let Some(error_match) = Self::has_sql_error(&body) {
						let db_type = Self::detect_db_type(&body);
						let mut finding = Finding::new(
							VulnerabilityType::SqlInjection,
							Severity::High,
							Confidence::Confirmed,
							format!("SQL Injection ({}): parameter '{}' with payload '{}' — {} database detected",
								technique, param_name, payload, db_type),
							target.to_string(),
							"native-sqli-scanner".to_string(),
						);
						finding.parameter = Some(param_name.clone());
						finding.evidence = Evidence {
							request: Some(format!("GET {} HTTP/1.1", inject_url)),
							response: Some(format!("Status: {}, SQL error: '{}' in response", status, error_match)),
							payload: Some(payload.to_string()),
							pattern: Some(error_match),
							context: Some(format!("Database: {}", db_type)),
						};
						finding.cwe_id = Some("CWE-89".to_string());
						finding.cvss_score = Some(8.6);
						finding.remediation = "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.".to_string();
						finding.references = vec![
							"https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
							"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
						];
						findings.push(finding);
						break; // One finding per parameter is enough for error-based
					}
				}
			}

			// === BOOLEAN-BASED BLIND SQLi ===
			let baseline_url = Self::build_url(target, param_name, "1")?;
			let true_url = Self::build_url(target, param_name, bool_true_payload)?;
			let false_url = Self::build_url(target, param_name, bool_false_payload)?;

			if let (Ok((_, baseline_body, _)), Ok((_, true_body, _)), Ok((_, false_body, _))) = (
				self.fetch(&client, &baseline_url, context).await,
				self.fetch(&client, &true_url, context).await,
				self.fetch(&client, &false_url, context).await,
			) {
				// If true condition gives different response than false condition
				// AND true condition looks like baseline → likely boolean-blind SQLi
				if baseline_body.len() > 0
					&& true_body.len() > 0
					&& false_body.len() > 0
					&& baseline_body.len() == true_body.len()
					&& baseline_body.len() != false_body.len()
				{
					let mut finding = Finding::new(
						VulnerabilityType::SqlInjection,
						Severity::High,
						Confidence::Likely,
						format!("Boolean-based blind SQL Injection in parameter '{}'", param_name),
						target.to_string(),
						"native-sqli-scanner".to_string(),
					);
					finding.parameter = Some(param_name.clone());
					finding.evidence = Evidence {
						request: Some(format!("GET {} (true) vs GET {} (false)", true_url, false_url)),
						response: Some(format!(
							"Baseline: {} bytes, True condition: {} bytes, False condition: {} bytes",
							baseline_body.len(), true_body.len(), false_body.len()
						)),
						payload: Some(format!("True: {} | False: {}", bool_true_payload, bool_false_payload)),
						pattern: Some("Response length difference between true/false conditions".to_string()),
						context: None,
					};
					finding.cwe_id = Some("CWE-89".to_string());
					finding.cvss_score = Some(7.5);
					finding.remediation = "Use parameterized queries or prepared statements.".to_string();
					finding.references = vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()];
					findings.push(finding);
				}
			}

			// === TIME-BASED BLIND SQLi ===
			for (payload, delay_secs, technique) in &time_payloads {
				let inject_url = Self::build_url(target, param_name, payload)?;
				// First, get baseline response time
				let baseline_url = Self::build_url(target, param_name, "1")?;
				if let (Ok((_, _, baseline_elapsed)), Ok((_, _, inject_elapsed))) = (
					self.fetch(&client, &baseline_url, context).await,
					self.fetch(&client, &inject_url, context).await,
				) {
					// If response took significantly longer than baseline (> delay_secs * 800ms)
					let expected_ms = (*delay_secs as u128) * 800;
					if inject_elapsed > baseline_elapsed + expected_ms {
						let mut finding = Finding::new(
							VulnerabilityType::SqlInjection,
							Severity::High,
							Confidence::Likely,
							format!("Time-based blind SQL Injection ({}) in parameter '{}'", technique, param_name),
							target.to_string(),
							"native-sqli-scanner".to_string(),
						);
						finding.parameter = Some(param_name.clone());
						finding.evidence = Evidence {
							request: Some(format!("GET {} (delay={}s)", inject_url, delay_secs)),
							response: Some(format!(
								"Baseline: {}ms, Injected: {}ms (expected ~{}ms delay)",
								baseline_elapsed, inject_elapsed, delay_secs * 1000
							)),
							payload: Some(payload.to_string()),
							pattern: Some(format!("{}ms response delay detected", inject_elapsed - baseline_elapsed)),
							context: Some(technique.to_string()),
						};
						finding.cwe_id = Some("CWE-89".to_string());
						finding.cvss_score = Some(7.5);
						finding.remediation = "Use parameterized queries or prepared statements.".to_string();
						finding.references = vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()];
						findings.push(finding);
						break; // One time-based finding per parameter
					}
				}
			}
		}

		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_has_sql_error_mysql() {
		let body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
		assert!(NativeSqlScanner::has_sql_error(body).is_some());
		assert_eq!(NativeSqlScanner::detect_db_type(body), "MySQL/MariaDB");
	}

	#[test]
	fn test_has_sql_error_postgres() {
		let body = "ERROR: syntax error at or near \"1\"";
		assert!(NativeSqlScanner::has_sql_error(body).is_some());
		assert_eq!(NativeSqlScanner::detect_db_type(body), "PostgreSQL");
	}

	#[test]
	fn test_has_sql_error_mssql() {
		let body = "Unclosed quotation mark after the character string";
		assert!(NativeSqlScanner::has_sql_error(body).is_some());
		assert_eq!(NativeSqlScanner::detect_db_type(body), "Microsoft SQL Server");
	}

	#[test]
	fn test_has_sql_error_sqlite() {
		let body = "SQLITE_ERROR: near \"1\": syntax error";
		assert!(NativeSqlScanner::has_sql_error(body).is_some());
		assert_eq!(NativeSqlScanner::detect_db_type(body), "SQLite");
	}

	#[test]
	fn test_no_sql_error_normal_page() {
		let body = "<html><body>Hello World</body></html>";
		assert!(NativeSqlScanner::has_sql_error(body).is_none());
	}

	#[test]
	fn test_extract_params() {
		let params = NativeSqlScanner::extract_params("http://example.com/page?id=1&name=test");
		assert_eq!(params.len(), 2);
		assert_eq!(params[0].0, "id");
		assert_eq!(params[0].1, "1");
	}

	#[test]
	fn test_build_url() {
		let url = NativeSqlScanner::build_url(
			"http://example.com/page?id=1&name=test",
			"id",
			"1' OR '1'='1",
		).unwrap();
		assert!(url.contains("1%27+OR+%271%27%3D%271") || url.contains("id=1'%20OR%20'1'%3D'1"));
	}

	#[test]
	fn test_scanner_type() {
		let scanner = NativeSqlScanner;
		assert_eq!(scanner.scanner_type(), ScannerType::SqlInjection);
	}
}

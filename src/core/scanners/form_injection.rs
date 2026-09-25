#![allow(dead_code)]

use crate::core::scanners::crawl_integration::{ParamType, ScanParam, ScanTarget, TargetType};
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::{Duration, Instant};

/// POST body injection scanner — tests SQLi, XSS, SSTI via form submissions.
///
/// This scanner receives `ScanTarget` objects from the crawl system
/// and injects payloads into POST body parameters.
pub struct FormInjectionScanner {
    client: Client,
}

impl FormInjectionScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        let timeout = Duration::from_secs(config.general.timeout_secs.min(15));
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        Self { client }
    }

    /// Build form body from target params, replacing the target param with payload.
    fn build_form_body<'a>(
        params: &'a [ScanParam],
        target_param: &'a str,
        payload: &'a str,
    ) -> Vec<(&'a str, String)> {
        params
            .iter()
            .map(|p| {
                if p.name == target_param {
                    (p.name.as_str(), payload.to_string())
                } else {
                    (
                        p.name.as_str(),
                        p.value.clone().unwrap_or_else(|| "test".to_string()),
                    )
                }
            })
            .collect()
    }

    /// Send POST request with form-encoded body.
    async fn send_post_form(
        &self,
        url: &str,
        body: &[(&str, String)],
        context: &ScanContext,
    ) -> Result<(u16, String, u128), JackSparrowError> {
        let start = Instant::now();
        let mut req = self.client.post(url).form(body);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }
        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "form-injection".to_string(),
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        let elapsed = start.elapsed().as_millis();
        Ok((status, body_text, elapsed))
    }

    /// Send GET request with query parameters.
    async fn send_get(
        &self,
        base_url: &str,
        params: &[(&str, String)],
        context: &ScanContext,
    ) -> Result<(u16, String, u128), JackSparrowError> {
        let start = Instant::now();
        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        let url = if base_url.contains('?') {
            format!("{}&{}", base_url, query)
        } else {
            format!("{}?{}", base_url, query)
        };
        let mut req = self.client.get(&url);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }
        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "form-injection".to_string(),
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        let elapsed = start.elapsed().as_millis();
        Ok((status, body_text, elapsed))
    }

    /// Build query params from target params, replacing the target param with payload.
    fn build_query_params<'a>(
        params: &'a [ScanParam],
        target_param: &'a str,
        payload: &'a str,
    ) -> Vec<(&'a str, String)> {
        params
            .iter()
            .map(|p| {
                if p.name == target_param {
                    (p.name.as_str(), payload.to_string())
                } else {
                    (
                        p.name.as_str(),
                        p.value.clone().unwrap_or_else(|| "test".to_string()),
                    )
                }
            })
            .collect()
    }

    // ─── SQLi Detection (GET) ─────────────────────────────────────

    async fn test_sqli_get(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let error_payloads = [
            ("'", "Error-based single quote"),
            ("' OR '1'='1", "OR tautology"),
            ("' OR '1'='1' --", "OR tautology with comment"),
            ("1' ORDER BY 100--", "ORDER BY column count"),
            ("' UNION SELECT NULL--", "UNION NULL"),
        ];

        // Get baseline
        let baseline_params = Self::build_query_params(&target.params, &param.name, "sparrow_baseline");
        if let Ok((_, baseline, _)) = self.send_get(url, &baseline_params, context).await {
            // Error-based
            for (payload, technique) in &error_payloads {
                let params = Self::build_query_params(&target.params, &param.name, payload);
                if let Ok((status, resp, _)) = self.send_get(url, &params, context).await {
                    if let Some(error_match) = Self::has_sql_error(&resp) {
                        let db = Self::detect_db_type(&resp);
                        return Some(self.make_sqli_finding_get(
                            param, payload, technique, &error_match, db, url, status,
                        ));
                    }
                }
            }

            // Boolean-blind
            let true_params = Self::build_query_params(&target.params, &param.name, "' OR '1'='1");
            let false_params = Self::build_query_params(&target.params, &param.name, "' OR '1'='2");
            if let (Ok((_, tb, _)), Ok((_, fb, _))) = (
                self.send_get(url, &true_params, context).await,
                self.send_get(url, &false_params, context).await,
            ) {
                if !baseline.is_empty() && !tb.is_empty() && !fb.is_empty()
                    && tb.len() == baseline.len()
                    && tb.len() != fb.len()
                {
                    return Some(self.make_bool_finding_get(param, url));
                }
            }
        }

        None
    }

    // ─── XSS Detection (GET) ──────────────────────────────────────

    async fn test_xss_get(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "'-alert(1)-'",
            "\"><script>alert('xss')</script>",
        ];

        for payload in &payloads {
            let params = Self::build_query_params(&target.params, &param.name, payload);
            if let Ok((_, resp, _)) = self.send_get(url, &params, context).await {
                if resp.contains(payload) {
                    return Some(Finding {
                        id: uuid::Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::XssReflected,
                        severity: Severity::High,
                        confidence: Confidence::Confirmed,
                        title: format!("Reflected XSS in GET parameter: {}", param.name),
                        description: format!(
                            "The '{}' parameter reflects unsanitized input in GET response. \
                             Payload '{}' was reflected without encoding.",
                            param.name, payload
                        ),
                        url: url.to_string(),
                        parameter: Some(param.name.clone()),
                        evidence: Evidence {
                            request: Some(format!("GET {}?{}={}", url, param.name, payload)),
                            response: Some(format!("Payload reflected in response body")),
                            payload: Some(payload.to_string()),
                            pattern: Some(payload.to_string()),
                            context: Some("GET parameter reflection".to_string()),
                        },
                        remediation: "Encode all output data. Validate and sanitize input. Use Content-Security-Policy.".to_string(),
                        references: vec![
                            "https://owasp.org/www-community/attacks/xss/".to_string(),
                            "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                        ],
                        timestamp: chrono::Utc::now(),
                        cvss_score: Some(6.1),
                        cwe_id: Some("CWE-79".to_string()),
                        tool_source: "form-injection-xss".to_string(),
                    });
                }
            }
        }

        None
    }

    // ─── SSTI Detection (GET) ─────────────────────────────────────

    async fn test_ssti_get(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("{{7*'7'}}", "7777777", "Jinja2 string concat"),
            ("{7*7}", "49", "Smarty"),
            ("${7*7}", "49", "Freemarker/Velocity"),
            ("<%= 7*7 %>", "49", "ERB"),
        ];

        // Baseline
        let baseline_params = Self::build_query_params(&target.params, &param.name, "sparrow_baseline");
        let baseline_resp = self.send_get(url, &baseline_params, context).await.ok().map(|(_, b, _)| b).unwrap_or_default();

        for (payload, expected, engine) in &payloads {
            let params = Self::build_query_params(&target.params, &param.name, payload);
            if let Ok((_, resp, _)) = self.send_get(url, &params, context).await {
                if Self::check_ssti_hit(&resp, expected) && !Self::check_ssti_hit(&baseline_resp, expected) {
                    return Some(Finding {
                        id: uuid::Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::Ssti,
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        title: format!("SSTI via {} in GET parameter: {}", engine, param.name),
                        description: format!(
                            "Server-Side Template Injection confirmed at {} via GET parameter '{}'. \
                             Payload '{}' produced expected output '{}' via {} engine.",
                            url, param.name, payload, expected, engine
                        ),
                        url: url.to_string(),
                        parameter: Some(param.name.clone()),
                        evidence: Evidence {
                            request: Some(format!("GET {}?{}={}", url, param.name, payload)),
                            response: Some(format!("Expected output '{}' found in response", expected)),
                            payload: Some(payload.to_string()),
                            pattern: Some(expected.to_string()),
                            context: Some(format!("Template engine: {}", engine)),
                        },
                        remediation: "Never render user input in templates. Use sandboxed environments. Implement auto-escaping.".to_string(),
                        references: vec![
                            "https://cwe.mitre.org/data/definitions/1336.html".to_string(),
                            "https://owasp.org/www-community-vulnerabilities/Server_Side_Template_Injection".to_string(),
                        ],
                        timestamp: chrono::Utc::now(),
                        cvss_score: Some(9.8),
                        cwe_id: Some("CWE-1336".to_string()),
                        tool_source: "form-injection-ssti".to_string(),
                    });
                }
            }
        }

        None
    }

    // ─── SQLi Detection ───────────────────────────────────────────

    fn has_sql_error(body: &str) -> Option<String> {
        let patterns = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "mysql_fetch",
            "mysql_num_rows",
            "pg_query",
            "pg_exec",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",
            "ORA-01756",
            "ORA-00933",
            "quoted string not properly terminated",
            "SQLITE_ERROR",
            "SQLITE_CONSTRAINT",
            "unrecognized token",
            "near \": no such column",
            "near \"\": syntax error",
            "sql syntax",
            "syntax error",
            "unexpected end of sql command",
            "sqlstate",
        ];
        let lower = body.to_lowercase();
        for pat in &patterns {
            if lower.contains(pat) {
                return Some(pat.to_string());
            }
        }
        None
    }

    fn detect_db_type(body: &str) -> &'static str {
        let lower = body.to_lowercase();
        if lower.contains("mysql") || lower.contains("mariadb") || lower.contains("mysql_fetch") {
            "MySQL/MariaDB"
        } else if lower.contains("pg_query") || lower.contains("postgresql") || lower.contains("psql") {
            "PostgreSQL"
        } else if lower.contains("microsoft") || lower.contains("sql server") || lower.contains("odbc") {
            "Microsoft SQL Server"
        } else if lower.contains("ora-") || lower.contains("oracle") {
            "Oracle"
        } else if lower.contains("sqlite") || lower.contains("unrecognized token") {
            "SQLite"
        } else if lower.contains("syntax error at or near") {
            "PostgreSQL"
        } else {
            "Unknown"
        }
    }

    async fn test_sqli_post(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let error_payloads = [
            ("'", "Error-based single quote"),
            ("' OR '1'='1", "OR tautology"),
            ("' OR '1'='1' --", "OR tautology with comment"),
            ("1' ORDER BY 100--", "ORDER BY column count"),
            ("' UNION SELECT NULL--", "UNION NULL"),
        ];

        // Get baseline
        let baseline_body = Self::build_form_body(&target.params, &param.name, "sparrow_baseline");
        if let Ok((_, baseline, _)) = self.send_post_form(url, &baseline_body, context).await {
            // Error-based
            for (payload, technique) in &error_payloads {
                let body = Self::build_form_body(&target.params, &param.name, payload);
                if let Ok((status, resp, _)) = self.send_post_form(url, &body, context).await {
                    if let Some(error_match) = Self::has_sql_error(&resp) {
                        let db = Self::detect_db_type(&resp);
                        return Some(self.make_sqli_finding(
                            target, param, payload, technique, &error_match, db, url, status, &resp,
                        ));
                    }
                }
            }

            // Boolean-blind
            let true_body = Self::build_form_body(&target.params, &param.name, "' OR '1'='1");
            let false_body = Self::build_form_body(&target.params, &param.name, "' OR '1'='2");
            if let (Ok((_, tb, _)), Ok((_, fb, _))) = (
                self.send_post_form(url, &true_body, context).await,
                self.send_post_form(url, &false_body, context).await,
            ) {
                if !baseline.is_empty() && !tb.is_empty() && !fb.is_empty()
                    && tb.len() == baseline.len()
                    && tb.len() != fb.len()
                {
                    return Some(self.make_bool_finding(target, param, url));
                }
            }

            // Time-based
            let time_payloads = [
                ("' OR SLEEP(3)--", 3u64, "MySQL SLEEP"),
                ("'; WAITFOR DELAY '0:0:3'--", 3, "MSSQL WAITFOR"),
                ("' OR pg_sleep(3)--", 3, "PostgreSQL pg_sleep"),
            ];
            let baseline_url = Self::build_form_body(&target.params, &param.name, "1");
            if let Ok((_, _, baseline_ms)) = self.send_post_form(url, &baseline_url, context).await {
                for (payload, delay, technique) in &time_payloads {
                    let body = Self::build_form_body(&target.params, &param.name, payload);
                    if let Ok((_, _, inject_ms)) = self.send_post_form(url, &body, context).await {
                        let expected_ms = (*delay as u128) * 800;
                        if inject_ms > baseline_ms + expected_ms {
                            return Some(self.make_time_finding(
                                target, param, payload, technique, url, baseline_ms, inject_ms,
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    // ─── XSS Detection ───────────────────────────────────────────

    async fn test_xss_post(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "'-alert(1)-'",
            "\"><script>alert('xss')</script>",
        ];

        for payload in &payloads {
            let body = Self::build_form_body(&target.params, &param.name, payload);
            if let Ok((_, resp, _)) = self.send_post_form(url, &body, context).await {
                if resp.contains(payload) {
                    return Some(Finding {
                        id: uuid::Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::XssReflected,
                        severity: Severity::High,
                        confidence: Confidence::Confirmed,
                        title: format!("Reflected XSS in POST parameter: {}", param.name),
                        description: format!(
                            "The '{}' parameter reflects unsanitized input in POST response. \
                             Payload '{}' was reflected without encoding.",
                            param.name, payload
                        ),
                        url: url.to_string(),
                        parameter: Some(param.name.clone()),
                        evidence: Evidence {
                            request: Some(format!("POST {} [{}={}]", url, param.name, payload)),
                            response: Some(format!("Payload reflected in response body")),
                            payload: Some(payload.to_string()),
                            pattern: Some(payload.to_string()),
                            context: Some("POST body reflection".to_string()),
                        },
                        remediation: "Encode all output data. Validate and sanitize input. Use Content-Security-Policy.".to_string(),
                        references: vec![
                            "https://owasp.org/www-community/attacks/xss/".to_string(),
                            "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                        ],
                        timestamp: chrono::Utc::now(),
                        cvss_score: Some(6.1),
                        cwe_id: Some("CWE-79".to_string()),
                        tool_source: "form-injection-xss".to_string(),
                    });
                }
            }
        }

        None
    }

    // ─── SSTI Detection ──────────────────────────────────────────

    async fn test_ssti_post(
        &self,
        target: &ScanTarget,
        param: &ScanParam,
        context: &ScanContext,
    ) -> Option<Finding> {
        let url = target.url.as_str();
        let payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("{{7*'7'}}", "7777777", "Jinja2 string concat"),
            ("{7*7}", "49", "Smarty"),
            ("${7*7}", "49", "Freemarker/Velocity"),
            ("<%= 7*7 %>", "49", "ERB"),
        ];

        // Baseline
        let baseline_body = Self::build_form_body(&target.params, &param.name, "sparrow_baseline");
        let baseline_resp = self.send_post_form(url, &baseline_body, context).await.ok().map(|(_, b, _)| b).unwrap_or_default();

        for (payload, expected, engine) in &payloads {
            let body = Self::build_form_body(&target.params, &param.name, payload);
            if let Ok((_, resp, _)) = self.send_post_form(url, &body, context).await {
                if Self::check_ssti_hit(&resp, expected) && !Self::check_ssti_hit(&baseline_resp, expected) {
                    return Some(Finding {
                        id: uuid::Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::Ssti,
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        title: format!("SSTI via {} in POST parameter: {}", engine, param.name),
                        description: format!(
                            "Server-Side Template Injection confirmed at {} via POST parameter '{}'. \
                             Payload '{}' produced expected output '{}' via {} engine.",
                            url, param.name, payload, expected, engine
                        ),
                        url: url.to_string(),
                        parameter: Some(param.name.clone()),
                        evidence: Evidence {
                            request: Some(format!("POST {} [{}={}]", url, param.name, payload)),
                            response: Some(format!("Expected output '{}' found in response", expected)),
                            payload: Some(payload.to_string()),
                            pattern: Some(expected.to_string()),
                            context: Some(format!("Template engine: {}", engine)),
                        },
                        remediation: "Never render user input in templates. Use sandboxed environments. Implement auto-escaping.".to_string(),
                        references: vec![
                            "https://cwe.mitre.org/data/definitions/1336.html".to_string(),
                            "https://owasp.org/www-community-vulnerabilities/Server_Side_Template_Injection".to_string(),
                        ],
                        timestamp: chrono::Utc::now(),
                        cvss_score: Some(9.8),
                        cwe_id: Some("CWE-1336".to_string()),
                        tool_source: "form-injection-ssti".to_string(),
                    });
                }
            }
        }

        None
    }

    fn check_ssti_hit(body: &str, expected: &str) -> bool {
        if expected == "49" {
            let transformed = body.replace(">", "> ").replace("<", " <");
            let words: Vec<&str> = transformed.split_whitespace().collect();
            return words.iter().any(|w| *w == "49");
        }
        if expected == "7777777" {
            return body.contains("7777777");
        }
        body.contains(expected)
    }

    // ─── Finding Builders ─────────────────────────────────────────

    fn make_sqli_finding(
        &self, _target: &ScanTarget, param: &ScanParam, payload: &str,
        technique: &str, error_match: &str, db: &str, url: &str,
        status: u16, _resp: &str,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            title: format!("SQL Injection ({}) in POST parameter: {}", technique, param.name),
            description: format!(
                "SQL Injection confirmed at {} via POST parameter '{}'. \
                 Technique: {}. Database: {}. Error pattern: '{}'",
                url, param.name, technique, db, error_match
            ),
            url: url.to_string(),
            parameter: Some(param.name.clone()),
            evidence: Evidence {
                request: Some(format!("POST {} [{}={}]", url, param.name, payload)),
                response: Some(format!("Status: {}, SQL error: '{}' in response", status, error_match)),
                payload: Some(payload.to_string()),
                pattern: Some(error_match.to_string()),
                context: Some(format!("Database: {}", db)),
            },
            remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL.".to_string(),
            references: vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ],
            timestamp: chrono::Utc::now(),
            cvss_score: Some(8.6),
            cwe_id: Some("CWE-89".to_string()),
            tool_source: "form-injection-sqli".to_string(),
        }
    }

    fn make_bool_finding(
        &self, _target: &ScanTarget, param: &ScanParam, url: &str,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("Boolean-based blind SQLi in POST parameter: {}", param.name),
            description: format!(
                "Boolean-based blind SQL Injection detected in POST parameter '{}' at {}. \
                 True condition matches baseline, false condition differs.",
                param.name, url
            ),
            url: url.to_string(),
            parameter: Some(param.name.clone()),
            evidence: Evidence {
                request: Some(format!("POST {} [true vs false conditions]", url)),
                response: Some("Response length differs between true/false conditions".to_string()),
                payload: Some("true: ' OR '1'='1 | false: ' OR '1'='2".to_string()),
                pattern: Some("Boolean differential".to_string()),
                context: None,
            },
            remediation: "Use parameterized queries or prepared statements.".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            timestamp: chrono::Utc::now(),
            cvss_score: Some(7.5),
            cwe_id: Some("CWE-89".to_string()),
            tool_source: "form-injection-sqli".to_string(),
        }
    }

    fn make_time_finding(
        &self, _target: &ScanTarget, param: &ScanParam, payload: &str,
        technique: &str, url: &str, baseline_ms: u128, inject_ms: u128,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("Time-based blind SQLi ({}) in POST parameter: {}", technique, param.name),
            description: format!(
                "Time-based blind SQL Injection in POST parameter '{}' at {}. \
                 Baseline: {}ms, Injected: {}ms",
                param.name, url, baseline_ms, inject_ms
            ),
            url: url.to_string(),
            parameter: Some(param.name.clone()),
            evidence: Evidence {
                request: Some(format!("POST {} [{}={}]", url, param.name, payload)),
                response: Some(format!("Baseline: {}ms, Injected: {}ms", baseline_ms, inject_ms)),
                payload: Some(payload.to_string()),
                pattern: Some(format!("{}ms delay", inject_ms - baseline_ms)),
                context: Some(technique.to_string()),
            },
            remediation: "Use parameterized queries or prepared statements.".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            timestamp: chrono::Utc::now(),
            cvss_score: Some(7.5),
            cwe_id: Some("CWE-89".to_string()),
            tool_source: "form-injection-sqli".to_string(),
        }
    }

    fn make_sqli_finding_get(
        &self, param: &ScanParam, payload: &str,
        technique: &str, error_match: &str, db: &str, url: &str,
        status: u16,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            title: format!("SQL Injection ({}) in GET parameter: {}", technique, param.name),
            description: format!(
                "SQL Injection confirmed at {} via GET parameter '{}'. \
                 Technique: {}. Database: {}. Error pattern: '{}'",
                url, param.name, technique, db, error_match
            ),
            url: url.to_string(),
            parameter: Some(param.name.clone()),
            evidence: Evidence {
                request: Some(format!("GET {}?{}={}", url, param.name, payload)),
                response: Some(format!("Status: {}, SQL error: '{}' in response", status, error_match)),
                payload: Some(payload.to_string()),
                pattern: Some(error_match.to_string()),
                context: Some(format!("Database: {}", db)),
            },
            remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL.".to_string(),
            references: vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ],
            timestamp: chrono::Utc::now(),
            cvss_score: Some(8.6),
            cwe_id: Some("CWE-89".to_string()),
            tool_source: "form-injection-sqli".to_string(),
        }
    }

    fn make_bool_finding_get(
        &self, param: &ScanParam, url: &str,
    ) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("Boolean-based blind SQLi in GET parameter: {}", param.name),
            description: format!(
                "Boolean-based blind SQL Injection detected in GET parameter '{}' at {}. \
                 True condition matches baseline, false condition differs.",
                param.name, url
            ),
            url: url.to_string(),
            parameter: Some(param.name.clone()),
            evidence: Evidence {
                request: Some(format!("GET {} [true vs false conditions]", url)),
                response: Some("Response length differs between true/false conditions".to_string()),
                payload: Some("true: ' OR '1'='1 | false: ' OR '1'='2".to_string()),
                pattern: Some("Boolean differential".to_string()),
                context: None,
            },
            remediation: "Use parameterized queries or prepared statements.".to_string(),
            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            timestamp: chrono::Utc::now(),
            cvss_score: Some(7.5),
            cwe_id: Some("CWE-89".to_string()),
            tool_source: "form-injection-sqli".to_string(),
        }
    }
}

#[async_trait]
impl Scanner for FormInjectionScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::FormInjection
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        _context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        // Basic scan mode — not used directly. Use scan_with_targets() instead.
        let _ = target;
        Ok(Vec::new())
    }
}

impl FormInjectionScanner {
    /// Scan a list of form targets for injection vulnerabilities.
    pub async fn scan_with_targets(
        &self,
        targets: &[&ScanTarget],
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        for target in targets {
            if target.target_type != TargetType::Form {
                continue;
            }

            let is_get = matches!(
                target.method,
                crate::core::crawler::parser::Method::Get
            );

            for param in &target.params {
                if param.is_hidden || param.param_type == ParamType::Hidden {
                    continue;
                }

                if is_get {
                    if let Some(f) = self.test_sqli_get(target, param, context).await {
                        findings.push(f);
                    }
                    if let Some(f) = self.test_xss_get(target, param, context).await {
                        findings.push(f);
                    }
                    if let Some(f) = self.test_ssti_get(target, param, context).await {
                        findings.push(f);
                    }
                } else {
                    if let Some(f) = self.test_sqli_post(target, param, context).await {
                        findings.push(f);
                    }
                    if let Some(f) = self.test_xss_post(target, param, context).await {
                        findings.push(f);
                    }
                    if let Some(f) = self.test_ssti_post(target, param, context).await {
                        findings.push(f);
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
    use crate::core::crawler::parser::Method;
    use crate::core::scanners::crawl_integration::TargetType;
    use url::Url;

    fn make_form_target(url: &str, params: Vec<ScanParam>) -> ScanTarget {
        ScanTarget {
            url: Url::parse(url).unwrap(),
            method: Method::Post,
            params,
            source_url: None,
            target_type: TargetType::Form,
            depth: 1,
        }
    }

    fn make_param(name: &str) -> ScanParam {
        ScanParam {
            name: name.to_string(),
            param_type: ParamType::Body,
            value: Some("test".to_string()),
            is_hidden: false,
        }
    }

    #[test]
    fn test_has_sql_error_mysql() {
        let body = "You have an error in your SQL syntax mysql_fetch; check the manual";
        assert!(FormInjectionScanner::has_sql_error(body).is_some());
        assert_eq!(FormInjectionScanner::detect_db_type(body), "MySQL/MariaDB");
    }

    #[test]
    fn test_has_sql_error_postgres() {
        let body = "ERROR: syntax error at or near \"1\" postgresql";
        assert!(FormInjectionScanner::has_sql_error(body).is_some());
        assert_eq!(FormInjectionScanner::detect_db_type(body), "PostgreSQL");
    }

    #[test]
    fn test_has_sql_error_mssql() {
        let body = "Unclosed quotation mark after the character string microsoft sql server";
        assert!(FormInjectionScanner::has_sql_error(body).is_some());
        assert_eq!(FormInjectionScanner::detect_db_type(body), "Microsoft SQL Server");
    }

    #[test]
    fn test_no_sql_error_normal() {
        let body = "<html><body>Hello World</body></html>";
        assert!(FormInjectionScanner::has_sql_error(body).is_none());
    }

    #[test]
    fn test_build_form_body() {
        let params = vec![make_param("user"), make_param("pass")];
        let body = FormInjectionScanner::build_form_body(&params, "user", "payload");
        assert_eq!(body.len(), 2);
        assert_eq!(body[0], ("user", "payload".to_string()));
        assert_eq!(body[1], ("pass", "test".to_string()));
    }

    #[test]
    fn test_check_ssti_hit_math() {
        assert!(FormInjectionScanner::check_ssti_hit("<p>Result: 49</p>", "49"));
    }

    #[test]
    fn test_check_ssti_no_false_positive() {
        assert!(!FormInjectionScanner::check_ssti_hit("<p>Result: 149</p>", "49"));
    }

    #[test]
    fn test_check_ssti_string_concat() {
        assert!(FormInjectionScanner::check_ssti_hit("7777777", "7777777"));
    }

    #[test]
    fn test_scanner_type() {
        let scanner = FormInjectionScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::FormInjection);
    }

    #[test]
    fn test_form_target_has_params() {
        let target = make_form_target(
            "http://example.com/login",
            vec![make_param("username"), make_param("password")],
        );
        assert_eq!(target.params.len(), 2);
        assert_eq!(target.target_type, TargetType::Form);
    }
}

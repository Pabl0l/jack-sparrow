use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;

const WS_PATHS: &[&str] = &[
    "/ws",
    "/socket",
    "/websocket",
    "/chat",
    "/events",
    "/stream",
    "/ws/",
    "/socket.io/",
    "/signalr/",
    "/graphql-ws",
    "/api/ws",
    "/realtime",
    "/live",
    "/push",
];

const WS_HEADERS: &[(&str, &str)] = &[
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ("Sec-WebSocket-Version", "13"),
    ("Sec-WebSocket-Protocol", "chat, superchat"),
];

const INFO_DISCLOSURE_HEADERS: &[(&str, &str)] = &[
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "X-AspNet-Version"),
    ("x-generator", "X-Generator"),
];

/// Extracts `host[:port]` from an `http(s)://` URL.
/// Currently exercised by the unit tests; kept for upcoming origin checks.
#[allow(dead_code)]
fn extract_domain(url: &str) -> String {
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

fn build_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    let mut req = client.get(url);
    for (k, v) in WS_HEADERS {
        req = req.header(*k, *v);
    }
    req
}

fn build_request_with_context(
    client: &reqwest::Client,
    url: &str,
    context: &ScanContext,
) -> reqwest::RequestBuilder {
    let mut req = build_request(client, url);
    if let Some(ref cookies) = context.cookies {
        req = req.header("Cookie", cookies.as_str());
    }
    for (k, v) in &context.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    req
}

fn make_finding(
    url: &str,
    title: String,
    description: String,
    sev: Severity,
    cwe: &str,
) -> Finding {
    let mut f = Finding::new(
        VulnerabilityType::SecurityHeader,
        sev,
        Confidence::Confirmed,
        title,
        url.to_string(),
        "websocket-security-scanner".to_string(),
    );
    f.description = description;
    f.cwe_id = Some(cwe.to_string());
    f
}

/// WebSocket Security Scanner
///
/// Detects: missing auth, Cross-Site WebSocket Hijacking, info disclosure via WS handshake.
pub struct WebSocketSecurityScanner;

impl WebSocketSecurityScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for WebSocketSecurityScanner {
    fn scanner_type(&self) -> ScannerType {
        // NOTE: needs WebSocketSecurity variant in mod.rs ScannerType enum
        ScannerType::SecurityHeaders
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?;

        let base = target.trim_end_matches('/');
        let mut all_findings = Vec::new();

        for path in WS_PATHS {
            let url = format!("{}{}", base, path);

            // 1. Test WebSocket upgrade with context
            let status = build_request_with_context(&client, &url, context)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0);

            if status != 101 {
                continue;
            }

            // Report WS upgrade supported
            all_findings.push(make_finding(
                &url,
                "WebSocket upgrade supported on path".to_string(),
                format!(
					"The server accepted a WebSocket upgrade on {}. Audit for auth and origin validation.",
					path
				),
                Severity::Info,
                "CWE-200",
            ));

            // 2. Test without auth
            let noauth_status = build_request(&client, &url)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0);

            if status == 101 && noauth_status == 101 {
                let mut f = make_finding(
					&url,
					"WebSocket endpoint accessible without authentication".to_string(),
					format!(
						"The WS endpoint at {} accepts upgrades without auth headers, even with auth context available.",
						path
					),
					Severity::High,
					"CWE-306",
				);
                f.remediation =
					"Require authentication before accepting WebSocket upgrades. Reject with HTTP 401.".to_string();
                f.evidence = Evidence {
                    request: Some(format!("GET {} (no auth)", url)),
                    response: Some("HTTP 101 Switching Protocols".to_string()),
                    payload: None,
                    pattern: Some("Upgrade: websocket".to_string()),
                    context: None,
                };
                f.cvss_score = Some(7.5);
                f.references =
                    vec!["https://portswigger.net/web-security/websockets/csrf".to_string()];
                all_findings.push(f);
            }

            // 3. Cross-Site WebSocket Hijacking
            let cswsh_status = client
                .get(&url)
                .headers({
                    let mut h = reqwest::header::HeaderMap::new();
                    for (k, v) in WS_HEADERS {
                        h.insert(
                            reqwest::header::HeaderName::from_static(k),
                            v.parse().unwrap(),
                        );
                    }
                    h
                })
                .header("Origin", "https://evil-attacker.com")
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0);

            if cswsh_status == 101 {
                let mut f = make_finding(
                    &url,
                    "Cross-Site WebSocket Hijacking possible".to_string(),
                    format!(
						"WS endpoint at {} accepted upgrade with cross-origin Origin (https://evil-attacker.com).",
						path
					),
                    Severity::High,
                    "CWE-346",
                );
                f.remediation =
                    "Validate Origin header on WS handshake. Use CSRF tokens for WS auth."
                        .to_string();
                f.evidence = Evidence {
                    request: Some(format!("GET {} Origin: https://evil-attacker.com", url)),
                    response: Some("HTTP 101 Switching Protocols".to_string()),
                    payload: None,
                    pattern: Some("Origin: https://evil-attacker.com".to_string()),
                    context: None,
                };
                f.cvss_score = Some(8.1);
                f.references = vec![
                    "https://portswigger.net/web-security/websockets/csrf".to_string(),
                    "https://cwe.mitre.org/data/definitions/346.html".to_string(),
                ];
                all_findings.push(f);
            }

            // 4. Info disclosure in handshake
            if let Ok(resp) = build_request(&client, &url).send().await {
                for (header_name, header_label) in INFO_DISCLOSURE_HEADERS {
                    if let Some(val) = resp.headers().get(*header_name) {
                        if let Ok(val_str) = val.to_str() {
                            if !val_str.is_empty() {
                                let mut f = make_finding(
                                    &url,
                                    "WebSocket endpoint leaks server information".to_string(),
                                    format!("{} header present: {}", header_label, val_str),
                                    Severity::Low,
                                    "CWE-200",
                                );
                                f.remediation = format!("Remove the {} header.", header_label);
                                f.evidence = Evidence {
                                    request: Some(format!("GET {}", url)),
                                    response: Some(format!("{}: {}", header_label, val_str)),
                                    payload: None,
                                    pattern: Some(format!("{}: {}", header_label, val_str)),
                                    context: None,
                                };
                                all_findings.push(f);
                            }
                        }
                    }
                }
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type() {
        let config = JackSparrowConfig::default();
        let scanner = WebSocketSecurityScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::SecurityHeaders);
    }

    #[test]
    fn test_ws_paths_list() {
        assert_eq!(WS_PATHS.len(), 14);
        assert!(WS_PATHS.contains(&"/ws"));
        assert!(WS_PATHS.contains(&"/socket"));
        assert!(WS_PATHS.contains(&"/websocket"));
        assert!(WS_PATHS.contains(&"/chat"));
        assert!(WS_PATHS.contains(&"/events"));
        assert!(WS_PATHS.contains(&"/stream"));
        assert!(WS_PATHS.contains(&"/graphql-ws"));
        assert!(WS_PATHS.contains(&"/socket.io/"));
        assert!(WS_PATHS.contains(&"/signalr/"));
    }

    #[test]
    fn test_ws_headers_list() {
        assert_eq!(WS_HEADERS.len(), 5);
        let names: Vec<&str> = WS_HEADERS.iter().map(|(k, _)| *k).collect();
        assert!(names.contains(&"Upgrade"));
        assert!(names.contains(&"Connection"));
        assert!(names.contains(&"Sec-WebSocket-Key"));
        assert!(names.contains(&"Sec-WebSocket-Version"));
        assert!(names.contains(&"Sec-WebSocket-Protocol"));
    }

    #[test]
    fn test_new_scanner() {
        let config = JackSparrowConfig::default();
        let scanner = WebSocketSecurityScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::SecurityHeaders);
    }

    #[test]
    fn test_build_client() {
        let result = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ws_upgrade_headers() {
        let has_upgrade = WS_HEADERS.iter().any(|(k, _)| *k == "Upgrade");
        let has_connection = WS_HEADERS.iter().any(|(k, _)| *k == "Connection");
        let has_key = WS_HEADERS.iter().any(|(k, _)| *k == "Sec-WebSocket-Key");
        let has_version = WS_HEADERS
            .iter()
            .any(|(k, _)| *k == "Sec-WebSocket-Version");
        assert!(has_upgrade);
        assert!(has_connection);
        assert!(has_key);
        assert!(has_version);
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(
            extract_domain("http://sub.example.com:8080/ws"),
            "sub.example.com:8080"
        );
        assert_eq!(extract_domain("https://10.0.0.1/api"), "10.0.0.1");
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_default_config() {
        let config = JackSparrowConfig::default();
        let scanner = WebSocketSecurityScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::SecurityHeaders);
    }
}

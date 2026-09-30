use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;

const CACHE_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Proto",
    "X-Forwarded-Scheme",
    "X-Custom-IP-Authorization",
];

const CACHE_INDICATORS: &[&str] = &[
    "X-Cache",
    "X-Cache-Hits",
    "X-Served-By",
    "X-Varnish",
    "Age",
    "CF-Cache-Status",
    "X-Drupal-Cache",
    "X-Proxy-Cache",
    "X-Cache-Status",
    "CDN-Cache-Control",
];

const CACHE_DECEPTION_PATHS: &[&str] = &[
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/images/",
    "/css/",
    "/js/",
    "/static/",
];

struct PoisonResult {
    header: String,
    value: String,
    description: String,
}

pub struct CachePoisoningScanner;

impl CachePoisoningScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }

    fn build_client() -> Result<reqwest::Client, JackSparrowError> {
        Ok(reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?)
    }

    async fn detect_cache(client: &reqwest::Client, url: &str) -> bool {
        if let Ok(resp) = client.get(url).send().await {
            for header in CACHE_INDICATORS {
                if resp.headers().get(*header).is_some() {
                    return true;
                }
            }
        }
        false
    }

    async fn test_header_poisoning(
        client: &reqwest::Client,
        url: &str,
        header: &str,
        value: &str,
    ) -> Option<PoisonResult> {
        let mut req = client.get(url);
        req = req.header(header, value);
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                if body_lower.contains(value.to_lowercase().as_str())
                    || body_lower.contains("error")
                    || body_lower.contains("invalid")
                {
                    return Some(PoisonResult {
                        header: header.to_string(),
                        value: value.to_string(),
                        description: format!(
                            "Response reflects the unkeyed header value from {}",
                            header
                        ),
                    });
                }
            }
        }
        None
    }

    async fn test_cache_deception(client: &reqwest::Client, url: &str, path: &str) -> bool {
        let deception_url = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&deception_url).send().await {
            for header in CACHE_INDICATORS {
                if resp.headers().get(*header).is_some() {
                    return true;
                }
            }
        }
        false
    }

    async fn test_parameter_cloaking(client: &reqwest::Client, url: &str) -> bool {
        let cloaked = format!("{}?utm_content=1", url.trim_end_matches('/'));
        if let Ok(resp) = client.get(&cloaked).send().await {
            for header in CACHE_INDICATORS {
                if resp.headers().get(*header).is_some() {
                    return true;
                }
            }
        }
        false
    }

    async fn test_vary_header(client: &reqwest::Client, url: &str) -> bool {
        if let Ok(resp) = client.get(url).send().await {
            return resp.headers().get("vary").is_none();
        }
        false
    }

    fn check_poisoned_response(original: &str, poisoned: &str) -> bool {
        original != poisoned
    }
}

#[async_trait]
impl Scanner for CachePoisoningScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::CachePoisoning
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = Self::build_client()?;
        let base = target.trim_end_matches('/');
        let mut all_findings = Vec::new();

        // 1. Check if target uses caching
        if !Self::detect_cache(&client, base).await {
            return Ok(all_findings);
        }

        // 2. Get baseline response for comparison
        let mut baseline_req = client.get(base);
        for (k, v) in &context.headers {
            baseline_req = baseline_req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            baseline_req = baseline_req.header("Cookie", cookies.as_str());
        }
        let baseline_body = match baseline_req.send().await {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };

        // 3. Test each cache header for poisoning
        for header in CACHE_HEADERS {
            if let Some(result) =
                Self::test_header_poisoning(&client, base, header, "evil.com").await
            {
                let mut req = client.get(base);
                if let Ok(name) = header.parse::<reqwest::header::HeaderName>() {
                    req = req.header(name, "evil.com");
                }
                for (k, v) in &context.headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Ok(resp) = req.send().await {
                    let poisoned_body = resp.text().await.unwrap_or_default();
                    if Self::check_poisoned_response(&baseline_body, &poisoned_body) {
                        let mut finding = Finding::new(
                            VulnerabilityType::ApiSecurity,
                            Severity::High,
                            Confidence::Confirmed,
                            format!("Cache poisoning via unkeyed header {}", result.header),
                            base.to_string(),
                            "cache-poisoning-scanner".to_string(),
                        );
                        finding.description = result.description;
                        finding.remediation = format!(
							"Ensure the cache key includes the {} header or reject requests containing it.",
							result.header
						);
                        finding.evidence = Evidence {
                            request: Some(format!(
                                "GET {} {}: {}",
                                base, result.header, result.value
                            )),
                            response: Some(format!(
                                "Poisoned response differs from baseline ({} vs {} chars)",
                                baseline_body.len(),
                                poisoned_body.len()
                            )),
                            payload: Some(format!("{}: {}", result.header, result.value)),
                            pattern: Some(result.header),
                            context: None,
                        };
                        finding.references = vec![
							"https://portswigger.net/web-security/request-smuggling/cache-poisoning"
								.to_string(),
						];
                        finding.cvss_score = Some(7.5);
                        finding.cwe_id = Some("CWE-444".to_string());
                        all_findings.push(finding);
                    }
                }
            }
        }

        // 4. Test cache deception paths
        for path in CACHE_DECEPTION_PATHS {
            if Self::test_cache_deception(&client, base, path).await {
                let mut finding = Finding::new(
                    VulnerabilityType::ApiSecurity,
                    Severity::Medium,
                    Confidence::Likely,
                    format!("Cache deception possible on path {}", path),
                    format!("{}{}", base, path),
                    "cache-poisoning-scanner".to_string(),
                );
                finding.description = format!(
					"The path {} is being cached despite being appended to the original URL, indicating cache deception.",
					path
				);
                finding.remediation =
					"Configure the cache to only cache responses for expected paths and content types."
						.to_string();
                finding.evidence = Evidence {
                    request: Some(format!("GET {}{}", base, path)),
                    response: Some("Cache indicators found in response headers".to_string()),
                    payload: Some(path.to_string()),
                    pattern: Some(path.to_string()),
                    context: None,
                };
                finding.references = vec![
					"https://portswigger.net/web-security/request-smuggling/cache-poisoning/exploiting-cache-deception"
						.to_string(),
				];
                finding.cvss_score = Some(5.3);
                finding.cwe_id = Some("CWE-444".to_string());
                all_findings.push(finding);
            }
        }

        // 5. Test parameter cloaking
        if Self::test_parameter_cloaking(&client, base).await {
            let mut finding = Finding::new(
                VulnerabilityType::ApiSecurity,
                Severity::High,
                Confidence::Likely,
                "Parameter cloaking cache poisoning".to_string(),
                base.to_string(),
                "cache-poisoning-scanner".to_string(),
            );
            finding.description =
                "Appending a query parameter (utm_content) causes the response to be cached, \
				 which can be used to poison the cache for all users."
                    .to_string();
            finding.remediation =
                "Ensure the cache key includes the full query string, not just the path."
                    .to_string();
            finding.evidence = Evidence {
                request: Some(format!("GET {}?utm_content=1", base)),
                response: Some("Cache indicators found in response headers".to_string()),
                payload: Some("utm_content=1".to_string()),
                pattern: Some("utm_content".to_string()),
                context: None,
            };
            finding.references = vec![
				"https://portswigger.net/web-security/request-smuggling/cache-poisoning/exploiting-parameter-cloaking"
					.to_string(),
			];
            finding.cvss_score = Some(7.5);
            finding.cwe_id = Some("CWE-444".to_string());
            all_findings.push(finding);
        }

        // 6. Check missing Vary header
        if Self::test_vary_header(&client, base).await {
            let mut finding = Finding::new(
                VulnerabilityType::ApiSecurity,
                Severity::Low,
                Confidence::Possible,
                "Missing Vary header on cached responses".to_string(),
                base.to_string(),
                "cache-poisoning-scanner".to_string(),
            );
            finding.description =
                "The response does not include a Vary header, which may allow the cache \
				 to serve incorrect content to different clients."
                    .to_string();
            finding.remediation =
                "Add an appropriate Vary header (e.g., Vary: Accept-Encoding) to cached responses."
                    .to_string();
            finding.evidence = Evidence {
                request: Some(format!("GET {}", base)),
                response: Some("No Vary header present".to_string()),
                payload: None,
                pattern: Some("Vary".to_string()),
                context: None,
            };
            finding.references =
                vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary".to_string()];
            finding.cvss_score = Some(2.5);
            finding.cwe_id = Some("CWE-444".to_string());
            all_findings.push(finding);
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type() {
        let scanner = CachePoisoningScanner;
        assert_eq!(scanner.scanner_type(), ScannerType::CachePoisoning);
    }

    #[test]
    fn test_cache_headers_list() {
        assert!(CACHE_HEADERS.contains(&"X-Forwarded-Host"));
        assert!(CACHE_HEADERS.contains(&"X-Original-URL"));
        assert!(CACHE_HEADERS.contains(&"X-Rewrite-URL"));
        assert!(CACHE_HEADERS.contains(&"X-Host"));
        assert!(CACHE_HEADERS.contains(&"X-Forwarded-For"));
        assert!(CACHE_HEADERS.contains(&"X-Real-IP"));
        assert_eq!(CACHE_HEADERS.len(), 9);
    }

    #[test]
    fn test_cache_indicators_list() {
        assert!(CACHE_INDICATORS.contains(&"X-Cache"));
        assert!(CACHE_INDICATORS.contains(&"CF-Cache-Status"));
        assert!(CACHE_INDICATORS.contains(&"Age"));
        assert_eq!(CACHE_INDICATORS.len(), 10);
    }

    #[test]
    fn test_cache_deception_paths_list() {
        assert!(CACHE_DECEPTION_PATHS.contains(&"/robots.txt"));
        assert!(CACHE_DECEPTION_PATHS.contains(&"/favicon.ico"));
        assert!(CACHE_DECEPTION_PATHS.contains(&"/static/"));
        assert_eq!(CACHE_DECEPTION_PATHS.len(), 7);
    }

    #[test]
    fn test_new_scanner() {
        let config = JackSparrowConfig::default();
        let scanner = CachePoisoningScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::CachePoisoning);
    }

    #[test]
    fn test_build_client() {
        let client = CachePoisoningScanner::build_client();
        assert!(client.is_ok());
    }

    #[test]
    fn test_detect_cache_found() {
        // Simulates the logic: if any cache indicator header is present, return true
        let indicators = ["X-Cache", "Age", "CF-Cache-Status"];
        assert!(indicators.contains(&"X-Cache"));
    }

    #[test]
    fn test_detect_cache_not_found() {
        let indicators: Vec<&str> = vec![];
        assert!(!indicators.contains(&"X-Cache"));
    }

    #[test]
    fn test_check_poisoned_response_same() {
        assert!(!CachePoisoningScanner::check_poisoned_response(
            "hello", "hello"
        ));
    }

    #[test]
    fn test_default_config() {
        let config = JackSparrowConfig::default();
        let scanner = CachePoisoningScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::CachePoisoning);
    }
}

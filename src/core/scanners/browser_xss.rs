use crate::core::scanners::browser_scanner::{BrowserConfig, BrowserScanner};
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;

/// Browser-based XSS scanner
///
/// This scanner uses Playwright to render pages and detect XSS vulnerabilities
/// that require JavaScript execution. It's especially useful for:
/// - SPA applications that render content with JavaScript
/// - DOM-based XSS that only manifest in the browser
/// - XSS that requires authentication (cookies are passed to browser)
pub struct BrowserXssScanner {
    config: BrowserConfig,
}

impl BrowserXssScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        Self {
            config: BrowserConfig::from(config),
        }
    }

    /// XSS payloads for browser-based testing
    fn xss_payloads() -> Vec<&'static str> {
        vec![
            // Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            // Event handlers
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            // JavaScript URIs
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            // Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            // DOM XSS payloads
            "<img src=x onerror=alert(document.cookie)>",
            "<svg/onload=alert(document.domain)>",
            // Template injection
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
        ]
    }

    /// Check if response contains the unescaped payload
    fn detect_xss(&self, payload: &str, html: &str) -> bool {
        // Check if the payload appears in the HTML without encoding
        if html.contains(payload) {
            return true;
        }

        false
    }

    /// Extract the reflection context from HTML
    fn extract_reflection_context(&self, payload: &str, html: &str) -> Option<String> {
        // Find the position of the payload in HTML
        if let Some(pos) = html.find(payload) {
            let start = pos.saturating_sub(100);
            let end = (pos + payload.len() + 100).min(html.len());
            let context = &html[start..end];
            return Some(context.to_string());
        }
        None
    }

    /// Detect if page is a JavaScript-rendered SPA
    fn is_spa(&self, html: &str) -> bool {
        let spa_indicators = [
            "__next_data__",
            "__nuxt__",
            "__vue__",
            "ng-app",
            "data-reactroot",
            "data-v-app",
            "react-root",
            "vue-app",
            "ember-view",
            "angular",
            "react",
            "vue",
            "svelte",
        ];

        let html_lower = html.to_lowercase();
        spa_indicators
            .iter()
            .any(|indicator| html_lower.contains(indicator))
    }

    /// Test a URL parameter for XSS
    async fn test_url_param_xss(
        &self,
        url: &str,
        param_name: &str,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();
        let browser =
            crate::core::scanners::playwright_browser::PlaywrightBrowser::new(self.config.clone());

        for payload in Self::xss_payloads() {
            // Build URL with payload
            let separator = if url.contains('?') { '&' } else { '?' };
            let test_url = format!("{}{}{}={}", url, separator, param_name, payload);

            // Navigate to URL
            match browser.navigate(&test_url, context).await {
                Ok(page) => {
                    // Check if payload is reflected
                    if self.detect_xss(payload, &page.html) {
                        let reflection_context =
                            self.extract_reflection_context(payload, &page.html);

                        let mut finding = Finding::new(
                            VulnerabilityType::BrowserXss,
                            Severity::High,
                            Confidence::Confirmed,
                            format!("Browser XSS in parameter: {}", param_name),
                            url.to_string(),
                            "browser-xss".to_string(),
                        );

                        finding.parameter = Some(param_name.to_string());
                        finding.evidence = Evidence {
                            request: Some(format!("GET {} HTTP/1.1", test_url)),
                            response: None,
                            payload: Some(payload.to_string()),
                            pattern: Some("Unescaped payload in HTML".to_string()),
                            context: reflection_context,
                        };
                        finding.cwe_id = Some("CWE-79".to_string());
                        finding.cvss_score = Some(6.1);
                        finding.remediation = "Encode output and validate input".to_string();
                        finding.references =
                            vec!["https://owasp.org/www-community/attacks/xss/".to_string()];

                        findings.push(finding);
                        break; // Found XSS, no need to test more payloads
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(findings)
    }

    /// Test DOM-based XSS
    async fn test_dom_xss(
        &self,
        url: &str,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();
        let browser =
            crate::core::scanners::playwright_browser::PlaywrightBrowser::new(self.config.clone());

        // Navigate to the page
        let page = browser.navigate(url, context).await?;

        // Check if it's a SPA
        if !self.is_spa(&page.html) {
            return Ok(findings);
        }

        // Test fragment-based XSS
        let fragment_payloads = [
            "#<script>alert('XSS')</script>",
            "#<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ];

        for payload in &fragment_payloads {
            let test_url = format!("{}{}", url, payload);
            match browser.navigate(&test_url, context).await {
                Ok(test_page) => {
                    if self.detect_xss(payload, &test_page.html) {
                        let mut finding = Finding::new(
                            VulnerabilityType::BrowserXss,
                            Severity::High,
                            Confidence::Likely,
                            format!("DOM XSS via fragment: {}", payload),
                            url.to_string(),
                            "browser-xss".to_string(),
                        );

                        finding.parameter = Some("fragment".to_string());
                        finding.evidence = Evidence {
                            request: Some(format!("GET {}", test_url)),
                            response: None,
                            payload: Some(payload.to_string()),
                            pattern: Some("DOM manipulation via fragment".to_string()),
                            context: None,
                        };
                        finding.cwe_id = Some("CWE-79".to_string());
                        finding.cvss_score = Some(6.1);
                        finding.remediation =
                            "Sanitize fragment identifiers before DOM manipulation".to_string();
                        finding.references =
                            vec!["https://owasp.org/www-community/attacks/xss/".to_string()];

                        findings.push(finding);
                        break;
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(findings)
    }
}

#[async_trait]
impl Scanner for BrowserXssScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::BrowserXss
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        // Test common URL parameters
        let common_params = [
            "q", "search", "query", "name", "page", "redirect", "url", "callback", "next",
            "return", "ref", "link",
        ];

        // First, try to discover parameters from the URL
        if let Ok(parsed) = url::Url::parse(target) {
            for (param, _) in parsed.query_pairs() {
                let param_findings = self.test_url_param_xss(target, &param, context).await?;
                findings.extend(param_findings);
            }
        }

        // Test common parameters
        for param in &common_params {
            // Skip if already found XSS in this parameter
            if findings
                .iter()
                .any(|f| f.parameter.as_deref() == Some(param))
            {
                continue;
            }

            let param_findings = self.test_url_param_xss(target, param, context).await?;
            findings.extend(param_findings);
        }

        // Test DOM XSS
        let dom_findings = self.test_dom_xss(target, context).await?;
        findings.extend(dom_findings);

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_xss_scanner_new() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        assert_eq!(scanner.scanner_type(), ScannerType::BrowserXss);
    }

    #[test]
    fn test_xss_payloads_not_empty() {
        let payloads = BrowserXssScanner::xss_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.len() > 10);
    }

    #[test]
    fn test_detect_xss_found() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let payload = "<script>alert('XSS')</script>";
        let html = "<html><body><script>alert('XSS')</script></body></html>";
        assert!(scanner.detect_xss(payload, html));
    }

    #[test]
    fn test_detect_xss_not_found() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let payload = "<script>alert('XSS')</script>";
        let html = "<html><body>Safe content</body></html>";
        assert!(!scanner.detect_xss(payload, html));
    }

    #[test]
    fn test_detect_xss_encoded() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let payload = "<script>alert('XSS')</script>";
        let html = "<html><body>&lt;script&gt;alert('XSS')&lt;/script&gt;</body></html>";
        assert!(!scanner.detect_xss(payload, html));
    }

    #[test]
    fn test_extract_reflection_context() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let payload = "test123";
        let html = "Lorem ipsum dolor test123 sit amet";
        let context = scanner.extract_reflection_context(payload, html);
        assert!(context.is_some());
        assert!(context.unwrap().contains(payload));
    }

    #[test]
    fn test_is_spa_next() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let html = r#"<script id="__NEXT_DATA__">{"props":{}}</script>"#;
        assert!(scanner.is_spa(html));
    }

    #[test]
    fn test_is_spa_vue() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let html = r#"<div id="app" data-v-app></div>"#;
        assert!(scanner.is_spa(html));
    }

    #[test]
    fn test_is_spa_react() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let html = r#"<div id="root" class="react-root"></div>"#;
        assert!(scanner.is_spa(html));
    }

    #[test]
    fn test_is_not_spa() {
        let config = JackSparrowConfig::default();
        let scanner = BrowserXssScanner::new(&config);
        let html = r#"<html><body>Regular HTML page</body></html>"#;
        assert!(!scanner.is_spa(html));
    }
}

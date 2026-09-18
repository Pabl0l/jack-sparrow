//! # DOM XSS Scanner
//!
//! Detects DOM-based Cross-Site Scripting vulnerabilities by analyzing
//! JavaScript code for dangerous data flows from user-controlled sources
//! to dangerous sinks.

#![allow(dead_code)]
//!
//! ## Architecture
//!
//! ```text
//!                    ┌─────────────────┐
//!                    │  DomXssScanner  │
//!                    └────────┬────────┘
//!                             │
//!              ┌──────────────┼──────────────┐
//!              │              │              │
//!        ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
//!        │ JsAnalyzer│ │TaintAnalyzer│ │ Sink/Source│
//!        └───────────┘ └───────────┘ │  Databases │
//!                                     └───────────┘
//! ```
//!
//! ## Detection Flow
//!
//! 1. Extract inline `<script>` tags from HTML
//! 2. Analyze each script for sinks and sources
//! 3. Perform taint analysis to find source→sink flows
//! 4. Calculate risk score and generate findings

pub mod js_analyzer;
pub mod sinks;
pub mod sources;
pub mod taint;

use crate::core::crawler::engine::CrawlResults;
use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use taint::TaintFlow;

/// DOM XSS scanner that analyzes JavaScript for dangerous data flows.
pub struct DomXssScanner {
    js_analyzer: js_analyzer::JsAnalyzer,
    taint_analyzer: taint::TaintAnalyzer,
}

impl DomXssScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        }
    }

    /// Analyze HTML content for DOM XSS vulnerabilities.
    pub fn analyze_html(&self, html: &str) -> Vec<DomXssFinding> {
        let mut findings = Vec::new();

        // Analyze inline scripts
        let inline_analyses = self.js_analyzer.analyze_inline_scripts(html);
        for analysis in inline_analyses {
            if analysis.has_dom_xss_risk {
                let flows = self.taint_analyzer.analyze_flows(&analysis);
                for flow in flows {
                    findings.push(self.create_finding_from_flow(&flow, "inline script"));
                }
            }
        }

        // Analyze external scripts
        let suspicious_urls = self.js_analyzer.analyze_external_scripts(html);
        for url in suspicious_urls {
            findings.push(DomXssFinding {
                severity: Severity::Medium,
                confidence: Confidence::Possible,
                title: format!("Suspicious external script: {}", url),
                description: format!(
                    "An external script loaded from a potentially malicious URL was detected: {}. \
                     This could be used to inject malicious JavaScript.",
                    url
                ),
                sink_name: "external_script".to_string(),
                source_name: "external_url".to_string(),
                risk_score: 4.0,
                evidence: format!("Script URL: {}", url),
            });
        }

        // Deduplicate findings
        findings.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        findings.dedup_by(|a, b| a.title == b.title);

        findings
    }

    /// Analyze raw JavaScript code for DOM XSS.
    pub fn analyze_js_code(&self, code: &str) -> Vec<DomXssFinding> {
        let mut findings = Vec::new();

        let analysis = self.js_analyzer.analyze_js(code);
        if analysis.has_dom_xss_risk {
            let flows = self.taint_analyzer.analyze_flows(&analysis);
            for flow in flows {
                findings.push(self.create_finding_from_flow(&flow, "JavaScript code"));
            }
        }

        findings
    }

    /// Create a finding from a taint flow.
    fn create_finding_from_flow(&self, flow: &TaintFlow, context: &str) -> DomXssFinding {
        let severity = match flow.confidence {
            c if c >= 0.8 => Severity::Critical,
            c if c >= 0.6 => Severity::High,
            c if c >= 0.4 => Severity::Medium,
            _ => Severity::Low,
        };

        let confidence = match flow.confidence {
            c if c >= 0.8 => Confidence::Confirmed,
            c if c >= 0.6 => Confidence::Likely,
            c if c >= 0.4 => Confidence::Possible,
            _ => Confidence::Possible,
        };

        DomXssFinding {
            severity,
            confidence,
            title: format!(
                "DOM XSS: {} → {}",
                flow.source.name, flow.sink.name
            ),
            description: format!(
                "A taint flow was detected from user-controlled source '{}' to dangerous sink '{}' {}. \
                 This indicates a potential DOM-based XSS vulnerability where attacker-controlled data \
                 can reach a dangerous function without proper sanitization.\n\n\
                 Flow: {}",
                flow.source.name,
                flow.sink.name,
                context,
                flow.description
            ),
            sink_name: flow.sink.name.clone(),
            source_name: flow.source.name.clone(),
            risk_score: flow.confidence * 10.0,
            evidence: format!(
                "Source: {} (user_controlled: {})\n\
                 Sink: {} (risk: {:?})\n\
                 Confidence: {:.0}%",
                flow.source.name,
                flow.source.user_controlled,
                flow.sink.name,
                flow.sink.risk,
                flow.confidence * 100.0
            ),
        }
    }

    /// Convert DomXssFinding to our standard Finding type.
    fn to_finding(&self, dom_finding: &DomXssFinding, target: &str) -> Finding {
        let mut finding = Finding::new(
            VulnerabilityType::XssDom,
            dom_finding.severity.clone(),
            dom_finding.confidence.clone(),
            dom_finding.title.clone(),
            target.to_string(),
            "webscanner-dom-xss".to_string(),
        );

        finding.description = dom_finding.description.clone();
        finding.evidence = Evidence {
            request: None,
            response: None,
            payload: None,
            pattern: Some(format!(
                "source: {} → sink: {}",
                dom_finding.source_name, dom_finding.sink_name
            )),
            context: Some(dom_finding.evidence.clone()),
        };
        finding.cvss_score = Some(dom_finding.risk_score);
        finding.cwe_id = Some("CWE-79".to_string());
        finding.remediation = format!(
            "1. Avoid using dangerous sinks with user-controlled data\n\
             2. Sanitize input using a library like DOMPurify\n\
             3. Use textContent instead of innerHTML\n\
             4. Validate and encode all user input\n\
             5. Implement Content-Security-Policy headers"
        );
        finding.references = vec![
            "https://owasp.org/www-community/attacks/xss/".to_string(),
            "https://cwe.mitre.org/data/definitions/79.html".to_string(),
            "https://portswigger.net/web-security/cross-site-scripting/dom-based".to_string(),
        ];

        finding
    }
}

/// A DOM XSS finding before conversion to standard Finding.
#[derive(Debug, Clone)]
pub struct DomXssFinding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub sink_name: String,
    pub source_name: String,
    pub risk_score: f64,
    pub evidence: String,
}

#[async_trait]
impl Scanner for DomXssScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::XssDom
    }

    async fn scan(
        &self,
        target: &str,
        config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        // Basic scan mode: fetch target and analyze
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.general.timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "dom-xss".to_string(),
                message: e.to_string(),
            })?;

        let mut req = client.get(target);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let response = req.send().await.map_err(|e| {
            JackSparrowError::ToolExecutionFailed {
                tool: "dom-xss".to_string(),
                message: e.to_string(),
            }
        })?;

        let html = response.text().await.map_err(|e| {
            JackSparrowError::ToolExecutionFailed {
                tool: "dom-xss".to_string(),
                message: e.to_string(),
            }
        })?;

        let dom_findings = self.analyze_html(&html);
        let findings = dom_findings
            .iter()
            .map(|f| self.to_finding(f, target))
            .collect();

        Ok(findings)
    }
}

impl DomXssScanner {
    /// Run DOM XSS scan using crawl results.
    pub async fn scan_with_crawl(
        &self,
        crawl_results: &CrawlResults,
        _context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let mut findings = Vec::new();

        for page in &crawl_results.pages {
            if let Some(ref parsed) = page.parsed {
                // Analyze inline scripts
                for script in &parsed.inline_scripts {
                    let dom_findings = self.analyze_js_code(&script.code);
                    for dom_finding in dom_findings {
                        findings.push(self.to_finding(&dom_finding, page.url.as_str()));
                    }
                }

                // Analyze external scripts
                let html = self.reconstruct_html(parsed);
                let dom_findings = self.analyze_html(&html);
                for dom_finding in dom_findings {
                    findings.push(self.to_finding(&dom_finding, page.url.as_str()));
                }
            }
        }

        // Deduplicate
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings.dedup_by(|a, b| a.title == b.title && a.url == b.url);

        Ok(findings)
    }

    /// Reconstruct HTML from parsed data for analysis.
    fn reconstruct_html(&self, parsed: &crate::core::crawler::parser::ParsedPage) -> String {
        let mut html = String::new();

        // Add external scripts
        for script in &parsed.scripts {
            html.push_str(&format!(
                "<script src=\"{}\"></script>\n",
                script.src
            ));
        }

        // Add inline scripts (already in parsed.inline_scripts)
        // We'll analyze them separately

        // Add iframes
        for iframe in &parsed.iframes {
            if let Some(ref src) = iframe.src {
                html.push_str(&format!(
                    "<iframe src=\"{}\"></iframe>\n",
                    src
                ));
            }
        }

        // Add event handlers as comments for detection
        for handler in &parsed.event_handlers {
            html.push_str(&format!(
                "<{} {}=\"{}\">\n",
                handler.element, handler.event, handler.handler
            ));
        }

        html
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_safe_html() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let html = r#"
            <html>
            <head><title>Safe Page</title></head>
            <body>
                <p>Hello World</p>
            </body>
            </html>
        "#;

        let findings = scanner.analyze_html(html);
        assert!(findings.is_empty(), "Safe HTML should have no findings");
    }

    #[test]
    fn detect_dom_xss_with_hash() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

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
        assert!(!findings.is_empty(), "Should detect DOM XSS");
        assert!(findings.iter().any(|f| f.source_name == "location.hash"));
    }

    #[test]
    fn detect_dom_xss_with_eval() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let html = r#"
            <script>
                var code = location.search.substring(1);
                eval(code);
            </script>
        "#;

        let findings = scanner.analyze_html(html);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.sink_name == "eval"));
    }

    #[test]
    fn detect_suspicious_external_script() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let html = r#"
            <script src="http://evil.com/malicious.js"></script>
        "#;

        let findings = scanner.analyze_html(html);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("evil.com")));
    }

    #[test]
    fn analyze_js_code_direct() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let code = r#"
            var x = location.hash;
            eval(x);
        "#;

        let findings = scanner.analyze_js_code(code);
        assert!(!findings.is_empty());
    }

    #[test]
    fn finding_severity_matches_confidence() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let html = r#"
            <script>
                var data = location.hash;
                eval(data);
            </script>
        "#;

        let findings = scanner.analyze_html(html);
        if let Some(finding) = findings.first() {
            // High confidence should be Critical or High severity
            assert!(
                finding.severity == Severity::Critical || finding.severity == Severity::High
            );
        }
    }

    #[test]
    fn to_finding_has_cwe() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let dom_finding = DomXssFinding {
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Test".to_string(),
            sink_name: "eval".to_string(),
            source_name: "location.hash".to_string(),
            risk_score: 8.0,
            evidence: "test".to_string(),
        };

        let finding = scanner.to_finding(&dom_finding, "http://test.com");
        assert_eq!(finding.cwe_id, Some("CWE-79".to_string()));
        assert!(finding.cvss_score.is_some());
    }

    #[test]
    fn multiple_scripts_analyzed() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        let html = r#"
            <script>var a = location.hash; document.write(a);</script>
            <script>var b = location.search; eval(b);</script>
        "#;

        let findings = scanner.analyze_html(html);
        // Should find issues in both scripts
        assert!(findings.len() >= 2);
    }

    #[test]
    fn findings_deduplicated() {
        let scanner = DomXssScanner {
            js_analyzer: js_analyzer::JsAnalyzer::new(),
            taint_analyzer: taint::TaintAnalyzer::new(),
        };

        // Same vulnerability mentioned twice
        let html = r#"
            <script>
                var x = location.hash;
                document.getElementById('a').innerHTML = x;
                document.getElementById('b').innerHTML = x;
            </script>
        "#;

        let findings = scanner.analyze_html(html);
        // Should not have exact duplicates
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        let unique: std::collections::HashSet<&str> = titles.iter().cloned().collect();
        assert_eq!(titles.len(), unique.len());
    }
}

use super::sinks::{Sink, SinkPattern, SinkRisk, get_all_sinks};
use super::sources::{Source, SourceRisk};

/// Analysis result for a JavaScript code block.
#[derive(Debug, Clone)]
pub struct JsAnalysis {
    /// All sinks found in the code.
    pub sinks: Vec<Sink>,
    /// All sources found in the code.
    pub sources: Vec<Source>,
    /// Risk score (0.0 - 10.0).
    pub risk_score: f64,
    /// Whether the code contains potential DOM XSS.
    pub has_dom_xss_risk: bool,
    /// Source code snippet with highlights.
    pub snippet: Option<String>,
}

/// JavaScript analyzer using regex-based pattern matching.
pub struct JsAnalyzer {
    sink_patterns: Vec<SinkPattern>,
}

impl JsAnalyzer {
    /// Create a new JS analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            sink_patterns: get_all_sinks(),
        }
    }

    /// Analyze a JavaScript code block.
    pub fn analyze_js(&self, code: &str) -> JsAnalysis {
        let sinks = self.find_sinks(code);
        let sources = find_sources_in_code(code);

        let risk_score = self.calculate_risk_score(&sinks, &sources);
        let has_dom_xss_risk = risk_score >= 3.0 && !sources.is_empty() && !sinks.is_empty();

        JsAnalysis {
            sinks,
            sources,
            risk_score,
            has_dom_xss_risk,
            snippet: None,
        }
    }

    /// Analyze inline scripts from HTML.
    pub fn analyze_inline_scripts(&self, html: &str) -> Vec<JsAnalysis> {
        let mut results = Vec::new();

        // Extract inline <script> tags
        if let Ok(re) = regex::Regex::new(r"(?is)<script[^>]*>(.*?)</script>") {
            for cap in re.captures_iter(html) {
                if let Some(code) = cap.get(1) {
                    let code = code.as_str().trim();
                    if !code.is_empty() {
                        results.push(self.analyze_js(code));
                    }
                }
            }
        }

        results
    }

    /// Analyze external script URLs for potential issues.
    pub fn analyze_external_scripts(&self, html: &str) -> Vec<String> {
        let mut urls = Vec::new();

        if let Ok(re) = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#) {
            for cap in re.captures_iter(html) {
                if let Some(url) = cap.get(1) {
                    let url = url.as_str().to_string();
                    // Flag suspicious URLs
                    if self.is_suspicious_script_url(&url) {
                        urls.push(url);
                    }
                }
            }
        }

        urls
    }

    /// Find all sinks in the code.
    fn find_sinks(&self, code: &str) -> Vec<Sink> {
        let mut sinks = Vec::new();

        for pattern in &self.sink_patterns {
            if let Ok(re) = regex::Regex::new(&pattern.pattern) {
                for mat in re.find_iter(code) {
                    let before = &code[..mat.start()];
                    let line = before.lines().count();
                    let col = before
                        .rfind('\n')
                        .map_or(mat.start(), |pos| mat.start() - pos - 1);

                    sinks.push(Sink {
                        name: pattern.name.clone(),
                        full_match: mat.as_str().to_string(),
                        line,
                        col,
                        risk: pattern.risk,
                        category: pattern.category.clone(),
                    });
                }
            }
        }

        // Deduplicate by name + line
        sinks.sort_by(|a, b| a.name.cmp(&b.name).then(a.line.cmp(&b.line)));
        sinks.dedup_by(|a, b| a.name == b.name && a.line == b.line);

        sinks
    }

    /// Calculate risk score based on sinks and sources.
    fn calculate_risk_score(&self, sinks: &[Sink], sources: &[Source]) -> f64 {
        if sinks.is_empty() || sources.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;

        // Score from sinks
        for sink in sinks {
            match sink.risk {
                SinkRisk::Critical => score += 4.0,
                SinkRisk::High => score += 3.0,
                SinkRisk::Medium => score += 2.0,
                SinkRisk::Low => score += 1.0,
            }
        }

        // Score from sources
        for source in sources {
            match source.risk {
                SourceRisk::High => score += 2.0,
                SourceRisk::Medium => score += 1.0,
                SourceRisk::Low => score += 0.5,
            }
        }

        // Bonus for having user-controlled sources
        let user_controlled = sources.iter().filter(|s| s.user_controlled).count();
        score += user_controlled as f64 * 1.5;

        // Cap at 10.0
        score.min(10.0)
    }

    /// Check if a script URL looks suspicious.
    fn is_suspicious_script_url(&self, url: &str) -> bool {
        let lower = url.to_lowercase();

        // External domains
        if lower.starts_with("http://") && !lower.contains("localhost") {
            return true;
        }

        // Data URLs
        if lower.starts_with("data:") {
            return true;
        }

        // Blob URLs
        if lower.starts_with("blob:") {
            return true;
        }

        // JavaScript protocol
        if lower.starts_with("javascript:") {
            return true;
        }

        false
    }
}

/// Find sources in JavaScript code (re-exported from sources module).
fn find_sources_in_code(code: &str) -> Vec<Source> {
    super::sources::find_sources_in_code(code)
}

impl Default for JsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sinks::SinkRisk;

    #[test]
    fn analyze_simple_js_no_risk() {
        let analyzer = JsAnalyzer::new();
        let result = analyzer.analyze_js("var x = 42; console.log(x);");
        assert!(!result.has_dom_xss_risk);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn analyze_js_with_eval_and_hash() {
        let analyzer = JsAnalyzer::new();
        let code = r#"
            var hash = location.hash.substring(1);
            eval(hash);
        "#;
        let result = analyzer.analyze_js(code);
        assert!(result.has_dom_xss_risk);
        assert!(!result.sinks.is_empty());
        assert!(!result.sources.is_empty());
    }

    #[test]
    fn analyze_js_with_innerhtml() {
        let analyzer = JsAnalyzer::new();
        let code = r#"
            var data = location.hash.substring(1);
            document.getElementById('output').innerHTML = data;
        "#;
        let result = analyzer.analyze_js(code);
        assert!(result.has_dom_xss_risk);
        assert!(result.sinks.iter().any(|s| s.name == "innerHTML"));
        assert!(result.sources.iter().any(|s| s.name == "location.hash"));
    }

    #[test]
    fn detect_multiple_sinks() {
        let analyzer = JsAnalyzer::new();
        let code = r#"
            eval(code);
            document.write(html);
            el.innerHTML = data;
        "#;
        let result = analyzer.analyze_js(code);
        assert!(result.sinks.len() >= 3);
    }

    #[test]
    fn detect_multiple_sources() {
        let analyzer = JsAnalyzer::new();
        let code = r#"
            var h = location.hash;
            var s = location.search;
            var n = window.name;
        "#;
        let result = analyzer.analyze_js(code);
        assert!(result.sources.len() >= 3);
    }

    #[test]
    fn analyze_inline_scripts() {
        let analyzer = JsAnalyzer::new();
        let html = r#"
            <html>
            <script>var x = location.hash; eval(x);</script>
            <script>var y = document.URL; document.write(y);</script>
            </html>
        "#;
        let results = analyzer.analyze_inline_scripts(html);
        assert_eq!(results.len(), 2);
        assert!(results[0].has_dom_xss_risk || results[1].has_dom_xss_risk);
    }

    #[test]
    fn analyze_inline_scripts_ignores_empty() {
        let analyzer = JsAnalyzer::new();
        let html = "<script></script><script>   </script>";
        let results = analyzer.analyze_inline_scripts(html);
        assert!(results.is_empty());
    }

    #[test]
    fn detect_suspicious_external_scripts() {
        let analyzer = JsAnalyzer::new();
        let html = r#"
            <script src="http://evil.com/malicious.js"></script>
            <script src="data:text/javascript,alert(1)"></script>
            <script src="https://cdn.example.com/safe.js"></script>
        "#;
        let urls = analyzer.analyze_external_scripts(html);
        assert!(urls.len() >= 2);
        assert!(urls.iter().any(|u| u.contains("evil.com")));
        assert!(urls.iter().any(|u| u.contains("data:")));
    }

    #[test]
    fn risk_score_increases_with_severity() {
        let analyzer = JsAnalyzer::new();

        // Low risk: only low sinks and low sources
        let low_code = "el.src = localStorage.getItem('x');";
        let low = analyzer.analyze_js(low_code);

        // High risk: critical sinks and high sources
        let high_code = "eval(location.hash);";
        let high = analyzer.analyze_js(high_code);

        assert!(high.risk_score > low.risk_score);
    }

    #[test]
    fn risk_score_zero_without_sources() {
        let analyzer = JsAnalyzer::new();
        let code = "eval('test');";
        let result = analyzer.analyze_js(code);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn risk_score_zero_without_sinks() {
        let analyzer = JsAnalyzer::new();
        let code = "var x = location.hash;";
        let result = analyzer.analyze_js(code);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn sinks_deduplicated_by_line() {
        let analyzer = JsAnalyzer::new();
        let code = "eval('a'); eval('b');";
        let result = analyzer.analyze_js(code);
        // Two different lines, so 2 sinks
        assert_eq!(result.sinks.len(), 2);
    }

    #[test]
    fn critical_sinks_detected() {
        let analyzer = JsAnalyzer::new();
        let code = r#"
            eval(userInput);
            new Function(userInput);
            setTimeout('alert(1)', 100);
        "#;
        let result = analyzer.analyze_js(code);
        let critical: Vec<&Sink> = result
            .sinks
            .iter()
            .filter(|s| s.risk == SinkRisk::Critical)
            .collect();
        assert!(critical.len() >= 2);
    }
}

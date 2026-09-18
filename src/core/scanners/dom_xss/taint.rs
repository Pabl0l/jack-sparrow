use super::js_analyzer::JsAnalysis;
use super::sinks::Sink;
use super::sources::Source;

/// A taint flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// The source where tainted data enters.
    pub source: Source,
    /// The sink where tainted data is consumed.
    pub sink: Sink,
    /// Intermediate variable names in the flow.
    pub path: Vec<String>,
    /// Confidence that this flow is exploitable (0.0 - 1.0).
    pub confidence: f64,
    /// Description of the flow.
    pub description: String,
}

/// Taint analyzer that detects data flows from sources to sinks.
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    /// Create a new taint analyzer.
    pub fn new() -> Self {
        Self
    }

    /// Analyze a JavaScript analysis result for taint flows.
    pub fn analyze_flows(&self, analysis: &JsAnalysis) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        // Simple analysis: check if any source and sink exist together
        if !analysis.sources.is_empty() && !analysis.sinks.is_empty() {
            // Create flows for each source-sink pair
            for source in &analysis.sources {
                for sink in &analysis.sinks {
                    let confidence = self.calculate_direct_confidence(source, sink);
                    if confidence > 0.3 {
                        flows.push(TaintFlow {
                            source: source.clone(),
                            sink: sink.clone(),
                            path: Vec::new(),
                            confidence,
                            description: format!(
                                "Potential flow: {} → {}",
                                source.name, sink.name
                            ),
                        });
                    }
                }
            }
        }

        // Sort by confidence (highest first)
        flows.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        flows
    }

    /// Analyze raw JavaScript code for taint flows.
    pub fn analyze_code(&self, code: &str) -> Vec<TaintFlow> {
        let analyzer = super::js_analyzer::JsAnalyzer::new();
        let analysis = analyzer.analyze_js(code);
        self.analyze_flows_with_code(&analysis, code)
    }

    /// Analyze with source code access for better flow tracking.
    pub fn analyze_flows_with_code(&self, analysis: &JsAnalysis, code: &str) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        // Extract variable assignments
        let assignments = self.extract_assignments(code);

        for source in &analysis.sources {
            for sink in &analysis.sinks {
                // Direct flow: source used directly in sink
                if self.has_direct_flow(source, sink, code) {
                    let confidence = self.calculate_direct_confidence(source, sink);
                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        path: Vec::new(),
                        confidence,
                        description: format!(
                            "Direct flow: {} → {}",
                            source.name, sink.name
                        ),
                    });
                    continue;
                }

                // Indirect flow: source → variable → sink
                if let Some(flow) = self.check_indirect_flow(source, sink, &assignments, code) {
                    flows.push(flow);
                }
            }
        }

        // Sort by confidence
        flows.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        flows
    }

    /// Check if a direct flow exists between source and sink.
    fn has_direct_flow(&self, source: &Source, sink: &Sink, code: &str) -> bool {
        // Check if source appears in the same line as sink
        let source_lines: Vec<&str> = code.lines().collect();
        for (i, line) in source_lines.iter().enumerate() {
            let line = line.trim();
            // Check if both source and sink appear on lines near each other
            if line.contains(&source.full_match) {
                // Check surrounding lines (within 3 lines)
                for j in i.saturating_sub(3)..=(i + 3).min(source_lines.len() - 1) {
                    if source_lines[j].contains(&sink.full_match) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Extract variable assignments from code.
    fn extract_assignments(&self, code: &str) -> Vec<(String, String)> {
        let mut assignments = Vec::new();

        // Pattern: var x = source; or let x = source; or const x = source;
        // Or: x = source;
        if let Ok(re) = regex::Regex::new(
            r#"(?:(?:var|let|const)\s+)?(\w+)\s*=\s*([^;]+);"#
        ) {
            for cap in re.captures_iter(code) {
                if let (Some(var), Some(val)) = (cap.get(1), cap.get(2)) {
                    assignments.push((var.as_str().to_string(), val.as_str().trim().to_string()));
                }
            }
        }

        assignments
    }

    /// Check for indirect flow through variables.
    fn check_indirect_flow(
        &self,
        source: &Source,
        sink: &Sink,
        assignments: &[(String, String)],
        code: &str,
    ) -> Option<TaintFlow> {
        // Find variable that receives source
        for (var, value) in assignments {
            if value.contains(&source.full_match) {
                // Check if that variable is used in sink
                if code.contains(var) && code.contains(&sink.full_match) {
                    let confidence = self.calculate_indirect_confidence(source, sink);
                    return Some(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        path: vec![var.clone()],
                        confidence,
                        description: format!(
                            "Indirect flow: {} → {} → {}",
                            source.name, var, sink.name
                        ),
                    });
                }
            }
        }

        None
    }

    /// Calculate confidence for a direct flow.
    fn calculate_direct_confidence(&self, source: &Source, sink: &Sink) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence

        // Higher confidence for user-controlled sources
        if source.user_controlled {
            confidence += 0.3;
        }

        // Higher confidence for critical/high sinks
        match sink.risk {
            super::sinks::SinkRisk::Critical => confidence += 0.2,
            super::sinks::SinkRisk::High => confidence += 0.15,
            super::sinks::SinkRisk::Medium => confidence += 0.1,
            super::sinks::SinkRisk::Low => confidence += 0.05,
        }

        confidence.min(1.0)
    }

    /// Calculate confidence for an indirect flow.
    fn calculate_indirect_confidence(&self, source: &Source, sink: &Sink) -> f64 {
        let mut confidence: f64 = 0.3; // Lower base for indirect

        if source.user_controlled {
            confidence += 0.25;
        }

        match sink.risk {
            super::sinks::SinkRisk::Critical => confidence += 0.2,
            super::sinks::SinkRisk::High => confidence += 0.15,
            super::sinks::SinkRisk::Medium => confidence += 0.1,
            super::sinks::SinkRisk::Low => confidence += 0.05,
        }

        confidence.min(1.0)
    }

    /// Check if a taint flow exists between any source and sink.
    pub fn has_taint_flow(&self, analysis: &JsAnalysis) -> bool {
        !analysis.sources.is_empty() && !analysis.sinks.is_empty()
    }

    /// Get the highest confidence flow.
    pub fn get_highest_risk_flow<'a>(&self, flows: &'a [TaintFlow]) -> Option<&'a TaintFlow> {
        flows.iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::js_analyzer::JsAnalyzer;

    #[test]
    fn detect_direct_flow() {
        let analyzer = TaintAnalyzer::new();
        let code = r#"
            var data = location.hash;
            el.innerHTML = data;
        "#;
        let flows = analyzer.analyze_code(code);
        assert!(!flows.is_empty(), "Should detect direct flow");
        assert!(flows.iter().any(|f| f.source.name == "location.hash"));
        assert!(flows.iter().any(|f| f.sink.name == "innerHTML"));
    }

    #[test]
    fn detect_eval_with_hash() {
        let analyzer = TaintAnalyzer::new();
        let code = "eval(location.hash);";
        let flows = analyzer.analyze_code(code);
        assert!(!flows.is_empty());
        assert!(flows[0].confidence > 0.5);
    }

    #[test]
    fn detect_indirect_flow() {
        let analyzer = TaintAnalyzer::new();
        let code = r#"
            var x = location.search;
            var y = x;
            document.write(y);
        "#;
        let flows = analyzer.analyze_code(code);
        // Should detect at least one flow
        assert!(!flows.is_empty());
    }

    #[test]
    fn no_flow_without_sources() {
        let js_analyzer = JsAnalyzer::new();
        let analysis = js_analyzer.analyze_js("eval('test');");
        let taint = TaintAnalyzer::new();
        let flows = taint.analyze_flows(&analysis);
        assert!(flows.is_empty());
    }

    #[test]
    fn no_flow_without_sinks() {
        let js_analyzer = JsAnalyzer::new();
        let analysis = js_analyzer.analyze_js("var x = location.hash;");
        let taint = TaintAnalyzer::new();
        let flows = taint.analyze_flows(&analysis);
        assert!(flows.is_empty());
    }

    #[test]
    fn confidence_higher_for_user_controlled() {
        let taint = TaintAnalyzer::new();

        // User-controlled source
        let source_high = Source {
            name: "location.hash".to_string(),
            full_match: "location.hash".to_string(),
            line: 1,
            col: 0,
            user_controlled: true,
            risk: super::super::sources::SourceRisk::High,
        };

        // Non-user-controlled source
        let source_low = Source {
            name: "localStorage".to_string(),
            full_match: "localStorage.getItem('x')".to_string(),
            line: 1,
            col: 0,
            user_controlled: false,
            risk: super::super::sources::SourceRisk::Low,
        };

        let sink = Sink {
            name: "eval".to_string(),
            full_match: "eval(x)".to_string(),
            line: 2,
            col: 0,
            risk: super::super::sinks::SinkRisk::Critical,
            category: super::super::sinks::SinkCategory::CodeExecution,
        };

        let conf_high = taint.calculate_direct_confidence(&source_high, &sink);
        let conf_low = taint.calculate_direct_confidence(&source_low, &sink);

        assert!(conf_high > conf_low);
    }

    #[test]
    fn highest_risk_flow() {
        let taint = TaintAnalyzer::new();
        let flows = vec![
            TaintFlow {
                source: Source {
                    name: "a".to_string(),
                    full_match: "a".to_string(),
                    line: 1,
                    col: 0,
                    user_controlled: false,
                    risk: super::super::sources::SourceRisk::Low,
                },
                sink: Sink {
                    name: "b".to_string(),
                    full_match: "b".to_string(),
                    line: 2,
                    col: 0,
                    risk: super::super::sinks::SinkRisk::Low,
                    category: super::super::sinks::SinkCategory::CodeExecution,
                },
                path: Vec::new(),
                confidence: 0.3,
                description: "low".to_string(),
            },
            TaintFlow {
                source: Source {
                    name: "c".to_string(),
                    full_match: "c".to_string(),
                    line: 3,
                    col: 0,
                    user_controlled: true,
                    risk: super::super::sources::SourceRisk::High,
                },
                sink: Sink {
                    name: "d".to_string(),
                    full_match: "d".to_string(),
                    line: 4,
                    col: 0,
                    risk: super::super::sinks::SinkRisk::Critical,
                    category: super::super::sinks::SinkCategory::CodeExecution,
                },
                path: Vec::new(),
                confidence: 0.9,
                description: "high".to_string(),
            },
        ];

        let highest = taint.get_highest_risk_flow(&flows).unwrap();
        assert_eq!(highest.confidence, 0.9);
    }

    #[test]
    fn extract_assignments() {
        let taint = TaintAnalyzer::new();
        let code = r#"
            var x = location.hash;
            let y = document.URL;
            const z = "safe";
        "#;
        let assignments = taint.extract_assignments(code);
        assert!(assignments.iter().any(|(v, _)| v == "x"));
        assert!(assignments.iter().any(|(v, _)| v == "y"));
        assert!(assignments.iter().any(|(v, _)| v == "z"));
    }

    #[test]
    fn flows_sorted_by_confidence() {
        let taint = TaintAnalyzer::new();
        let code = r#"
            var a = location.hash;
            eval(a);
            var b = localStorage.getItem('x');
            document.write(b);
        "#;
        let flows = taint.analyze_code(code);
        if flows.len() > 1 {
            for i in 0..flows.len() - 1 {
                assert!(flows[i].confidence >= flows[i + 1].confidence);
            }
        }
    }
}

/// Sink database for DOM XSS detection.
///
/// Sinks are dangerous JavaScript functions/methods that can execute
/// or render untrusted data, leading to XSS vulnerabilities.

/// Risk level for a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SinkRisk {
    /// Direct code execution (eval, Function, setTimeout with string).
    Critical,
    /// HTML injection (innerHTML, document.write).
    High,
    /// Navigation/redirect (location.href, window.open).
    Medium,
    /// Attribute injection (element.src, element.href).
    Low,
}

/// A detected sink in JavaScript code.
#[derive(Debug, Clone)]
pub struct Sink {
    /// The sink function/method name.
    pub name: String,
    /// Full match from the regex.
    pub full_match: String,
    /// Line number (approximate, from byte offset).
    pub line: usize,
    /// Column number.
    pub col: usize,
    /// Risk level.
    pub risk: SinkRisk,
    /// Category of the sink.
    pub category: SinkCategory,
}

/// Category of sink for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkCategory {
    /// Direct code execution.
    CodeExecution,
    /// HTML/DOM injection.
    HtmlInjection,
    /// Navigation manipulation.
    Navigation,
    /// Attribute manipulation.
    AttributeInjection,
    /// Dynamic code generation.
    DynamicCode,
}

/// Get all sink patterns with their risk levels.
pub fn get_all_sinks() -> Vec<SinkPattern> {
    let mut sinks = Vec::new();

    // ─── Critical: Direct Code Execution ───
    sinks.extend(vec![
        SinkPattern {
            name: "eval".to_string(),
            pattern: r#"(?i)\beval\s*\("#.to_string(),
            risk: SinkRisk::Critical,
            category: SinkCategory::CodeExecution,
        },
        SinkPattern {
            name: "Function".to_string(),
            pattern: r#"(?i)\bnew\s+Function\s*\("#.to_string(),
            risk: SinkRisk::Critical,
            category: SinkCategory::CodeExecution,
        },
        SinkPattern {
            name: "setTimeout".to_string(),
            pattern: r#"(?i)\bsetTimeout\s*\(\s*["']"#.to_string(),
            risk: SinkRisk::Critical,
            category: SinkCategory::CodeExecution,
        },
        SinkPattern {
            name: "setInterval".to_string(),
            pattern: r#"(?i)\bsetInterval\s*\(\s*["']"#.to_string(),
            risk: SinkRisk::Critical,
            category: SinkCategory::CodeExecution,
        },
        SinkPattern {
            name: "execScript".to_string(),
            pattern: r#"(?i)\bexecScript\s*\("#.to_string(),
            risk: SinkRisk::Critical,
            category: SinkCategory::CodeExecution,
        },
    ]);

    // ─── High: HTML/DOM Injection ───
    sinks.extend(vec![
        SinkPattern {
            name: "innerHTML".to_string(),
            pattern: r#"(?i)\.innerHTML\s*="#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "outerHTML".to_string(),
            pattern: r#"(?i)\.outerHTML\s*="#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "insertAdjacentHTML".to_string(),
            pattern: r#"(?i)\.insertAdjacentHTML\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "document.write".to_string(),
            pattern: r#"(?i)\bdocument\.write\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "document.writeln".to_string(),
            pattern: r#"(?i)\bdocument\.writeln\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "jQuery.html".to_string(),
            pattern: r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.html\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "jQuery.append".to_string(),
            pattern: r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.append\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "jQuery.prepend".to_string(),
            pattern: r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.prepend\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "jQuery.after".to_string(),
            pattern: r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.after\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
        SinkPattern {
            name: "jQuery.before".to_string(),
            pattern: r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.before\s*\("#.to_string(),
            risk: SinkRisk::High,
            category: SinkCategory::HtmlInjection,
        },
    ]);

    // ─── Medium: Navigation Manipulation ───
    sinks.extend(vec![
        SinkPattern {
            name: "location.href".to_string(),
            pattern: r#"(?i)\blocation\.href\s*="#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
        SinkPattern {
            name: "location.assign".to_string(),
            pattern: r#"(?i)\blocation\.assign\s*\("#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
        SinkPattern {
            name: "location.replace".to_string(),
            pattern: r#"(?i)\blocation\.replace\s*\("#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
        SinkPattern {
            name: "window.open".to_string(),
            pattern: r#"(?i)\bwindow\.open\s*\("#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
        SinkPattern {
            name: "document.location".to_string(),
            pattern: r#"(?i)\bdocument\.location\s*="#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
        SinkPattern {
            name: "window.location".to_string(),
            pattern: r#"(?i)\bwindow\.location\s*="#.to_string(),
            risk: SinkRisk::Medium,
            category: SinkCategory::Navigation,
        },
    ]);

    // ─── Low: Attribute Injection ───
    sinks.extend(vec![
        SinkPattern {
            name: "element.src".to_string(),
            pattern: r#"(?i)\.src\s*="#.to_string(),
            risk: SinkRisk::Low,
            category: SinkCategory::AttributeInjection,
        },
        SinkPattern {
            name: "element.href".to_string(),
            pattern: r#"(?i)\.href\s*="#.to_string(),
            risk: SinkRisk::Low,
            category: SinkCategory::AttributeInjection,
        },
        SinkPattern {
            name: "element.action".to_string(),
            pattern: r#"(?i)\.action\s*="#.to_string(),
            risk: SinkRisk::Low,
            category: SinkCategory::AttributeInjection,
        },
        SinkPattern {
            name: "element.formAction".to_string(),
            pattern: r#"(?i)\.formAction\s*="#.to_string(),
            risk: SinkRisk::Low,
            category: SinkCategory::AttributeInjection,
        },
        SinkPattern {
            name: "element.setAttribute".to_string(),
            pattern: r#"(?i)\.setAttribute\s*\(\s*["'](?:src|href|action|formaction|data|code|dynsrc|lowsrc)["']"#.to_string(),
            risk: SinkRisk::Low,
            category: SinkCategory::AttributeInjection,
        },
    ]);

    sinks
}

/// A sink pattern definition.
#[derive(Debug, Clone)]
pub struct SinkPattern {
    /// Human-readable name.
    pub name: String,
    /// Regex pattern to match the sink.
    pub pattern: String,
    /// Risk level.
    pub risk: SinkRisk,
    /// Category.
    pub category: SinkCategory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_critical_sinks() {
        let sinks = get_all_sinks();
        let critical: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.risk == SinkRisk::Critical)
            .collect();
        assert!(critical.len() >= 5, "Should have at least 5 critical sinks");
    }

    #[test]
    fn has_high_sinks() {
        let sinks = get_all_sinks();
        let high: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.risk == SinkRisk::High)
            .collect();
        assert!(high.len() >= 5, "Should have at least 5 high-risk sinks");
    }

    #[test]
    fn has_medium_sinks() {
        let sinks = get_all_sinks();
        let medium: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.risk == SinkRisk::Medium)
            .collect();
        assert!(
            medium.len() >= 3,
            "Should have at least 3 medium-risk sinks"
        );
    }

    #[test]
    fn has_low_sinks() {
        let sinks = get_all_sinks();
        let low: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.risk == SinkRisk::Low)
            .collect();
        assert!(low.len() >= 3, "Should have at least 3 low-risk sinks");
    }

    #[test]
    fn all_patterns_are_valid_regex() {
        let sinks = get_all_sinks();
        for sink in &sinks {
            assert!(
                regex::Regex::new(&sink.pattern).is_ok(),
                "Invalid regex for sink '{}': {}",
                sink.name,
                sink.pattern
            );
        }
    }

    #[test]
    fn eval_sink_matches_example() {
        let re = regex::Regex::new(r#"(?i)\beval\s*\("#).unwrap();
        assert!(re.is_match("eval('alert(1)')"));
        assert!(re.is_match("eval ( 'code' )"));
        assert!(!re.is_match("evaluation"));
    }

    #[test]
    fn innerhtml_sink_matches_example() {
        let re = regex::Regex::new(r#"(?i)\.innerHTML\s*="#).unwrap();
        assert!(re.is_match("el.innerHTML = '<img src=x>'"));
        assert!(re.is_match("element.innerHTML=test"));
        assert!(!re.is_match("innerHTML"));
    }

    #[test]
    fn jquery_html_sink_matches() {
        let re = regex::Regex::new(r#"(?i)(?:jQuery|\$)\s*\([^)]*\)\s*\.html\s*\("#).unwrap();
        assert!(re.is_match("$('#el').html('<b>test</b>')"));
        assert!(re.is_match("jQuery('#el').html(data)"));
        assert!(!re.is_match(".html('test')"));
    }

    #[test]
    fn sink_categories_are_correct() {
        let sinks = get_all_sinks();
        let code_exec: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.category == SinkCategory::CodeExecution)
            .collect();
        assert!(!code_exec.is_empty());

        let html_inj: Vec<&SinkPattern> = sinks
            .iter()
            .filter(|s| s.category == SinkCategory::HtmlInjection)
            .collect();
        assert!(!html_inj.is_empty());
    }
}

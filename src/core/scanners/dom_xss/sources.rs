/// Source database for DOM XSS detection.
///
/// Sources are locations where untrusted user input can enter the DOM,
/// potentially leading to XSS if the data reaches a dangerous sink.

/// A detected source in JavaScript code.
#[derive(Debug, Clone)]
pub struct Source {
    /// The source API name.
    pub name: String,
    /// Full match from the regex.
    pub full_match: String,
    /// Line number (approximate).
    pub line: usize,
    /// Column number.
    pub col: usize,
    /// Whether this source is directly user-controlled.
    pub user_controlled: bool,
    /// Risk level.
    pub risk: SourceRisk,
}

/// Risk level for a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceRisk {
    /// Directly controlled by attacker (URL hash, query, window.name).
    High,
    /// Can be influenced by attacker (referrer, cookies).
    Medium,
    /// Potentially tainted (localStorage, sessionStorage).
    Low,
}

/// A source pattern definition.
#[derive(Debug, Clone)]
pub struct SourcePattern {
    /// Human-readable name.
    pub name: String,
    /// Regex pattern to match the source.
    pub pattern: String,
    /// Whether directly user-controlled.
    pub user_controlled: bool,
    /// Risk level.
    pub risk: SourceRisk,
}

/// Get all source patterns.
pub fn get_all_sources() -> Vec<SourcePattern> {
    let mut sources = Vec::new();

    // ─── High Risk: Directly User-Controlled ───
    sources.extend(vec![
        SourcePattern {
            name: "location.hash".to_string(),
            pattern: r#"(?i)\blocation\.hash"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "location.search".to_string(),
            pattern: r#"(?i)\blocation\.search"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "location.href".to_string(),
            pattern: r#"(?i)\blocation\.href"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "document.URL".to_string(),
            pattern: r#"(?i)\bdocument\.URL"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "document.documentURI".to_string(),
            pattern: r#"(?i)\bdocument\.documentURI"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "window.name".to_string(),
            pattern: r#"(?i)\bwindow\.name"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "document.baseURI".to_string(),
            pattern: r#"(?i)\bdocument\.baseURI"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
        SourcePattern {
            name: "location.origin".to_string(),
            pattern: r#"(?i)\blocation\.origin"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::High,
        },
    ]);

    // ─── Medium Risk: Attacker-Influenced ───
    sources.extend(vec![
        SourcePattern {
            name: "document.referrer".to_string(),
            pattern: r#"(?i)\bdocument\.referrer"#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Medium,
        },
        SourcePattern {
            name: "document.cookie".to_string(),
            pattern: r#"(?i)\bdocument\.cookie"#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Medium,
        },
        SourcePattern {
            name: "postMessage".to_string(),
            pattern: r#"(?i)\baddEventListener\s*\(\s*["']message["']"#.to_string(),
            user_controlled: true,
            risk: SourceRisk::Medium,
        },
        SourcePattern {
            name: "onmessage".to_string(),
            pattern: r#"(?i)\bonmessage\s*="#.to_string(),
            user_controlled: true,
            risk: SourceRisk::Medium,
        },
        SourcePattern {
            name: "XMLHttpRequest.response".to_string(),
            pattern: r#"(?i)\.response(?:Text)?\b"#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Medium,
        },
        SourcePattern {
            name: "fetch.response".to_string(),
            pattern: r#"(?i)\bfetch\s*\([^)]*\)(?:\s*\.then\s*\([^)]*\)\s*\.then\s*\([^)]*\))?"#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Medium,
        },
    ]);

    // ─── Low Risk: Client-Side Storage ───
    sources.extend(vec![
        SourcePattern {
            name: "localStorage".to_string(),
            pattern: r#"(?i)\blocalStorage\.getItem\s*\("#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Low,
        },
        SourcePattern {
            name: "sessionStorage".to_string(),
            pattern: r#"(?i)\bsessionStorage\.getItem\s*\("#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Low,
        },
        SourcePattern {
            name: "localStorage (bracket)".to_string(),
            pattern: r#"(?i)\blocalStorage\s*\["#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Low,
        },
        SourcePattern {
            name: "sessionStorage (bracket)".to_string(),
            pattern: r#"(?i)\bsessionStorage\s*\["#.to_string(),
            user_controlled: false,
            risk: SourceRisk::Low,
        },
    ]);

    sources
}

/// Check if a JavaScript expression contains a known source.
pub fn find_sources_in_code(code: &str) -> Vec<Source> {
    let patterns = get_all_sources();
    let mut sources = Vec::new();

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(&pattern.pattern) {
            for mat in re.find_iter(code) {
                let before = &code[..mat.start()];
                let line = before.lines().count();
                let col = before.rfind('\n').map_or(mat.start(), |pos| mat.start() - pos - 1);

                sources.push(Source {
                    name: pattern.name.clone(),
                    full_match: mat.as_str().to_string(),
                    line,
                    col,
                    user_controlled: pattern.user_controlled,
                    risk: pattern.risk,
                });
            }
        }
    }

    // Deduplicate by name + line
    sources.sort_by(|a, b| a.name.cmp(&b.name).then(a.line.cmp(&b.line)));
    sources.dedup_by(|a, b| a.name == b.name && a.line == b.line);

    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_high_risk_sources() {
        let sources = get_all_sources();
        let high: Vec<&SourcePattern> = sources
            .iter()
            .filter(|s| s.risk == SourceRisk::High)
            .collect();
        assert!(high.len() >= 5, "Should have at least 5 high-risk sources");
    }

    #[test]
    fn has_medium_risk_sources() {
        let sources = get_all_sources();
        let medium: Vec<&SourcePattern> = sources
            .iter()
            .filter(|s| s.risk == SourceRisk::Medium)
            .collect();
        assert!(
            medium.len() >= 3,
            "Should have at least 3 medium-risk sources"
        );
    }

    #[test]
    fn all_patterns_are_valid_regex() {
        let sources = get_all_sources();
        for source in &sources {
            assert!(
                regex::Regex::new(&source.pattern).is_ok(),
                "Invalid regex for source '{}': {}",
                source.name,
                source.pattern
            );
        }
    }

    #[test]
    fn location_hash_is_user_controlled() {
        let sources = get_all_sources();
        let hash = sources.iter().find(|s| s.name == "location.hash").unwrap();
        assert!(hash.user_controlled);
        assert_eq!(hash.risk, SourceRisk::High);
    }

    #[test]
    fn find_sources_in_code_detects_hash() {
        let code = r#"
            var hash = location.hash;
            var search = location.search;
        "#;
        let found = find_sources_in_code(code);
        assert!(found.iter().any(|s| s.name == "location.hash"));
        assert!(found.iter().any(|s| s.name == "location.search"));
    }

    #[test]
    fn find_sources_in_code_detects_document_url() {
        let code = "var url = document.URL;";
        let found = find_sources_in_code(code);
        assert!(found.iter().any(|s| s.name == "document.URL"));
    }

    #[test]
    fn find_sources_in_code_detects_window_name() {
        let code = "var name = window.name;";
        let found = find_sources_in_code(code);
        assert!(found.iter().any(|s| s.name == "window.name"));
    }

    #[test]
    fn find_sources_in_code_ignores_safe_code() {
        let code = "var x = 42; console.log('hello');";
        let found = find_sources_in_code(code);
        assert!(found.is_empty());
    }

    #[test]
    fn find_sources_deduplicates() {
        let code = "var a = location.hash; var b = location.hash;";
        let found = find_sources_in_code(code);
        let hash_count = found.iter().filter(|s| s.name == "location.hash").count();
        assert_eq!(hash_count, 1, "Should deduplicate same source on same line");
    }
}

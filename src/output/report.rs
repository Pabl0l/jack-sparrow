#![allow(dead_code)]

use crate::shared::types::{ScanResults, Severity, VulnerabilityType};
use std::fmt::Write;
use std::path::Path;

/// Supported report formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Html,
    Markdown,
    Csv,
}

impl ReportFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(ReportFormat::Json),
            "html" => Some(ReportFormat::Html),
            "markdown" | "md" => Some(ReportFormat::Markdown),
            "csv" => Some(ReportFormat::Csv),
            _ => None,
        }
    }

    pub fn extension(&self) -> &str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "md",
            ReportFormat::Csv => "csv",
        }
    }
}

/// Auto-calculate CVSS score based on vulnerability type and severity
pub fn auto_cvss(vuln_type: &VulnerabilityType, severity: &Severity) -> Option<f64> {
    let base = match vuln_type {
        VulnerabilityType::SqlInjection => 8.6,
        VulnerabilityType::XssReflected => 6.1,
        VulnerabilityType::XssStored => 8.0,
        VulnerabilityType::XssDom => 5.4,
        VulnerabilityType::Idor => 7.5,
        VulnerabilityType::Ssrf => 8.5,
        VulnerabilityType::SupplyChainDependency => 7.0,
        VulnerabilityType::SupplyChainMalicious => 9.0,
        VulnerabilityType::SecurityHeader => 3.0,
        VulnerabilityType::TechFingerprint => 0.0,
        VulnerabilityType::SecretExposed => 7.5,
        VulnerabilityType::SubdomainFound => 0.0,
        VulnerabilityType::WafDetected => 0.0,
        VulnerabilityType::JwtIssue => 5.0,
        VulnerabilityType::GraphQLIntrospection => 5.3,
        VulnerabilityType::ApiSecurity => 5.3,
        VulnerabilityType::Xxe => 8.5,
        VulnerabilityType::Ssti => 9.8,
        VulnerabilityType::FormInjection => 8.6,
        VulnerabilityType::Csrf => 8.0,
        VulnerabilityType::FileUpload => 8.0,
    };

    // Adjust based on severity
    let factor = match severity {
        Severity::Critical => 1.0,
        Severity::High => 0.9,
        Severity::Medium => 0.7,
        Severity::Low => 0.4,
        Severity::Info => 0.0,
    };

    let score = base * factor;
    if score > 0.0 {
        Some((score * 10.0_f64).round() / 10.0_f64)
    } else {
        None
    }
}

/// Get specific remediation advice based on vulnerability type
pub fn specific_remediation(vuln_type: &VulnerabilityType) -> &'static str {
    match vuln_type {
        VulnerabilityType::SqlInjection => "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Implement input validation and use ORM when possible.",
        VulnerabilityType::XssReflected => "Encode all user input before rendering in HTML. Use Content-Security-Policy headers. Implement input validation and output encoding.",
        VulnerabilityType::XssStored => "Sanitize all user input before storage. Use Content-Security-Policy headers. Implement output encoding and use templating engines with auto-escaping.",
        VulnerabilityType::XssDom => "Avoid using innerHTML, document.write, and eval with user input. Use textContent instead. Implement DOMPurify for HTML sanitization.",
        VulnerabilityType::Idor => "Implement proper authorization checks for every object access. Use indirect object references (maps) instead of direct IDs. Validate user permissions.",
        VulnerabilityType::Ssrf => "Validate and sanitize all URL inputs. Use allowlists for permitted domains. Block requests to internal networks (RFC 1918). Use network segmentation.",
        VulnerabilityType::SupplyChainDependency => "Keep all dependencies updated. Use lock files. Implement automated vulnerability scanning in CI/CD. Review dependency permissions.",
        VulnerabilityType::SupplyChainMalicious => "Verify package integrity with checksums. Use private registries. Review package sources and maintainers. Implement dependency firewalls.",
        VulnerabilityType::SecurityHeader => "Implement all recommended security headers. Use tools like securityheaders.com to verify configuration. Regularly audit header settings.",
        VulnerabilityType::TechFingerprint => "Review technology stack for known vulnerabilities. Keep all components updated. Remove unnecessary technology disclosures.",
        VulnerabilityType::SecretExposed => "Remove all hardcoded secrets from source code. Use environment variables or secret management services. Rotate exposed credentials immediately.",
        VulnerabilityType::SubdomainFound => "Review discovered subdomains for exposed services, development environments, or misconfigured access controls. Ensure all subdomains are behind appropriate authentication.",
        VulnerabilityType::WafDetected => "This is informational. WAF detection helps tune subsequent vulnerability scanning to use appropriate bypass techniques.",
        VulnerabilityType::JwtIssue => "Validate JWT tokens server-side. Reject tokens with weak algorithms (none, HS1). Use strong secrets or asymmetric algorithms (RS256/ES256). Set short expiration times.",
        VulnerabilityType::GraphQLIntrospection => "Disable GraphQL introspection in production. Restrict it to authenticated/admin users. Use persisted queries or schema stitching. Implement proper authorization on all resolvers.",
        VulnerabilityType::ApiSecurity => "Implement proper authentication and authorization on all API endpoints. Use CORS allowlists. Disable TRACE method. Replace verbose error messages with generic responses. Add rate limiting.",
        VulnerabilityType::Xxe => "Disable XML external entity processing. Use JSON instead of XML where possible. Configure XML parsers to disallow DTDs and external entities. Implement input validation.",
        VulnerabilityType::Ssti => "Never render user input in templates. Use sandboxed template environments. Implement auto-escaping. Validate and sanitize all user input. Use whitelisting for allowed template syntax.",
        VulnerabilityType::FormInjection => "Use parameterized queries for SQL. Encode output for XSS. Sanitize input for SSTI. Validate all form inputs server-side.",
        VulnerabilityType::Csrf => "Add CSRF tokens to all state-changing forms. Validate tokens server-side. Use SameSite cookies. Check Origin/Referer headers.",
        VulnerabilityType::FileUpload => "Validate file extensions against an allowlist. Validate Content-Type from file content. Store uploads outside web root. Use random filenames. Scan with antivirus.",
    }
}

/// Write report to file
pub fn write_report(
    results: &ScanResults,
    format: ReportFormat,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = generate_report(results, format)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// Write report in multiple formats simultaneously
pub fn write_reports(
    results: &ScanResults,
    formats: &[ReportFormat],
    base_path: &Path,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut written = Vec::new();

    for format in formats {
        let ext = format.extension();
        let path = base_path.with_extension(ext);
        write_report(results, *format, &path)?;
        written.push(path);
    }

    Ok(written)
}

/// Apply auto-CVSS and specific remediation to findings
pub fn enrich_findings(results: &mut ScanResults) {
    for finding in &mut results.findings {
        // Auto-fill CVSS if missing
        if finding.cvss_score.is_none() {
            finding.cvss_score = auto_cvss(&finding.vulnerability_type, &finding.severity);
        }

        // Auto-fill CWE if missing
        if finding.cwe_id.is_none() {
            finding.cwe_id = default_cwe(&finding.vulnerability_type);
        }

        // Use specific remediation if empty
        if finding.remediation.is_empty() {
            finding.remediation = specific_remediation(&finding.vulnerability_type).to_string();
        }
    }
}

/// Default CWE for each vulnerability type
fn default_cwe(vuln_type: &VulnerabilityType) -> Option<String> {
    let cwe = match vuln_type {
        VulnerabilityType::SqlInjection => "CWE-89",
        VulnerabilityType::XssReflected => "CWE-79",
        VulnerabilityType::XssStored => "CWE-79",
        VulnerabilityType::XssDom => "CWE-79",
        VulnerabilityType::Idor => "CWE-639",
        VulnerabilityType::Ssrf => "CWE-918",
        VulnerabilityType::SupplyChainDependency => "CWE-1395",
        VulnerabilityType::SupplyChainMalicious => "CWE-506",
        VulnerabilityType::SecurityHeader => "CWE-693",
        VulnerabilityType::TechFingerprint => "CWE-200",
        VulnerabilityType::SecretExposed => "CWE-798",
        VulnerabilityType::SubdomainFound => "CWE-200",
        VulnerabilityType::WafDetected => "CWE-16",
        VulnerabilityType::JwtIssue => "CWE-327",
        VulnerabilityType::GraphQLIntrospection => "CWE-200",
        VulnerabilityType::ApiSecurity => "CWE-284",
        VulnerabilityType::Xxe => "CWE-611",
        VulnerabilityType::Ssti => "CWE-1336",
        VulnerabilityType::FormInjection => "CWE-89",
        VulnerabilityType::Csrf => "CWE-352",
        VulnerabilityType::FileUpload => "CWE-434",
    };
    Some(cwe.to_string())
}

/// Generate a report in the specified format
pub fn generate_report(
    results: &ScanResults,
    format: ReportFormat,
) -> Result<String, std::fmt::Error> {
    match format {
        ReportFormat::Json => generate_json(results),
        ReportFormat::Html => generate_html(results),
        ReportFormat::Markdown => generate_markdown(results),
        ReportFormat::Csv => generate_csv(results),
    }
}

/// Generate JSON report
fn generate_json(results: &ScanResults) -> Result<String, std::fmt::Error> {
    serde_json::to_string_pretty(results).map_err(|_| std::fmt::Error)
}

/// Generate CSV report
fn generate_csv(results: &ScanResults) -> Result<String, std::fmt::Error> {
    let mut csv = String::with_capacity(1024);

    // Header
    writeln!(
        csv,
        "Severity,Type,Title,URL,Parameter,Tool,CWE,CVSS,Description,Remediation"
    )?;

    // Sort findings by severity
    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by_key(|a| std::cmp::Reverse(a.severity.rank()));

    for finding in &sorted_findings {
        let vuln_type = match &finding.vulnerability_type {
            VulnerabilityType::SqlInjection => "SQL Injection",
            VulnerabilityType::XssReflected => "Reflected XSS",
            VulnerabilityType::XssStored => "Stored XSS",
            VulnerabilityType::XssDom => "DOM XSS",
            VulnerabilityType::Idor => "IDOR",
            VulnerabilityType::Ssrf => "SSRF",
            VulnerabilityType::SupplyChainDependency => "Dependency Vulnerability",
            VulnerabilityType::SupplyChainMalicious => "Malicious Package",
            VulnerabilityType::SecurityHeader => "Security Header",
            VulnerabilityType::TechFingerprint => "Technology Fingerprint",
            VulnerabilityType::SecretExposed => "Exposed Secret",
            VulnerabilityType::SubdomainFound => "Subdomain Discovered",
            VulnerabilityType::WafDetected => "WAF Detected",
            VulnerabilityType::JwtIssue => "JWT Issue",
            VulnerabilityType::GraphQLIntrospection => "GraphQL Introspection",
            VulnerabilityType::ApiSecurity => "API Security",
            VulnerabilityType::Xxe => "XML External Entity",
            VulnerabilityType::Ssti => "Server-Side Template Injection",
            VulnerabilityType::FormInjection => "Form Injection",
            VulnerabilityType::Csrf => "Cross-Site Request Forgery",
            VulnerabilityType::FileUpload => "Unrestricted File Upload",
        };

        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{}",
            escape_csv(&finding.severity.to_string()),
            escape_csv(vuln_type),
            escape_csv(&finding.title),
            escape_csv(&finding.url),
            escape_csv(finding.parameter.as_deref().unwrap_or("")),
            escape_csv(&finding.tool_source),
            escape_csv(finding.cwe_id.as_deref().unwrap_or("")),
            escape_csv(&finding.cvss_score.map_or_else(|| String::new(), |v| v.to_string())),
            escape_csv(&finding.description),
            escape_csv(&finding.remediation),
        )?;
    }

    Ok(csv)
}

/// Escape a value for CSV (wrap in quotes if contains comma, quote, or newline)
fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Generate HTML report
fn generate_html(results: &ScanResults) -> Result<String, std::fmt::Error> {
    let counts = results.count_by_severity();
    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let high = counts.get(&Severity::High).unwrap_or(&0);
    let medium = counts.get(&Severity::Medium).unwrap_or(&0);
    let low = counts.get(&Severity::Low).unwrap_or(&0);
    let info = counts.get(&Severity::Info).unwrap_or(&0);

    let mut html = String::with_capacity(4096);

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jack Sparrow Report - {}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --critical: #f85149;
            --high: #f85149;
            --medium: #d29922;
            --low: #388bfd;
            --info: #8b949e;
            --green: #3fb950;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
            color: #f0f6fc;
        }}
        h2 {{
            font-size: 1.3rem;
            margin: 2rem 0 1rem;
            color: #f0f6fc;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }}
        .meta {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .stat-card .label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .critical {{ color: var(--critical); }}
        .high {{ color: var(--high); }}
        .medium {{ color: var(--medium); }}
        .low {{ color: var(--low); }}
        .info {{ color: var(--info); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #21262d;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            color: var(--text-muted);
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-critical {{ background: rgba(248,81,73,0.15); color: var(--critical); }}
        .badge-high {{ background: rgba(248,81,73,0.15); color: var(--high); }}
        .badge-medium {{ background: rgba(210,153,34,0.15); color: var(--medium); }}
        .badge-low {{ background: rgba(56,139,253,0.15); color: var(--low); }}
        .badge-info {{ background: rgba(139,148,158,0.15); color: var(--info); }}
        .finding-detail {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.2rem;
            margin-bottom: 1rem;
        }}
        .finding-detail h3 {{
            font-size: 1rem;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .finding-detail p {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }}
        .finding-detail .meta-row {{
            display: flex;
            gap: 1.5rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .finding-detail code {{
            background: #21262d;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}
        .footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.8rem;
            text-align: center;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0.5cm; }}
            .stat-card {{ border: 1px solid #ccc; }}
            .finding-detail {{ border: 1px solid #ccc; break-inside: avoid; }}
            table {{ border: 1px solid #ccc; }}
            th, td {{ border-bottom: 1px solid #ddd; }}
            th {{ background: #f0f0f0; color: #333; }}
            .badge-critical {{ background: #fee; color: #c00; }}
            .badge-high {{ background: #fee; color: #c00; }}
            .badge-medium {{ background: #ffc; color: #900; }}
            .badge-low {{ background: #eef; color: #06c; }}
            .badge-info {{ background: #f5f5f5; color: #666; }}
            h1, h2 {{ color: #000; }}
            a {{ color: #000; text-decoration: underline; }}
            .footer {{ border-top: 1px solid #ccc; color: #666; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Jack Sparrow Security Report</h1>
        <div class="meta">
            Target: <strong>{}</strong> &mdash;
            Scanned: <strong>{}</strong> &mdash;
            Duration: <strong>{}ms</strong> &mdash;
            Tools: <strong>{}</strong>
        </div>

        <div class="summary-grid">
            <div class="stat-card">
                <div class="number critical">{}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number high">{}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number medium">{}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number low">{}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card">
                <div class="number info">{}</div>
                <div class="label">Info</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: var(--green);">{}</div>
                <div class="label">Total</div>
            </div>
        </div>

        <h2>Findings ({} total)</h2>
"#,
        results.target,
        results.target,
        results.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        results.scan_duration_ms,
        results.tools_used.join(", "),
        critical,
        high,
        medium,
        low,
        info,
        results.findings.len(),
        results.findings.len(),
    )?;

    // Sort findings by severity
    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by_key(|a| std::cmp::Reverse(a.severity.rank()));

    for finding in &sorted_findings {
        let badge_class = match finding.severity {
            Severity::Critical => "badge-critical",
            Severity::High => "badge-high",
            Severity::Medium => "badge-medium",
            Severity::Low => "badge-low",
            Severity::Info => "badge-info",
        };

        let vuln_type = match &finding.vulnerability_type {
            VulnerabilityType::SqlInjection => "SQL Injection",
            VulnerabilityType::XssReflected => "Reflected XSS",
            VulnerabilityType::XssStored => "Stored XSS",
            VulnerabilityType::XssDom => "DOM XSS",
            VulnerabilityType::Idor => "IDOR",
            VulnerabilityType::Ssrf => "SSRF",
            VulnerabilityType::SupplyChainDependency => "Dependency Vulnerability",
            VulnerabilityType::SupplyChainMalicious => "Malicious Package",
            VulnerabilityType::SecurityHeader => "Security Header",
            VulnerabilityType::TechFingerprint => "Technology Fingerprint",
            VulnerabilityType::SecretExposed => "Exposed Secret",
            VulnerabilityType::SubdomainFound => "Subdomain Discovered",
            VulnerabilityType::WafDetected => "WAF Detected",
            VulnerabilityType::JwtIssue => "JWT Issue",
            VulnerabilityType::GraphQLIntrospection => "GraphQL Introspection",
            VulnerabilityType::ApiSecurity => "API Security",
            VulnerabilityType::Xxe => "XML External Entity",
            VulnerabilityType::Ssti => "Server-Side Template Injection",
            VulnerabilityType::FormInjection => "Form Injection",
            VulnerabilityType::Csrf => "Cross-Site Request Forgery",
            VulnerabilityType::FileUpload => "Unrestricted File Upload",
        };

        write!(
            html,
            r#"
        <div class="finding-detail">
            <h3>
                <span class="badge {badge_class}">{severity}</span>
                {title}
            </h3>
            <p>{description}</p>
            <div class="meta-row">
                <span>Type: {vuln_type}</span>
                <span>URL: <code>{url}</code></span>
                {parameter}
                <span>Tool: {tool}</span>
                {cwe}
                {cvss}
            </div>
            {remediation}
        </div>"#,
            badge_class = badge_class,
            severity = finding.severity,
            title = finding.title,
            description = if finding.description.is_empty() {
                "No description provided."
            } else {
                &finding.description
            },
            vuln_type = vuln_type,
            url = finding.url,
            parameter = if let Some(ref p) = finding.parameter {
                format!("<span>Parameter: <code>{}</code></span>", p)
            } else {
                String::new()
            },
            tool = finding.tool_source,
            cwe = if let Some(ref cwe) = finding.cwe_id {
                format!("<span>CWE: <code>{}</code></span>", cwe)
            } else {
                String::new()
            },
            cvss = if let Some(cvss) = finding.cvss_score {
                format!("<span>CVSS: <code>{}</code></span>", cvss)
            } else {
                String::new()
            },
            remediation = if !finding.remediation.is_empty() {
                format!(
                    "<p><strong>Remediation:</strong> {}</p>",
                    finding.remediation
                )
            } else {
                String::new()
            },
        )?;
    }

    if results.findings.is_empty() {
        write!(
            html,
            r#"
        <div class="finding-detail">
            <h3 style="color: var(--green);">No vulnerabilities detected</h3>
            <p>The scan completed without finding any security issues.</p>
        </div>"#
        )?;
    }

    write!(
        html,
        r#"
        <div class="footer">
            Generated by Jack Sparrow v0.4.0 &mdash; {timestamp}
        </div>
    </div>
</body>
</html>"#,
        timestamp = results.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
    )?;

    Ok(html)
}

/// Generate Markdown report
fn generate_markdown(results: &ScanResults) -> Result<String, std::fmt::Error> {
    let counts = results.count_by_severity();
    let critical = counts.get(&Severity::Critical).unwrap_or(&0);
    let high = counts.get(&Severity::High).unwrap_or(&0);
    let medium = counts.get(&Severity::Medium).unwrap_or(&0);
    let low = counts.get(&Severity::Low).unwrap_or(&0);
    let info = counts.get(&Severity::Info).unwrap_or(&0);

    let mut md = String::with_capacity(2048);

    writeln!(md, "# Jack Sparrow Security Report")?;
    writeln!(md)?;
    writeln!(md, "| Field | Value |")?;
    writeln!(md, "|-------|-------|")?;
    writeln!(md, "| **Target** | {} |", results.target)?;
    writeln!(
        md,
        "| **Scanned** | {} |",
        results.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    )?;
    writeln!(md, "| **Duration** | {}ms |", results.scan_duration_ms)?;
    writeln!(md, "| **Tools** | {} |", results.tools_used.join(", "))?;
    writeln!(md)?;

    writeln!(md, "## Summary")?;
    writeln!(md)?;
    writeln!(md, "| Severity | Count |")?;
    writeln!(md, "|----------|-------|")?;
    writeln!(md, "| 🔴 Critical | {} |", critical)?;
    writeln!(md, "| 🟠 High | {} |", high)?;
    writeln!(md, "| 🟡 Medium | {} |", medium)?;
    writeln!(md, "| 🔵 Low | {} |", low)?;
    writeln!(md, "| ⚪ Info | {} |", info)?;
    writeln!(md, "| **Total** | **{}** |", results.findings.len())?;
    writeln!(md)?;

    // Sort findings by severity
    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by_key(|a| std::cmp::Reverse(a.severity.rank()));

    if sorted_findings.is_empty() {
        writeln!(md, "## Findings")?;
        writeln!(md)?;
        writeln!(
            md,
            "No vulnerabilities detected. The scan completed without finding any security issues."
        )?;
    } else {
        writeln!(md, "## Findings ({} total)", sorted_findings.len())?;
        writeln!(md)?;

        for (i, finding) in sorted_findings.iter().enumerate() {
            let severity_icon = match finding.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };

            let vuln_type = match &finding.vulnerability_type {
                VulnerabilityType::SqlInjection => "SQL Injection",
                VulnerabilityType::XssReflected => "Reflected XSS",
                VulnerabilityType::XssStored => "Stored XSS",
                VulnerabilityType::XssDom => "DOM XSS",
                VulnerabilityType::Idor => "IDOR",
                VulnerabilityType::Ssrf => "SSRF",
                VulnerabilityType::SupplyChainDependency => "Dependency Vulnerability",
                VulnerabilityType::SupplyChainMalicious => "Malicious Package",
                VulnerabilityType::SecurityHeader => "Security Header",
                VulnerabilityType::TechFingerprint => "Technology Fingerprint",
                VulnerabilityType::SecretExposed => "Exposed Secret",
                VulnerabilityType::SubdomainFound => "Subdomain Discovered",
                VulnerabilityType::WafDetected => "WAF Detected",
                VulnerabilityType::JwtIssue => "JWT Issue",
                VulnerabilityType::GraphQLIntrospection => "GraphQL Introspection",
                VulnerabilityType::ApiSecurity => "API Security",
                VulnerabilityType::Xxe => "XML External Entity",
                VulnerabilityType::Ssti => "Server-Side Template Injection",
                VulnerabilityType::FormInjection => "Form Injection",
                VulnerabilityType::Csrf => "Cross-Site Request Forgery",
                VulnerabilityType::FileUpload => "Unrestricted File Upload",
            };

            writeln!(
                md,
                "### {}. {} {} [{}]",
                i + 1,
                severity_icon,
                finding.title,
                finding.severity
            )?;
            writeln!(md)?;
            writeln!(md, "- **Type:** {}", vuln_type)?;
            writeln!(md, "- **URL:** `{}`", finding.url)?;
            if let Some(ref param) = finding.parameter {
                writeln!(md, "- **Parameter:** `{}`", param)?;
            }
            writeln!(md, "- **Tool:** {}", finding.tool_source)?;
            if let Some(ref cwe) = finding.cwe_id {
                writeln!(md, "- **CWE:** {}", cwe)?;
            }
            if let Some(cvss) = finding.cvss_score {
                writeln!(md, "- **CVSS:** {}", cvss)?;
            }
            if !finding.description.is_empty() {
                writeln!(md)?;
                writeln!(md, "> {}", finding.description)?;
            }
            if !finding.remediation.is_empty() {
                writeln!(md)?;
                writeln!(md, "**Remediation:** {}", finding.remediation)?;
            }
            writeln!(md)?;
        }
    }

    writeln!(md, "---")?;
    writeln!(
        md,
        "*Generated by Jack Sparrow v0.4.0 — {}*",
        results.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    )?;

    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::types::{Confidence, Finding};
    use chrono::Utc;

    fn sample_results() -> ScanResults {
        let mut results = ScanResults::new("http://test.example.com".to_string());
        results.scan_duration_ms = 1234;
        results.tools_used = vec!["sqlmap".to_string(), "dalfox".to_string()];
        results.timestamp = Utc::now();

        let mut finding1 = Finding::new(
            VulnerabilityType::SqlInjection,
            Severity::High,
            Confidence::Confirmed,
            "SQL Injection in login".to_string(),
            "http://test.example.com/login".to_string(),
            "sqlmap".to_string(),
        );
        finding1.parameter = Some("user".to_string());
        finding1.cwe_id = Some("CWE-89".to_string());
        finding1.cvss_score = Some(8.6);
        finding1.remediation = "Use parameterized queries".to_string();
        results.findings.push(finding1);

        let finding2 = Finding::new(
            VulnerabilityType::XssReflected,
            Severity::Medium,
            Confidence::Likely,
            "XSS in search".to_string(),
            "http://test.example.com/search".to_string(),
            "dalfox".to_string(),
        );
        results.findings.push(finding2);

        results
    }

    #[test]
    fn test_json_report() {
        let results = sample_results();
        let json = generate_report(&results, ReportFormat::Json).unwrap();
        assert!(json.contains("http://test.example.com"));
        assert!(json.contains("SQL Injection in login"));
        assert!(json.contains("XSS in search"));
    }

    #[test]
    fn test_html_report() {
        let results = sample_results();
        let html = generate_report(&results, ReportFormat::Html).unwrap();
        assert!(html.contains("Jack Sparrow Security Report"));
        assert!(html.contains("SQL Injection in login"));
        assert!(html.contains("XSS in search"));
        assert!(html.contains("badge-high"));
        assert!(html.contains("badge-medium"));
    }

    #[test]
    fn test_markdown_report() {
        let results = sample_results();
        let md = generate_report(&results, ReportFormat::Markdown).unwrap();
        assert!(md.contains("# Jack Sparrow Security Report"));
        assert!(md.contains("SQL Injection in login"));
        assert!(md.contains("XSS in search"));
        assert!(md.contains("**Target**"));
        assert!(md.contains("**Duration**"));
    }

    #[test]
    fn test_empty_findings() {
        let results = ScanResults::new("http://clean.example.com".to_string());
        let html = generate_report(&results, ReportFormat::Html).unwrap();
        assert!(html.contains("No vulnerabilities detected"));

        let md = generate_report(&results, ReportFormat::Markdown).unwrap();
        assert!(md.contains("No vulnerabilities detected"));
    }

    #[test]
    fn test_report_format_from_str() {
        assert_eq!(ReportFormat::from_str("json"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::from_str("html"), Some(ReportFormat::Html));
        assert_eq!(
            ReportFormat::from_str("markdown"),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(ReportFormat::from_str("md"), Some(ReportFormat::Markdown));
        assert_eq!(ReportFormat::from_str("yaml"), None);
    }

    #[test]
    fn test_report_format_extension() {
        assert_eq!(ReportFormat::Json.extension(), "json");
        assert_eq!(ReportFormat::Html.extension(), "html");
        assert_eq!(ReportFormat::Markdown.extension(), "md");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
    }

    #[test]
    fn test_csv_report() {
        let results = sample_results();
        let csv = generate_report(&results, ReportFormat::Csv).unwrap();
        assert!(csv.contains("Severity,Type,Title"));
        assert!(csv.contains("SQL Injection"));
        assert!(csv.contains("Reflected XSS"));
        assert!(csv.contains("http://test.example.com/login"));
        assert!(csv.contains("http://test.example.com/search"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(escape_csv("hello"), "hello");
        assert_eq!(escape_csv("hello,world"), "\"hello,world\"");
        assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape_csv("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn test_csv_empty_findings() {
        let results = ScanResults::new("http://clean.example.com".to_string());
        let csv = generate_report(&results, ReportFormat::Csv).unwrap();
        assert!(csv.contains("Severity,Type,Title"));
        // Only header, no data rows
        assert_eq!(csv.lines().count(), 1);
    }

    #[test]
    fn test_csv_sorted_by_severity() {
        let mut results = sample_results();
        // Add a critical finding
        let critical = Finding::new(
            VulnerabilityType::Ssti,
            Severity::Critical,
            Confidence::Confirmed,
            "SSTI in template".to_string(),
            "http://test.example.com/render".to_string(),
            "sparrow".to_string(),
        );
        results.findings.push(critical);

        let csv = generate_report(&results, ReportFormat::Csv).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        // First data row should be CRITICAL
        assert!(lines[1].starts_with("CRITICAL,"));
    }
}

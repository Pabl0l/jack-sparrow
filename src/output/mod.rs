#![allow(dead_code)]

pub mod report;

use crate::shared::types::{Finding, ScanResults, Severity};
use colored::*;

/// Display findings in terminal with colors
pub fn display_findings(findings: &[Finding]) {
    println!("\n{}", "=== Findings ===".bold().cyan());

    if findings.is_empty() {
        println!("{}", "No vulnerabilities found.".green());
        return;
    }

    // Group by severity
    let mut by_severity: std::collections::HashMap<Severity, Vec<&Finding>> =
        std::collections::HashMap::new();
    for finding in findings {
        by_severity
            .entry(finding.severity.clone())
            .or_default()
            .push(finding);
    }

    // Display in severity order
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for severity in &severities {
        if let Some(findings) = by_severity.get(severity) {
            let color = match severity {
                Severity::Critical => severity.to_string().red().bold(),
                Severity::High => severity.to_string().red(),
                Severity::Medium => severity.to_string().yellow(),
                Severity::Low => severity.to_string().blue(),
                Severity::Info => severity.to_string().white(),
            };

            println!("\n{} ({} findings):", color, findings.len());

            for finding in findings {
                println!("  {} {}", "•".white(), finding.title);
                println!("    {} {}", "URL:".dimmed(), finding.url);
                if let Some(ref param) = finding.parameter {
                    println!("    {} {}", "Parameter:".dimmed(), param);
                }
                println!("    {} {}", "Tool:".dimmed(), finding.tool_source);
            }
        }
    }
}

/// Display scan summary
pub fn display_summary(results: &ScanResults) {
    println!("\n{}", "=== Scan Summary ===".bold().cyan());
    println!("{}: {}", "Target".white(), results.target);
    println!("{}: {}ms", "Duration".white(), results.scan_duration_ms);
    println!(
        "{}: {}",
        "Tools Used".white(),
        results.tools_used.join(", ")
    );

    let counts = results.count_by_severity();
    println!("\n{}", "Findings by Severity:".bold());
    println!(
        "  {} {}",
        "Critical:".red().bold(),
        counts.get(&Severity::Critical).unwrap_or(&0)
    );
    println!(
        "  {} {}",
        "High:".red(),
        counts.get(&Severity::High).unwrap_or(&0)
    );
    println!(
        "  {} {}",
        "Medium:".yellow(),
        counts.get(&Severity::Medium).unwrap_or(&0)
    );
    println!(
        "  {} {}",
        "Low:".blue(),
        counts.get(&Severity::Low).unwrap_or(&0)
    );
    println!(
        "  {} {}",
        "Info:".white(),
        counts.get(&Severity::Info).unwrap_or(&0)
    );
}

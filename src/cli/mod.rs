use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Jack Sparrow - Professional web pentesting tool
#[derive(Parser, Debug)]
#[command(name = "sparrow")]
#[command(version = "0.4.0")]
#[command(
    about = "🏴‍☠️ Professional web pentesting tool — find SQLi, XSS, IDOR, SSRF, and Supply Chain vulnerabilities"
)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a target for vulnerabilities
    Scan {
        /// Target URL or path
        #[arg(short, long)]
        target: String,

        /// Checks to run (sqli, xss, xss-reflected, xss-stored, xss-dom, idor, ssrf, supply-chain, headers, tech, secrets, subdomains, waf, jwt, graphql, api, cloud-metadata, xxe, ssti, all)
        #[arg(long, default_value = "all")]
        checks: String,

        /// Use a recorded session file
        #[arg(short, long)]
        session: Option<PathBuf>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format (json, html, markdown, csv — use html + browser Print to PDF)
        #[arg(long, default_value = "json")]
        format: String,

        /// Number of concurrent scans
        #[arg(long, default_value = "4")]
        concurrency: usize,

        /// Timeout in seconds
        #[arg(long, default_value = "300")]
        timeout: u64,

        /// Cookie string for authenticated scanning (e.g. "PHPSESSID=abc123; security=low")
        #[arg(long)]
        cookie: Option<String>,

        /// Custom HTTP header (repeatable, format: "Key: Value")
        #[arg(long)]
        header: Vec<String>,

        /// Login URL for form-based authentication (POST target)
        #[arg(long)]
        login_url: Option<String>,

        /// Username for form login
        #[arg(long)]
        login_user: Option<String>,

        /// Password for form login
        #[arg(long)]
        login_pass: Option<String>,

        /// Username form field name (default: "username")
        #[arg(long, default_value = "username")]
        login_field_user: String,

        /// Password form field name (default: "password")
        #[arg(long, default_value = "password")]
        login_field_pass: String,

        /// Extra form field for login (repeatable, format: "name=value")
        #[arg(long)]
        login_field: Vec<String>,
    },

    /// Record a browser session for later scanning
    Record {
        /// Output file path
        #[arg(short, long, default_value = "session.har")]
        output: PathBuf,

        /// Browser to use (chromium, firefox, webkit)
        #[arg(long, default_value = "chromium")]
        browser: String,

        /// Headless mode
        #[arg(long)]
        headless: bool,
    },

    /// Check if required tools are installed
    CheckTools,

    /// Generate a default configuration file
    InitConfig {
        /// Output file path
        #[arg(short, long, default_value = "jack-sparrow.toml")]
        output: PathBuf,
    },

    /// Show version information
    Version,
}

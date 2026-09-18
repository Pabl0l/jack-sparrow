# Jack Sparrow

Professional web pentesting tool that orchestrates proven security tools to detect **10 types of vulnerabilities** from a single CLI.

## Vulnerability Scanners

| Scanner | Detection Method | CWE |
|---------|-----------------|-----|
| **SQL Injection** | sqlmap wrapper (level, risk, tamper) | CWE-89 |
| **XSS Reflected** | dalfox-rs (workers, WAF evasion) | CWE-79 |
| **XSS Stored** | Form analysis + injection + persistence verification | CWE-79 |
| **DOM XSS** | Static JS analysis (taint: source → sink) | CWE-79 |
| **IDOR** | Sequential ID testing + path enumeration | CWE-639 |
| **SSRF** | ssrfmap wrapper (readfiles, portscan) | CWE-918 |
| **Supply Chain** | npm audit, pip-audit, cargo-audit | CWE-937 |
| **Security Headers** | 7 headers: CSP, HSTS, X-Frame-Options, etc. | CWE-693 |
| **Tech Fingerprint** | Framework, version, CMS, server detection | Info |
| **Secrets** | API keys, tokens, credentials in source | CWE-798 |

## Features

- **Concurrent scanning** — all scanners run in parallel via `tokio::join!`
- **Crawler engine** — async web crawler with Bloom filter dedup, robots.txt compliance, per-domain rate limiting
- **Session recording** — record browser sessions with Playwright, export to HAR 1.2
- **Professional reports** — JSON, HTML (dark theme), Markdown with CVSS scores and remediation
- **Auth support** — `--cookie` and `--header` flags for authenticated scanning
- **Configurable** — TOML config files for scanner tuning
- **10 scanners** — covering OWASP Top 10 and beyond

## Installation

### Prerequisites

- Rust 1.70+

### Build from source

```bash
git clone https://github.com/your-repo/jack-sparrow.git
cd jack-sparrow
cargo build --release
```

### Install external tools

```bash
make install-deps
```

Or manually:

```bash
pip install sqlmap          # SQL Injection
cargo install dalfox         # XSS
git clone https://github.com/swisskyrepo/ssrfmap.git  # SSRF
pip install pip-audit        # Python supply chain
cargo install cargo-audit    # Rust supply chain
```

## Usage

### Scan a target

```bash
# Scan all vulnerabilities
sparrow scan --target http://localhost/dvwa

# Scan specific checks
sparrow scan --target http://localhost/dvwa --checks sqli,xss,headers

# With authentication
sparrow scan --target http://localhost/dvwa \
  --checks sqli,xss \
  --cookie "PHPSESSID=abc123; security=low" \
  --header "Authorization: Bearer token123"

# With output format
sparrow scan --target http://localhost/dvwa \
  --output report.html --format html

# With concurrency and timeout
sparrow scan --target http://localhost/dvwa \
  --checks all --concurrency 8 --timeout 600
```

### Available checks

```
sqli              SQL Injection
xss               All XSS types (reflected + stored + DOM)
xss-reflected     Reflected XSS only
xss-stored        Stored XSS only
xss-dom           DOM XSS only
idor              Insecure Direct Object Reference
ssrf              Server-Side Request Forgery
supply-chain      Dependency vulnerabilities (npm/pip/cargo)
headers           Security headers audit
tech              Technology fingerprint
secrets           Exposed secrets and credentials
all               All scanners (default)
```

### Record a session

```bash
sparrow record --output session.har --browser chromium
```

### Check installed tools

```bash
sparrow check-tools
```

### Generate default config

```bash
sparrow init-config --output jack-sparrow.toml
```

## Configuration

Create a `jack-sparrow.toml` file:

```toml
[general]
max_concurrent = 4
timeout_secs = 300
user_agent = "JackSparrow/0.2.0"
verbose = false

[scanners.sqli]
level = 3
risk = 1
threads = 4

[scanners.xss]
workers = 50
waf_evasion = false

[scanners.idor]
param_names = ["id", "user_id", "account_id"]
id_range = [1, 100]
similarity_threshold = 0.8

[scanners.ssrf]
level = 2
modules = ["readfiles", "portscan"]

[scanners.supply_chain]
check_npm = true
check_pip = true
check_cargo = true
```

## Architecture

```
jack-sparrow/
├── src/
│   ├── main.rs                    # Entry point, CLI dispatch
│   ├── lib.rs                     # Re-exports
│   ├── cli/mod.rs                 # Clap CLI definitions
│   ├── commands/mod.rs            # Command handlers
│   ├── core/
│   │   ├── engine.rs              # Scan orchestrator (concurrent)
│   │   ├── crawler/               # Async web crawler
│   │   │   ├── config.rs          # CrawlerConfig + CrawlScope
│   │   │   ├── engine.rs          # CrawlerEngine (workers)
│   │   │   ├── fetcher.rs         # HTTP fetcher + retry + backoff
│   │   │   ├── frontier.rs        # URL frontier + Bloom dedup
│   │   │   ├── parser.rs          # HTML parser (links/forms/scripts)
│   │   │   ├── robots.rs          # robots.txt handler + cache
│   │   │   ├── rate_limiter.rs    # Per-domain GCRA rate limiting
│   │   │   └── sitemap.rs         # Sitemap generator (XML/JSON/Text)
│   │   ├── recorder/              # Playwright session recorder
│   │   │   ├── browser.rs         # Browser recording
│   │   │   └── har.rs             # HAR 1.2 types + builder
│   │   └── scanners/
│   │       ├── mod.rs             # Scanner trait + ScannerType enum
│   │       ├── sqli.rs            # SQLMap wrapper
│   │       ├── xss.rs             # dalfox-rs wrapper
│   │       ├── stored_xss.rs      # Stored XSS (form analysis)
│   │       ├── dom_xss/           # DOM XSS (JS taint analysis)
│   │       │   ├── js_analyzer.rs
│   │       │   ├── sinks.rs
│   │       │   ├── sources.rs
│   │       │   └── taint.rs
│   │       ├── idor.rs            # Custom IDOR detector
│   │       ├── ssrf.rs            # ssrfmap wrapper
│   │       ├── supply_chain.rs    # npm/pip/cargo audit
│   │       ├── headers.rs         # Security headers checker
│   │       ├── tech_fingerprint.rs # Technology detection
│   │       ├── secrets.rs         # Secret detection
│   │       └── crawl_integration.rs # Crawl → Scanner bridge
│   ├── shared/
│   │   ├── types.rs               # Finding, Severity, ScanResults
│   │   ├── config.rs              # JackSparrowConfig (TOML)
│   │   ├── error.rs               # JackSparrowError (thiserror)
│   │   ├── context.rs             # ScanContext (auth)
│   │   └── tool_checker.rs        # External tool verification
│   └── output/
│       ├── mod.rs                 # Terminal colored output
│       └── report.rs              # JSON/HTML/Markdown reports
├── tests/
│   ├── integration_tests.rs       # Unit + integration tests
│   ├── labs_e2e.rs                # E2E tests against Docker labs
│   └── e2e/cli_test.rs           # CLI tests
├── benches/
│   └── scanner_bench.rs           # Criterion benchmarks
├── lab/                           # Docker lab environments
│   ├── docker-compose.yml         # DVWA, Juice Shop, SSRF Lab
│   └── scan-config.toml           # Tool paths config
└── dev_plan.md                    # Development plan
```

## Testing

### Run unit and integration tests

```bash
cargo test
```

### Run E2E tests against Docker labs

```bash
# Start labs
make lab-up

# Run lab tests
cargo test --test labs_e2e -- --ignored

# Stop labs
make lab-down
```

### Run benchmarks

```bash
cargo bench
```

### Lint and format

```bash
cargo clippy -- -D warnings
cargo fmt
```

## Lab Environment

Start vulnerable applications for testing:

```bash
make lab-up
```

| Lab | URL | Purpose |
|-----|-----|---------|
| DVWA | http://localhost:80 | SQLi, XSS, IDOR testing |
| Juice Shop | http://localhost:3001 | Modern web app vulnerabilities |
| WebGoat | http://localhost:8080 | OWASP learning |
| SSRF Lab | http://localhost:5000 | SSRF detection testing |

## Metrics

| Metric | Target |
|--------|--------|
| SQLi Detection Rate | >90% (DVWA low) |
| XSS Detection Rate | >85% (DVWA/Juice Shop) |
| SSRF Detection Rate | >80% (Custom lab) |
| False Positive Rate | <10% |
| Concurrent Scanners | 10 (configurable) |

## License

MIT License

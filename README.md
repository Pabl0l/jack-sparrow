# Jack Sparrow

[![CI](https://github.com/your-repo/jack-sparrow/actions/workflows/ci.yml/badge.svg)](https://github.com/your-repo/jack-sparrow/actions/workflows/ci.yml)
[![Release](https://github.com/your-repo/jack-sparrow/actions/workflows/release.yml/badge.svg)](https://github.com/your-repo/jack-sparrow/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Professional web pentesting tool that orchestrates proven security tools to detect **18 types of vulnerabilities** from a single CLI.

## Vulnerability Scanners

| # | Scanner | Detection Method | CWE |
|---|---------|-----------------|-----|
| 1 | **SQL Injection** | sqlmap wrapper (level, risk, tamper) | CWE-89 |
| 2 | **XSS Reflected** | dalfox-rs (workers, WAF evasion) | CWE-79 |
| 3 | **XSS Stored** | Form analysis + injection + persistence verification | CWE-79 |
| 4 | **DOM XSS** | Static JS analysis (taint: source → sink) | CWE-79 |
| 5 | **IDOR** | Sequential ID testing + path enumeration | CWE-639 |
| 6 | **SSRF** | ssrfmap wrapper (readfiles, portscan) | CWE-918 |
| 7 | **Supply Chain** | npm audit, pip-audit, cargo-audit | CWE-937 |
| 8 | **Security Headers** | 7 headers: CSP, HSTS, X-Frame-Options, etc. | CWE-693 |
| 9 | **Tech Fingerprint** | Framework, version, CMS, server detection | Info |
| 10 | **Secrets** | API keys, tokens, credentials in source | CWE-798 |
| 11 | **Subdomain Enum** | crt.sh Certificate Transparency + brute-force | Info |
| 12 | **WAF Detection** | 12 WAF fingerprints (Cloudflare, AWS, Akamai, etc.) | Info |
| 13 | **JWT Analysis** | Decode, entropy analysis, common secrets, claims | CWE-798 |
| 14 | **GraphQL Introspection** | Schema analysis, dangerous mutations, injectable args | CWE-200 |
| 15 | **API Security** | CORS, methods, rate limiting, error disclosure | CWE-942 |
| 16 | **Cloud Metadata SSRF** | AWS/GCP/Azure IMDS, IP obfuscation detection | CWE-918 |
| 17 | **XXE** | XML entity injection, file reads, SSRF via XXE | CWE-611 |
| 18 | **SSTI** | Template injection (Jinja2, Smarty, Freemarker, etc.) | CWE-1336 |

## Features

- **18 scanners** — covering OWASP Top 10 and beyond
- **Concurrent scanning** — all scanners run in parallel via `tokio::join!`
- **Crawler engine** — async web crawler with Bloom filter dedup, robots.txt compliance, per-domain rate limiting
- **Session recording** — record browser sessions with Playwright, export to HAR 1.2
- **Professional reports** — JSON, HTML (dark theme, PDF-printable), Markdown, CSV with CVSS scores and remediation
- **Auth support** — `--cookie` and `--header` flags for authenticated scanning
- **Configurable** — TOML config files for scanner tuning
- **Cross-platform** — Linux, macOS, Windows

## Installation

### Prerequisites

- Rust 1.70+

### Install from release

Download the latest binary from [Releases](https://github.com/your-repo/jack-sparrow/releases).

### Build from source

```bash
git clone https://github.com/your-repo/jack-sparrow.git
cd jack-sparrow
cargo build --release
```

### Install as global command

```bash
cargo install --path .
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
sqli              SQL Injection (via sqlmap)
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
subdomains        Subdomain enumeration (crt.sh + brute-force)
waf               WAF detection (12 fingerprints)
jwt               JWT analysis (entropy, common secrets, claims)
graphql           GraphQL introspection and schema analysis
api               API security (CORS, methods, rate limiting)
cloud-metadata    Cloud metadata SSRF (AWS/GCP/Azure IMDS)
xxe               XML External Entity injection
ssti              Server-Side Template Injection
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
user_agent = "JackSparrow/0.4.0"
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
│   │       ├── idor.rs            # Custom IDOR detector
│   │       ├── ssrf.rs            # ssrfmap wrapper
│   │       ├── supply_chain.rs    # npm/pip/cargo audit
│   │       ├── headers.rs         # Security headers checker
│   │       ├── tech_fingerprint.rs # Technology detection
│   │       ├── secrets.rs         # Secret detection
│   │       ├── subdomain.rs       # Subdomain enumeration
│   │       ├── waf.rs             # WAF detection
│   │       ├── jwt.rs             # JWT analysis
│   │       ├── graphql.rs         # GraphQL introspection
│   │       ├── api_security.rs    # API security checks
│   │       ├── cloud_metadata.rs  # Cloud metadata SSRF
│   │       ├── xxe.rs             # XXE injection
│   │       ├── ssti.rs            # SSTI detection
│   │       └── crawl_integration.rs # Crawl → Scanner bridge
│   ├── shared/
│   │   ├── types.rs               # Finding, Severity, ScanResults
│   │   ├── config.rs              # JackSparrowConfig (TOML)
│   │   ├── error.rs               # JackSparrowError (thiserror)
│   │   ├── context.rs             # ScanContext (auth)
│   │   └── tool_checker.rs        # External tool verification
│   └── output/
│       ├── mod.rs                 # Terminal colored output
│       └── report.rs              # JSON/HTML/Markdown/CSV reports
├── tests/
│   ├── integration_tests.rs       # Unit + integration tests
│   ├── labs_e2e.rs                # E2E tests against Docker labs
│   └── e2e/cli_test.rs           # CLI tests
├── benches/
│   └── scanner_bench.rs           # Criterion benchmarks
├── lab/                           # Docker lab environments
│   ├── docker-compose.yml         # DVWA, Juice Shop, SSRF Lab
│   └── scan-config.toml           # Tool paths config
└── .github/workflows/
    ├── ci.yml                     # CI pipeline (test, clippy, fmt)
    └── release.yml                # Cross-platform release builds
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
cargo fmt --check
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
| Unit Tests | 265+ |

## Roadmap

- [x] Phase P0: Core scanners (SQLi, XSS, IDOR, SSRF, Supply Chain)
- [x] Phase P1: Headers, Tech Fingerprint, Secrets
- [x] Phase P2: Crawler, Stored XSS, DOM XSS
- [x] Phase P3: Subdomains, WAF, JWT, GraphQL, API Security
- [x] Phase P4: Cloud Metadata, XXE, SSTI, CSV/PDF reports
- [ ] Browser-based scanning (Playwright integration)
- [ ] OAuth/OIDC flow testing
- [ ] Rate limit bypass techniques

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

MIT License

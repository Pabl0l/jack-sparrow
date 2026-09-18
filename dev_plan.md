# Plan del Proyecto: Jack Sparrow

## Visión General
- **Objetivo:** Herramienta profesional de pentesting web en Rust, orquestando herramientas externas probadas para detectar vulnerabilidades.
- **Stack tecnológico:** Rust 2021, Tokio (async), Clap (CLI), Reqwest (HTTP), Playwright-rs (browser automation), dalfox-rs (XSS), serde/serde_json (serialización), TOML (config)
- **Arquitectura:** Modular basada en trait `Scanner` con orquestador central (`ScanEngine`), separación CLI → Commands → Core → Output

---

## Resumen de Scanners (18 activos)

| # | Scanner | Archivo | Check keyword | Tests |
|---|---------|---------|---------------|-------|
| 1 | SQL Injection | `sqli.rs` | `sqli` | Wrapper sqlmap |
| 2 | XSS Reflected | `xss.rs` | `xss` | dalfox-rs |
| 3 | XSS Stored | `stored_xss.rs` | `xss-stored` | Form injection |
| 4 | DOM XSS | `dom_xss/` | `xss-dom` | JS analysis |
| 5 | IDOR | `idor.rs` | `idor` | Custom detector |
| 6 | SSRF | `ssrf.rs` | `ssrf` | ssrfmap wrapper |
| 7 | Supply Chain | `supply_chain.rs` | `supply-chain` | npm/pip/cargo audit |
| 8 | Security Headers | `headers.rs` | `headers` | 7 headers |
| 9 | Tech Fingerprint | `tech_fingerprint.rs` | `tech` | Framework/CMS detection |
| 10 | Secrets | `secrets.rs` | `secrets` | API keys/tokens |
| 11 | Subdomain Enum | `subdomain.rs` | `subdomains` | crt.sh + brute-force |
| 12 | WAF Detection | `waf.rs` | `waf` | 12 WAF fingerprints |
| 13 | JWT Analysis | `jwt.rs` | `jwt` | Decode + entropy + common secrets |
| 14 | GraphQL Introspection | `graphql.rs` | `graphql` | Schema analysis |
| 15 | API Security | `api_security.rs` | `api` | CORS, methods, errors, rate-limit |
| 16 | **Cloud Metadata SSRF** | `cloud_metadata.rs` | `cloud-metadata` | AWS/GCP/Azure IMDS, IP obfuscation |
| 17 | **XXE** | `xxe.rs` | `xxe` | XML entity injection, file reads, SSRF |
| 18 | **SSTI** | `ssti.rs` | `ssti` | Template injection, RCE, multi-engine |

---

## Estado Actual
- **Última actualización:** 2026-09-18
- **Progreso general:** ~100%
- **Versión:** 0.4.0
- **Tests:** 261 unit/integration
- **Warnings:** 0
- **Instalado globalmente:** `sparrow` command via `cargo install`
- **Siguiente paso:** P4 — Browser-based scanning, PDF/CSV reports, OAuth/OIDC testing

---

## Módulos

### Módulo 1: CLI (`src/cli/mod.rs`)
- **Estado:** [X] Completado

### Módulo 2: Comandos (`src/commands/mod.rs`)
- **Estado:** [X] Completado

### Módulo 3: Motor de Orquestación (`src/core/engine.rs`)
- **Estado:** [X] Completado
- Checks: sqli, xss, xss-reflected, xss-stored, xss-dom, idor, ssrf, supply-chain, headers, tech, secrets, subdomains, waf, jwt, graphql, api, cloud-metadata, xxe, ssti, all

### Módulos 4-10: Scanners Core
- **Estado:** [X] Completado (SQLi, XSS, IDOR, SSRF, SupplyChain, Headers, Recorder)

### Módulo 11: Reporter (`src/output/`)
- **Estado:** [X] Completado — JSON/HTML/Markdown, CVSS auto, remediación específica

### Módulo 12: Shared (`src/shared/`)
- **Estado:** [X] Completado — 18 VulnerabilityTypes, 18 ScannerTypes

### Módulo 13: Tests (`tests/`)
- **Estado:** [X] Completado

### Módulo 14: Lab Environment (`lab/`)
- **Estado:** [X] Completado

### Módulo 15: Subdomain Enumeration (`src/core/scanners/subdomain.rs`)
- **Estado:** [X] Completado
- crt.sh Certificate Transparency + 80+ subdomain brute-force

### Módulo 16: WAF Detection (`src/core/scanners/waf.rs`)
- **Estado:** [X] Completado
- 12 WAF fingerprints (Cloudflare, AWS, Akamai, Sucuri, ModSecurity, etc.)

### Módulo 17: JWT Analysis (`src/core/scanners/jwt.rs`)
- **Estado:** [X] Completado
- Decode, entropy analysis, common secret detection, algorithm checks, claims validation

### Módulo 18: GraphQL Introspection (`src/core/scanners/graphql.rs`)
- **Estado:** [X] Completado
- Introspection detection, schema analysis (sensitive types/fields, dangerous mutations, injectable args, subscriptions)

### Módulo 19: API Security (`src/core/scanners/api_security.rs`)
- **Estado:** [X] Completado
- CORS misconfiguration, HTTP method enumeration (TRACE/PUT/DELETE), verbose error detection, information disclosure headers, rate limiting check, common API path discovery

### Módulo 20: Cloud Metadata SSRF (`src/core/scanners/cloud_metadata.rs`)
- **Estado:** [X] Completado
- AWS IMDSv1/v2, GCP metadata, Azure instance metadata, Kubernetes secrets, DigitalOcean, IP obfuscation detection (octal, hex, decimal, IPv6), URL parameter SSRF probing

### Módulo 21: XXE (`src/core/scanners/xxe.rs`)
- **Estado:** [X] Completado
- XML entity injection, Linux/Windows file reads, PHP filter bypass, SSRF via XXE, blind XXE, SVG XXE, XML endpoint detection

### Módulo 22: SSTI (`src/core/scanners/ssti.rs`)
- **Estado:** [X] Completado
- Jinja2/Twig, Smarty, Freemarker, Velocity, Mako, ERB, RCE detection, math payload verification, config disclosure

---

## P3 — Largo Plazo
- [X] Subdomain enumeration
- [X] WAF detection
- [X] JWT/session analysis
- [X] GraphQL introspection
- [X] API testing (REST)

---

## Roadmap

### P0 — Completado ✅
### P1 — Corto Plazo ✅
### P2 — Mediano Plazo ✅ (Crawler + Stored XSS + DOM XSS)
### P3 — Largo Plazo ✅ (Subdomains + WAF + JWT + GraphQL + API)
### P4 — Próximo
- [X] Cloud metadata SSRF (AWS/GCP/Azure endpoint detection)
- [X] XXE (XML External Entity detection)
- [X] SSTI (Server-Side Template Injection)
- [ ] Browser-based scanning (Playwright integration for JS-heavy apps)
- [ ] PDF/CSV report export
- [ ] OAuth/OIDC flow testing
- [ ] Rate limit bypass techniques
- [ ] JWT brute-force (optional, opt-in)

---

## Dependencias Principales
| Dependencia | Versión | Propósito |
|-------------|---------|-----------|
| clap | 4 | CLI framework |
| tokio | 1 (full) | Async runtime |
| reqwest | 0.12 (rustls-tls, cookies) | HTTP client |
| playwright-rs | 0.15 | Browser automation |
| dalfox-rs | 0.5.5 | XSS scanning |
| base64 | 0.22 | JWT decoding |
| serde / serde_json | 1 | Serialization |
| thiserror | 1 | Error handling |
| colored / indicatif | 2 / 0.17 | Terminal output |
| async-trait | 0.1 | Async trait support |

---

## Herramientas Externas
| Herramienta | Propósito | Estado |
|-------------|-----------|--------|
| sqlmap | SQL Injection | Docker wrapper |
| dalfox | XSS | Nativo |
| ssrfmap | SSRF | GitHub clone |
| npm audit | Supply chain | Con npm |
| pip-audit | Supply chain | Instalado |
| cargo audit | Supply chain | Instalado |

---

## Labs Docker
| Lab | Puerto | Estado |
|-----|--------|--------|
| DVWA | 80 | Activo |
| Juice Shop | 3001 | Activo |
| WebGoat | 8080 | Activo |
| SSRF Lab | 5000 | Activo |

---

## Comandos de Uso
```bash
# Scan completo
sparrow scan -t "http://target.com" --checks all

# GraphQL introspection
sparrow scan -t "http://target.com" --checks graphql

# API security
sparrow scan -t "http://target.com" --checks api

# Cloud metadata SSRF
sparrow scan -t "http://target.com" --checks cloud-metadata

# XXE injection
sparrow scan -t "http://target.com" --checks xxe

# SSTI (Server-Side Template Injection)
sparrow scan -t "http://target.com" --checks ssti

# Subdomain enumeration
sparrow scan -t "http://target.com" --checks subdomains

# WAF detection
sparrow scan -t "http://target.com" --checks waf

# JWT analysis (with token)
sparrow scan -t "http://target.com" --checks jwt --header "Authorization: Bearer <token>"

# Authenticated scan
sparrow scan -t "http://target.com" --cookie "session=abc123" --header "X-API-Key: secret"
```

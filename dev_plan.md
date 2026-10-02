# Plan del Proyecto: Jack Sparrow

## Visión General
- **Objetivo:** Herramienta profesional de pentesting web en Rust, orquestando herramientas externas probadas para detectar vulnerabilidades.
- **Stack tecnológico:** Rust 2021, Tokio (async), Clap (CLI), Reqwest (HTTP), Playwright-rs (browser automation), dalfox-rs (XSS), serde/serde_json (serialización), TOML (config)
- **Arquitectura:** Modular basada en trait `Scanner` con orquestador central (`ScanEngine`), separación CLI → Commands → Core → Output

---

## Resumen de Scanners (26 activos)

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
| 19 | **Browser XSS** | `browser_xss.rs` | `browser-xss` | Browser-rendered XSS detection, SPA detection |
| 20 | **OAuth/OIDC Security** | `oauth_scanner.rs` | `oauth` | OIDC discovery, CSRF (missing state), open redirect, implicit flow, weak PKCE |
| 21 | **Rate Limit Bypass** | `rate_limit_bypass.rs` | `rate-limit` | Rate limit detection, bypass via method/header/URL/cookie manipulation |
| 22 | **JWT Brute-Force** | `jwt_bruteforce.rs` | `jwt-bruteforce` | HMAC secret brute-force, algorithm confusion, weak algorithm detection |
| 23 | **CORS Deep Testing** | `cors_deep.rs` | `cors` | Origin reflection, null origin, wildcard, subdomain bypass, preflight |
| 24 | **Subdomain Takeover** | `subdomain_takeover.rs` | `subdomain-takeover` | CNAME takeover detection, service signature matching |
| 25 | **WebSocket Security** | `websocket_security.rs` | `websocket` | WS upgrade detection, missing auth, CSWSH, info disclosure |
| 26 | **API Fuzzing** | `api_fuzzing.rs` | `api-fuzz` | Parameter fuzzing, error patterns, payload reflection |

---

## Estado Actual
- **Última actualización:** 2026-10-01
- **Progreso general:** ~100%
- **Versión:** 0.6.1 (tag `v0.6.1` — CI + Release verificados en verde)
- **Tests:** ~590 (lib 530 + integration 8 + e2e 12 + mission_consistency 2 + lab suites) + 25 aserciones JS (`node docs/tutorial/tests/game.test.js`) — ambos, el test de consistencia y el test JS, corren en CI
- **Warnings:** 0 — gate estricto `RUSTFLAGS=-D warnings` en CI (fmt + clippy + test)
- **Instalado globalmente:** `sparrow` command via `cargo install`
- **CI/CD:** GitHub Actions (ci.yml + release.yml). Release v0.6.1 incluye fix ARM64 (openssl vendored target-dep)
- **Documentación:** `TUTORIAL.md` (Markdown) + `docs/tutorial/` (tutorial HTML interactivo estilo terminal con **Modo Misión** de 12 niveles, embebido en el binario vía `sparrow tutorial`)
- **Bugs corregidos:** main.rs duplicaba el árbol de módulos (≈50 dead_code), ~35 lints clippy, test e2e esperaba versión 0.4.0, p5_lab_e2e tests anidados dentro de otro test, strings de versión hardcodeados → `env!(CARGO_PKG_VERSION)`
- **Siguiente paso:** CI verde con autenticación fusionada (run 37033979117, 2026-10-02: #35/#36/#37 resueltos); pendiente solo verificar el login contra el lab DVWA real en `localhost:3001` cuando esté levantado. Mejoras opcionales (GitHub Pages, sonido/animación en el Modo Misión)

---

## Módulos

### Módulo 1: CLI (`src/cli/mod.rs`)
- **Estado:** [X] Completado

### Módulo 2: Comandos (`src/commands/mod.rs`)
- **Estado:** [X] Completado

### Módulo 3: Motor de Orquestación (`src/core/engine.rs`)
- **Estado:** [X] Completado
- Checks: sqli, xss, xss-reflected, xss-stored, xss-dom, idor, ssrf, supply-chain, headers, tech, secrets, subdomains, waf, jwt, graphql, api, cloud-metadata, xxe, ssti, form, csrf, upload, browser-xss, oauth, rate-limit, jwt-bruteforce, api-fuzz, cors, subdomain-takeover, websocket, all

### Módulos 4-10: Scanners Core
- **Estado:** [X] Completado (SQLi, XSS, IDOR, SSRF, SupplyChain, Headers, Recorder)

### Módulo 11: Reporter (`src/output/`)
- **Estado:** [X] Completado — JSON/HTML/Markdown, CVSS auto, remediación específica

### Módulo 12: Shared (`src/shared/`)
- **Estado:** [X] Completado — 26 VulnerabilityTypes, 26 ScannerTypes

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

### Módulo 23: Browser XSS Scanner (`src/core/scanners/browser_xss.rs`)
- **Estado:** [X] Completado
- Playwright-based browser rendering for XSS detection in SPA/JS-heavy apps
- BrowserScanner trait + PlaywrightBrowser implementation
- URL parameter XSS testing, DOM XSS detection, SPA detection
- Cookie/header passthrough for authenticated scanning

### Módulo 24: Browser Scanner Infrastructure (`src/core/scanners/browser_scanner.rs`)
- **Estado:** [X] Completado
- BrowserScanner trait, BrowserConfig, BrowserManager, BrowserPage, NetworkRequest, Cookie structs

### Módulo 25: OAuth/OIDC Scanner (`src/core/scanners/oauth_scanner.rs`)
- **Estado:** [X] Completado
- OIDC Discovery endpoint detection (/.well-known/openid-configuration)
- Authorization endpoint probing (/authorize, /oauth/authorize, etc.)
- Token endpoint probing (POST)
- HTML indicator detection (oauth, openid, authorize links)
- Missing state parameter detection (CSRF vulnerability)
- Implicit flow detection (deprecated response_type=token)
- Weak PKCE detection (plain method)
- Open redirect testing via redirect_uri parameter

### Módulo 26: Rate Limit Bypass Scanner (`src/core/scanners/rate_limit_bypass.rs`)
- **Estado:** [X] Completado
- Rate limit header detection (x-ratelimit-limit, retry-after, etc.)
- HTTP method switching bypass (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD)
- IP spoofing header bypass (X-Forwarded-For, X-Real-IP, True-Client-IP, etc.)
- URL manipulation bypass (encoding tricks, case changes, double slashes)
- Cookie removal bypass (session rotation)
- Missing rate limit detection on sensitive endpoints (login, register, password reset)

### Módulo 27: JWT Brute-Force Scanner (`src/core/scanners/jwt_bruteforce.rs`)
- **Estado:** [X] Completado
- JWT HMAC secret brute-force (30 common secrets)
- Algorithm confusion detection (alg=none, HS256 when expecting RSA)
- Weak algorithm detection (none, HS256/384/512)
- Missing expiration (exp claim) detection
- Missing iss/aud claim detection
- HMAC signature verification

### Módulo 28: CORS Deep Testing Scanner (`src/core/scanners/cors_deep.rs`)
- **Estado:** [X] Completado
- Origin reflection testing (attacker.com)
- Null Origin testing (sandboxed iframe)
- Wildcard + credentials detection
- Subdomain bypass testing
- Preflight (OPTIONS) response analysis

### Módulo 29: Subdomain Takeover Scanner (`src/core/scanners/subdomain_takeover.rs`)
- **Estado:** [X] Completado
- HTTP-based takeover detection (20 known service signatures)
- Response body signature matching
- Redirect header analysis for known services
- Server header analysis for service identification

### Módulo 30: WebSocket Security Scanner (`src/core/scanners/websocket_security.rs`)
- **Estado:** [X] Completado
- WebSocket upgrade detection (13 common WS paths)
- Missing authentication testing
- Cross-Site WebSocket Hijacking (CSWSH) detection
- Information disclosure via WS handshake headers

### Módulo 31: API Fuzzing Scanner (`src/core/scanners/api_fuzzing.rs`)
- **Estado:** [X] Completado
- 13 fuzz payloads (SQLi, XSS, SSTI, path traversal, cmd injection, CRLF)
- 25 common parameter names tested via GET and POST
- Error pattern detection (SQL errors, stack traces)
- Payload reflection detection (XSS)

### Módulo 32: Custom Wordlists (`src/core/wordlist.rs`)
- **Estado:** [X] Completado
- Custom wordlist file loading with caching
- Built-in defaults (50 subdomains, 45 paths, 30 params)
- Merge custom + default wordlists
- Validation of wordlist files

### Módulo 33: Performance Profiling (`src/core/perf.rs`)
- **Estado:** [X] Completado
- Per-scanner timing, findings count, request count
- Findings-per-second metric
- Slowest/fastest scanner identification
- Optimization suggestions (slow scanners, low throughput, high error rates)

### Módulo 34: Tutorial HTML interactivo (`docs/tutorial/` + `src/commands/tutorial.rs`)
- **Descripción:** Tutorial estilo terminal (estética Matrix del portafolio) basado en `TUTORIAL.md`; comando `sparrow tutorial` lo ensambla en un HTML autocontenido y lo abre en el navegador (`open` crate). `--save <ruta>` solo escribe el fichero (CI/archivado).
- **Dependencias:** `open = "5"`, `include_str!` de `docs/tutorial/{index.html,css,js}`
- **Estado:** [X] Completado
- **Tasks:**
  - [X] Sitio (index + css + js) movido al repo en `docs/tutorial/`
  - [X] Subcomando `Tutorial { save }` en CLI + dispatch
  - [X] Ensamblado autocontenido (CSS/JS inline) sin build step
  - [X] Banner oficial del CLI (`print_banner`)
  - [X] Tests: 2 unitarios (assemble) + 2 e2e (help, save)
  - [X] Docs: README + TUTORIAL.md (flujo post-instalación)

### Módulo 35: Modo Misión — juego de niveles (`docs/tutorial/js/game.js`)
- **Descripción:** Gamificación del tutorial: 12 niveles donde el usuario recibe un objetivo (URL + alcance) y debe tipear el comando real de `sparrow` con la sintaxis correcta. Validador estricto (prefijo, flags, valores, comillas obligatorias con espacios, conjunto exacto de `--checks` con orden libre), XP/estrellas/rangos, HUD y progreso persistente.
- **Dependencias:** ninguna (JS puro; `MISSIONS` en `content.js`, motor en `game.js`)
- **Estado:** [X] Completado
- **Tasks:**
  - [X] `game.js`: PRNG mulberry32 con semilla por partida, tokenizador con comillas/comentarios, validador de specs, XP/estrellas/rangos, `localStorage`
  - [X] `content.js`: 12 niveles × 4-12 retos (3 por nivel elegidos por semilla) + portada `mission` + help
  - [X] `terminal.js`: enrutado (`mission*`, `hint`, `rank`, `abort`, `sparrow …`, `make …`) + restore en boot
  - [X] `tutorial.rs`: inline de `game.js` + test `test_assemble_inlines_game_engine`
  - [X] Tests: `docs/tutorial/tests/game.test.js` (25 aserciones, `node`, sin deps)
  - [X] Test de consistencia retos ↔ CLI: `tests/mission_consistency.rs` (keywords `--checks` ↔ `parse_checks`, flags/subcomandos ↔ `cli/mod.rs`, pares keyword↔flag, objetivos `Makefile`) + red de seguridad anti-regex-vacío
  - [X] CI: steps en job `test` → `cargo test --test mission_consistency` + Node 20 + `node docs/tutorial/tests/game.test.js`
  - [X] `storageOk()`: aviso en `mission start` si `localStorage` no permite persistir (#30)
  - [X] Verificación manual con Playwright (HTML ensamblado: start, hint, acierto, error, restore)
  - [X] Docs: README, TUTORIAL.md, `docs/tutorial/README.md`

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
### P4 — Próximo ✅
- [X] Cloud metadata SSRF (AWS/GCP/Azure endpoint detection)
- [X] XXE (XML External Entity detection)
- [X] SSTI (Server-Side Template Injection)
- [X] Browser-based scanning (Playwright integration for JS-heavy apps)
- [X] PDF/CSV report export (CSV native + HTML print-to-PDF)
- [X] OAuth/OIDC flow testing
- [X] Rate limit bypass techniques
- [X] JWT brute-force (optional, opt-in)

### P5 — Avanzado
- [X] CORS deep testing
- [X] Custom wordlists support
- [X] Subdomain takeover detection
- [X] WebSocket security testing
- [X] API fuzzing
- [X] Performance profiling

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
# Tutorial interactivo HTML (post-instalación — se abre en el navegador)
sparrow tutorial
sparrow tutorial --save tutorial.html   # solo guarda, sin abrir navegador

# Modo Misión (dentro del tutorial): 12 niveles jugables
#   mission start · mission status · hint · rank · abort

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

# OAuth/OIDC security testing
sparrow scan -t "http://target.com" --checks oauth --oauth

# Rate limit bypass testing
sparrow scan -t "http://target.com" --checks rate-limit --rate-limit

# JWT brute-force (opt-in, requires token)
sparrow scan -t "http://target.com" --checks jwt-bruteforce --jwt-bruteforce --header "Authorization: Bearer <token>"

# Authenticated scan
sparrow scan -t "http://target.com" --cookie "session=abc123" --header "X-API-Key: secret"
```

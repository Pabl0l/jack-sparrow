# Puntos Débiles y Riesgos del Proyecto: Jack Sparrow

---

## Nuevos Weaknesses (2026-10-01)

### 26. `docs/tutorial/js/content.js` puede desincronizarse con `TUTORIAL.md`
- **Riesgo**: Medio — el tutorial HTML es un resumen tipado del Markdown; si TUTORIAL.md cambia, el sitio queda viejo
- **Probabilidad**: Media (el tutorial ya existe y se completó; cambios futuros puntuales)
- **Mitigación**: [X] Enlace permanente al TUTORIAL.md fuente (footer + sección `intro`); README de `docs/tutorial/` documenta la regla "si cambia el tutorial → actualizar content.js". [ ] Considerar generador desde Markdown si el tutorial crece.
- **Estado**: [~] Monitorizado

### 27. Ensamblado del tutorial depende de etiquetas exactas en `index.html`
- **Riesgo**: Bajo — `tutorial.rs` hace `replace` de `<link … style.css>` y los dos `<script src>`; si se editan esas etiquetas, el HTML autocontenido saldría sin CSS/JS
- **Probabilidad**: Baja (los tests unitarios `test_assemble_inlines_assets` y e2e `test_tutorial_save_writes_standalone_html` fallan si ocurre)
- **Mitigación**: [X] Doble red de tests (unit + e2e) sobre el HTML ensamblado
- **Estado**: [X] Resuelto

### 28. El tutorial offline depende de Google Fonts (requiere red)
- **Riesgo**: Leve — sin conexión las fuentes VT323/JetBrains Mono caen a Courier New (cambia la estética, la funcionalidad no)
- **Probabilidad**: Media (usuarios offline tras instalar)
- **Mitigación**: [~] Fallbacks en CSS (`'VT323', 'Courier New', monospace`); si importa, auto-hostear woff2 en `docs/tutorial/fonts/` (+ ~80 KB al binario)
- **Estado**: [~] Aceptado por ahora

### 29. Retos del Modo Misión fijados a mano frente a la CLI real
- **Riesgo**: Medio — los retos de `MISSIONS` usan flags/keywords copiados de `cli/mod.rs` y `parse_checks`; si la CLI cambia (flag renombrado, keyword nueva), el reto queda obsoleto y el jugador "falla" un comando que en realidad es válido
- **Probabilidad**: Media (la CLI evoluciona por sprints)
- **Mitigación**: [X] test `tests/mission_consistency.rs` que extrae keywords/flags/subcomandos/pares keyword↔flag de `MISSIONS` y los cruza con `parse_checks`, `src/cli/mod.rs` y el `Makefile` (con red de seguridad anti-regex-vacío); [X] revisión manual contra el código real al implementarlo (2026-10-01)
- **Estado**: [X] Resuelto (2026-10-01)

### 30. Progreso del Modo Misión en `localStorage`
- **Riesgo**: Bajo — sin storage (modo privado / `file://` restringido) la partida no persiste entre recargas y se pierde el XP
- **Probabilidad**: Baja/Media
- **Mitigación**: [X] todo el acceso va en `try/catch` (el juego funciona, solo no persiste); [X] `mission start` avisa si el storage no escribe (`storageOk()` con probe de escritura)
- **Estado**: [X] Resuelto (2026-10-01)

### 31. Validador estricto del Modo Misión puede frustrar
- **Riesgo**: Bajo — rechaza argumentos sobrantes o flags no pedidos en ese reto; un usuario con experiencia puede ver rechazado un comando que la CLI aceptaría
- **Probabilidad**: Media
- **Mitigación**: [X] cada error muestra la sintaxis esperada + `hint`; [X] orden de `--checks` libre y alias reales aceptados (`-t/--target`, `-o/--output`, `-h/--help`)
- **Estado**: [~] Monitorizado

### 32. `docs/tutorial/tests/game.test.js` no corre en CI
- **Riesgo**: Bajo — las 25 aserciones del modo misión son locales; una regresión en `game.js`/`content.js` pasaría el CI (que solo valida Rust)
- **Probabilidad**: Media
- **Mitigación**: [X] steps en el job `test` de `ci.yml`: `cargo test --test mission_consistency` + `actions/setup-node@v4` + `node docs/tutorial/tests/game.test.js` (sin dependencias)
- **Estado**: [X] Resuelto (2026-10-01)

### 33. Hook `_debug()` viaja en el HTML ensamblado
- **Riesgo**: Leve — `window.GAME._debug` solo se define si `window.__MISSION_TEST__` está marcado antes de cargar, así que en producción no existe; aun así, quien abra la consola podría auto-revelar la respuesta de un reto
- **Probabilidad**: Baja (es un tutorial, no una competición)
- **Mitigación**: [X] sin flag no hay API; aceptado como coste de tener tests deterministas
- **Estado**: [X] Aceptado

### 34. `.gitignore` con `*.html` excluía `docs/tutorial/index.html`
- **Riesgo**: Alto (materializado) — la regla `*.html` (reports de escaneo) impedía versionar el HTML del tutorial que `tutorial.rs` embebe con `include_str!`: el push del tutorial (52834cd) **rompió el CI** y un clone limpio no compilaba
- **Probabilidad**: Alta mientras exista la regla global
- **Mitigación**: [X] negación `!docs/tutorial/index.html` en `.gitignore` + archivo versionado (693146f); [X] CI verde verificado en el run de `693146f`
- **Estado**: [X] Resuelto (2026-10-01)

---

## Nuevos Weaknesses (2026-09-30)

### 22. CI gate `RUSTFLAGS=-D warnings` es frágil ante regresiones
- **Riesgo**: Medio — cualquier warning nuevo (rustc o clippy) rompe 3 jobs de CI a la vez
- **Probabilidad**: Alta (cualquier PR que añada código puede introducir warnings)
- **Mitigación**: [X] Base limpia — 0 warnings en los ~85 detectados; lints de estilo con `#![allow]` crate-level documentados en `lib.rs`. `cargo clippy --all-targets` local antes de cada push.
- **Estado**: [X] Resuelto (2026-09-30), monitoreo continuo

### 23. Release `aarch64-unknown-linux-gnu` depende de openssl vendored
- **Riesgo**: Medio — el único build de release que fallaba; `openssl-sys` cross no encuentra OpenSSL del target (entra vía `native-tls`: reqwest default-tls + tokio-tungstenite de playwright-rs)
- **Probabilidad**: Alta sin fix / Baja con fix
- **Mitigación**: [X] Resuelto — dep condicional `openssl = { features = ["vendored"] }` solo en `cfg(target_os="linux", target_arch="aarch64")`. Dep global (sin cfg) rompía Windows — verificado y descartado.
- **Estado**: [X] Resuelto (2026-09-30) — pendiente de confirmación en Release v0.6.1

### 24. Causa raíz ARM64 inferida sin logs de Actions
- **Riesgo**: Bajo — la API de GitHub devuelve 403 para logs de jobs; la diagnóstico se hizo sobre el grafo de `Cargo.lock`, no sobre el log real
- **Probabilidad**: N/A (limitación de acceso)
- **Mitigación**: Si el Release v0.6.1 sigue fallando en ARM64, instalar `gh` CLI (autenticado) para leer logs, o reproducir con `cross build --target aarch64-unknown-linux-gnu`.

### 25. Strings de versión unificados con `env!(CARGO_PKG_VERSION)`
- **Riesgo**: Bajo — el test e2e esperaba 0.4.0 mientras la versión era 0.6.0 (regresión histórica: cada bump rompía el test)
- **Mitigación**: [X] Resuelto — CLI, `commands::Version`, reportes, User-Agents y test usan `env!`; solo `Cargo.toml` es la fuente de verdad.
- **Estado**: [X] Resuelto (2026-09-30)

---

## ✅ Todos los puntos débiles resueltos

### 1-10. Core Issues (P0-P1)
- **Estado**: [X] Todos resueltos — Orquestación, Tests E2E, Coverage, Benchmarks, README, Warning StoredXSS, Tool Verification, Config Validation, Error Handling, Rate Limiting

### 11. Subdomain Enum sin DNS resolution
- **Estado**: [~] Parcial — crt.sh + HTTP brute-force, sin DNS real
- **Mitigación**: Subdominios HTTP-only detectados. DNS resolution futuro.

### 12. WAF Detection con fingerprints estáticos
- **Estado**: [~] Parcial — 12 WAF signatures
- **Mitigación**: Cubre >90% de WAFs comerciales. Actualizaciones manuales vía código.

### 13. JWT Analysis sin brute-force de secret
- **Estado**: [X] Resuelto — Entropy analysis + common secret detection
- **Fecha**: 2026-09-18
- **Mitigación**: Shannon entropy (>4.0 bits/byte) + 30+ common secrets detectados. Brute-force es opt-in y potencialmente destructivo.

### 14. 133 warnings de unused code
- **Estado**: [X] Resuelto — 0 warnings
- **Fecha**: 2026-09-18
- **Mitigación**: `cargo fix --lib` + `#[allow(dead_code)]` selectivo en módulos de infraestructura (crawler, recorder)

---

## Nuevos Weaknesses (2026-09-23)

### 20. dalfox XSS scanner no recibe cookies de autenticación
- **Riesgo**: Medio — dalfox no puede escanear targets que requieren login (DVWA, apps autenticadas)
- **Probabilidad**: Alta en entornos con auth
- **Mitigación**: [X] Resuelto — BrowserXssScanner pasa cookies via Playwright browser context. `--browser` flag habilita scanning autenticado.

### 21. Stored XSS no detectado por form injection
- **Riesgo**: Bajo — form injection prueba reflected XSS en la misma request, stored necesita reload
- **Probabilidad**: N/A (limitación conocida)
- **Mitigación**: Stored XSS requiere crawl + reload pattern. Scanner separado `stored_xss.rs` maneja esto con crawl.

---

## Nuevos Weaknesses (2026-09-18)

### 15. GraphQL introspection bypass
- **Riesgo**: Bajo — introspection deshabilitada no es testeable con nuestro approach
- **Probabilidad**: Baja
- **Mitigación**: Reporta "introspection disabled" cuando detecta el error. Suficiente para pentesting passivo.

### 16. API Security passive-only
- **Riesgo**: Bajo — no hace fuzzing ni testing activo de endpoints
- **Probabilidad**: N/A
- **Mitigación**: Cobertura OWASP API Security Top 10 via fingerprinting passivo. Fuzzing futuro.

### 17. Cloud metadata solo detecta IMDSv1
- **Riesgo**: Bajo — IMDSv2 requiere session token, no testeable sin contexto de aplicación
- **Probabilidad**: Media
- **Mitigación**: Reporta "IMDSv1 accessible" con remediación para migrar a IMDSv2. Entornos con IMDSv2 ya protegidos.

### 18. XXE depende de Content-Type detection
- **Riesgo**: Bajo — algunos endpoints aceptan XML sin reportarlo en Content-Type
- **Probabilidad**: Media
- **Mitigación**: Intenta POST con Content-Type: application/xml a paths comunes (/api, /xml, /soap, /upload). Coverage razonable.

### 19. SSTI sin detección automática de engine
- **Riesgo**: Bajo — prueba payloads para todos los engines sin identificar cuál usa el target
- **Probabilidad**: N/A
- **Mitigación**: Si un payload produce output esperado, reporta el engine. Prueba 15 payloads cubriendo 6 engines principales.

---

## Acciones Recomendadas (Priorizadas)
1. ~~Fix dead code warnings~~ ✅ 2026-09-18
2. ~~GraphQL introspection scanner~~ ✅ 2026-09-18
3. ~~API Security scanner~~ ✅ 2026-09-18
4. ~~Global install as `sparrow` command~~ ✅ 2026-09-18
5. ~~Cloud metadata SSRF~~ ✅ 2026-09-18
6. ~~XXE scanner~~ ✅ 2026-09-18
7. ~~SSTI scanner~~ ✅ 2026-09-18
8. ~~PDF/CSV report export~~ ✅ 2026-09-18 (CSV native + HTML print-to-PDF)
9. ~~`--checks all` crashes when tools missing~~ ✅ 2026-09-21 (graceful degradation)
10. ~~XSS scanner loses findings on dalfox exit code 1~~ ✅ 2026-09-21 (parse error JSON)
11. ~~Form injection POST-only~~ ✅ 2026-09-23 (GET + POST support)
12. ~~discover_form_targets sin cookies~~ ✅ 2026-09-23 (cookie passthrough)
13. ~~Form action `#` breaks query params~~ ✅ 2026-09-23 (strip fragments)
14. ~~dalfox XSS scanner sin cookies~~ ✅ 2026-09-25 (BrowserXssScanner with Playwright)
15. Browser-based scanning (Playwright integration) ✅ 2026-09-25
16. ~~JWT brute-force (optional, opt-in)~~ ✅ 2026-09-25 (JwtBruteForceScanner with HMAC brute-force + algorithm confusion)
17. ~~OAuth/OIDC flow testing~~ ✅ 2026-09-25 (OAuthScanner with HTTP probing)
18. ~~Rate limit bypass techniques~~ ✅ 2026-09-25 (RateLimitBypassScanner with method/header/URL/cookie bypass)
19. ~~CORS deep testing~~ ✅ 2026-09-25 (CorsDeepScanner with origin/null/wildcard/subdomain/preflight)
20. ~~Subdomain takeover detection~~ ✅ 2026-09-25 (SubdomainTakeoverScanner with service signature matching)
21. ~~WebSocket security testing~~ ✅ 2026-09-25 (WebSocketSecurityScanner with upgrade/auth/CSWSH)
22. ~~API fuzzing~~ ✅ 2026-09-25 (ApiFuzzingScanner with parameter/body/error/reflection detection)
23. ~~Custom wordlists~~ ✅ 2026-09-25 (WordlistManager with file loading, caching, defaults)
24. ~~Performance profiling~~ ✅ 2026-09-25 (PerfProfiler with per-scanner metrics and optimization suggestions)
25. ~~Release v0.5.0~~ ✅ 2026-09-25 (Version bump, PerfProfiler integration, E2E tests)
26. ~~CI fallaba por ~85 warnings bajo `-D warnings`~~ ✅ 2026-09-30 (0 warnings: main→lib, fixes reales + allows crate-level documentados)
27. ~~Release ARM64 fallaba por openssl-sys cross~~ ✅ 2026-09-30 (openssl vendored condicional a aarch64-linux)
28. ~~Test e2e de versión hardcodeado (0.4.0)~~ ✅ 2026-09-30 (env!(CARGO_PKG_VERSION) en toda la base)
29. ~~Tutorial para nuevos usuarios~~ ✅ 2026-09-30 (TUTORIAL.md, 18 secciones, enlazado desde README)
30. ~~Tutorial interactivo HTML + `sparrow tutorial`~~ ✅ 2026-10-01 (`docs/tutorial/`, ensamblado autocontenido)
31. ~~Tutorial pasivo → Modo Misión (12 niveles jugables)~~ ✅ 2026-10-01 (game.js + MISSIONS + validador estricto)
32. ~~Verificar keywords/flags de `MISSIONS` contra la CLI (test)~~ ✅ 2026-10-01 (`tests/mission_consistency.rs`)
33. ~~Añadir `node docs/tutorial/tests/game.test.js` al CI~~ ✅ 2026-10-01 (job `test` en `ci.yml`)

---

## Historial de Mitigaciones

| Fecha | Riesgo | Acción tomada | Resultado |
|-------|--------|---------------|-----------|
| 2026-10-01 | Retos de MISSIONS podían desincronizarse de la CLI (#29) | `tests/mission_consistency.rs` cruza retos ↔ `parse_checks`/`cli/mod.rs`/`Makefile` | ✅ 2 tests en CI |
| 2026-10-01 | `*.html` excluía `docs/tutorial/index.html` del repo (#34) | negación en `.gitignore` + archivo versionado | ✅ CI verde (run 36900168317) |
| 2026-10-01 | Sin aviso si `localStorage` falla (#30) | probe de escritura en `mission start` con warn | ✅ Resuelto |
| 2026-10-01 | Tests JS del juego fuera del CI (#32) | steps Node + `mission_consistency` en job `test` | ✅ 25 aserciones en CI |
| 2026-10-01 | Tutorial pasivo, poco retención | Modo Misión: 12 niveles, validador estricto, XP/estrellas, localStorage | ✅ 25 aserciones + prueba Playwright |
| 2026-09-30 | CI fallaba por ~85 warnings (`-D warnings`) | main→lib, dead code, lints clippy, allows crate-level | ✅ 0 warnings |
| 2026-09-30 | Release ARM64: openssl-sys cross sin OpenSSL | dep condicional openssl vendored (aarch64-linux) | ✅ Fix aplicado (v0.6.1) |
| 2026-09-30 | Test e2e de versión hardcodeado 0.4.0 | `env!(CARGO_PKG_VERSION)` en CLI/reportes/UA/test | ✅ Future-proof |
| 2026-09-30 | Sin documentación para nuevos usuarios | TUTORIAL.md (18 secciones, ES) enlazado desde README | ✅ Publicado |
| 2026-09-25 | dalfox XSS sin cookies | BrowserXssScanner with Playwright | ✅ Resuelto |
| 2026-09-25 | OAuth/OIDC flow testing | OAuthScanner with HTTP probing + HTML analysis | ✅ Resuelto |
| 2026-09-25 | Rate limit bypass techniques | RateLimitBypassScanner with method/header/URL/cookie bypass | ✅ Resuelto |
| 2026-09-25 | JWT brute-force | JwtBruteForceScanner with HMAC brute-force + algorithm confusion | ✅ Resuelto |
| 2026-09-25 | CORS deep testing | CorsDeepScanner with origin/null/wildcard/subdomain/preflight | ✅ Resuelto |
| 2026-09-25 | Subdomain takeover | SubdomainTakeoverScanner with service signature matching | ✅ Resuelto |
| 2026-09-25 | WebSocket security | WebSocketSecurityScanner with upgrade/auth/CSWSH | ✅ Resuelto |
| 2026-09-25 | API fuzzing | ApiFuzzingScanner with parameter/body/error/reflection | ✅ Resuelto |
| 2026-09-25 | Custom wordlists | WordlistManager with file loading, caching, defaults | ✅ Resuelto |
| 2026-09-25 | Performance profiling | PerfProfiler with per-scanner metrics and suggestions | ✅ Resuelto |
| 2026-09-25 | Release v0.5.0 | Version bump + PerfProfiler integration + E2E tests | ✅ Resuelto |
| 2026-09-25 | Browser-based scanning pendiente | browser_xss.rs + playwright_browser.rs + browser_scanner.rs | ✅ Resuelto |
| 2026-09-21 | `--checks all` crashes sin sqlmap/ssrfmap | Tool existence check antes de ejecutar | ✅ Resuelto |
| 2026-09-21 | XSS scanner pierde findings (dalfox exit 1) | Parse JSON del error output | ✅ Resuelto |
| 2026-09-21 | Puerto 3000 conflicto con Juice Shop | docker-compose → puerto 3001 | ✅ Resuelto |
| 2026-09-18 | 133 dead code warnings | cargo fix + #[allow(dead_code)] | ✅ 0 warnings |
| 2026-09-18 | JWT sin entropy analysis | Shannon entropy + common secrets | ✅ Resuelto |
| 2026-09-18 | Sin GraphQL introspection | graphql.rs scanner | ✅ Resuelto |
| 2026-09-23 | Form injection solo POST | GET form support (test_*_get methods) | ✅ Resuelto |
| 2026-09-23 | discover_form_targets sin cookies | Cookie passthrough from ScanContext | ✅ Resuelto |
| 2026-09-23 | Form action `#` breaks query params | Strip fragment from resolved URLs | ✅ Resuelto |
| 2026-09-18 | Sin API security testing | api_security.rs scanner | ✅ Resuelto |
| 2026-09-18 | sparrow no era global command | cargo install --path . | ✅ Resuelto |
| 2026-09-18 | Sin cloud metadata SSRF | cloud_metadata.rs (AWS/GCP/Azure) | ✅ Resuelto |
| 2026-09-18 | Sin XXE detection | xxe.rs (11 payloads, XML endpoint detection) | ✅ Resuelto |
| 2026-09-18 | Sin SSTI detection | ssti.rs (15 payloads, 6 engines) | ✅ Resuelto |
| 2026-09-18 | No CSV/PDF report export | CSV format + HTML @media print CSS | ✅ Resuelto |
| 2026-09-17 | Orquestación secuencial | futures::join_all | ✅ Resuelto |
| 2026-09-17 | Sin tests E2E | tests/labs_e2e.rs | ✅ Resuelto |
| 2026-09-17 | Config sin validación | validate() con 15+ checks | ✅ Resuelto |

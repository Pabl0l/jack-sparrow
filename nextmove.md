# Jack Sparrow - Next Move

## Estado Actual del Proyecto

**Fecha:** 2026-09-15 (actualizado)
**Versión:** 0.2.0
**Lenguaje:** Rust 2021 edition
**Ubicación:** `C:\Users\jpom1\OneDrive\Escritorio\PROYECTOS\jack-sparrow`

### Módulos Completados
- **Phase 8:** Recorder (HAR 1.2) - `src/core/recorder/`
- **Phase 9:** Reporter (JSON/HTML/MD) - `src/output/report.rs`
- **Phase 10:** Tests - 30/30 passing (unit + E2E + integration)
- **Phase 11:** Docs - README.md completo
- **Phase 12:** Auth support (cookies/headers) - ScanContext + CLI flags
- **Phase 13:** SSRF scanner (ssrfmap integration)
- **Phase 14:** Security Headers scanner

### Scanners Implementados
| Scanner | Archivo | Estado |
|---------|---------|--------|
| SQLi | `src/core/scanners/sqli.rs` | Funcional + cookies/headers soporte |
| XSS | `src/core/scanners/xss.rs` | Reflejado + cookies via dalfox |
| IDOR | `src/core/scanners/idor.rs` | Funcional + auth headers via reqwest |
| SSRF | `src/core/scanners/ssrf.rs` | Funcional via ssrfmap + cookies en request |
| Supply Chain | `src/core/scanners/supply_chain.rs` | Funcional |
| Security Headers | `src/core/scanners/headers.rs` | **NUEVO** - Verifica 7 headers de seguridad |

### Archivos Clave del Proyecto
```
src/
├── main.rs
├── core/
│   ├── scanners/
│   │   ├── mod.rs
│   │   ├── sqli.rs          # SQLi via sqlmap
│   │   ├── xss.rs           # XSS via dalfox
│   │   ├── idor.rs          # IDOR custom
│   │   ├── ssrf.rs          # SSRF (placeholder)
│   │   └── supply_chain.rs  # npm/pip/cargo audit
│   ├── recorder/
│   │   ├── mod.rs
│   │   ├── har.rs           # HAR 1.2 types
│   │   └── browser.rs       # Playwright recorder
│   └── runner.rs
├── commands/
│   └── mod.rs               # CLI commands (scan, record)
├── shared/
│   ├── config.rs            # Jack SparrowConfig
│   └── tool_checker.rs      # Tool availability check
└── output/
    └── report.rs            # Report generation

lab/
├── docker-compose.yml       # DVWA, Juice Shop, WebGoat, SSRF Lab
├── scan-config.toml         # Tool paths config
├── ssrf-lab.py              # Custom SSRF lab
├── sqlmap/                  # sqlmap clone (blocked by Defender)
└── dvwa/                    # DVWA clone
```

### Dependencias Principales
- `playwright-rs = "0.15.1"` - Browser automation (v API específica)
- `clap = { version = "4.5", features = ["derive"] }` - CLI
- `reqwest = "0.12"` - HTTP client
- `ctrlc = "3"` - SIGINT handling

### Labs Docker (Corriendo)
| Lab | Puerto | Estado |
|-----|--------|--------|
| DVWA | 80 | Activo, DB inicializada |
| Juice Shop | 3001 | Activo (remapped de 3000) |
| WebGoat | 8080 | Activo |
| SSRF Lab | 5000 | Activo (fix applied) |

### Tools Instalados
- **sqlmap:** Via Docker (`googlesky/sqlmap`) - Windows Defender bloquea la instalación nativa
  - Wrapper script: `C:\Users\jpom1\AppData\Local\Temp\sqlmap.bat`
- **dalfox:** v3.2.2 instalado nativamente
- **ssrfmap:** v0.1.0 via GitHub clone
  - Wrapper script: `C:\Users\jpom1\AppData\Local\Temp\ssrfmap.bat`

### Config Actual (`lab/scan-config.toml`)
```toml
[tools]
sqlmap_path = "C:\\Users\\jpom1\\AppData\\Local\\Temp\\sqlmap.bat"
dalfox_path = "C:\\Users\\jpom1\\AppData\\Local\\Miniconda3\\Scripts\\dalfox.exe"
ssrfmap_path = "C:\\Users\\jpom1\\AppData\\Local\\Temp\\ssrfmap.bat"
```

---

## Hallazgos de las Pruebas con Labs

### DVWA - SQL Injection (CRITICAL)
- 4 tipos: boolean-blind, error-based, time-based, UNION query
- Backend: MySQL >= 5.1 (MariaDB) en Linux Debian 9
- Extracción de datos confirmada
- **Payloads en:** `reports/dvwa-sqli.txt` (via sqlmap)

### DVWA - XSS Reflected (MEDIUM)
- Parámetro `name` vulnerable
- Payload: `<svg onload=alert(1)>`
- 184 requests para confirmar
- **Resultado en:** `reports/dvwa-xss.json`

### SSRF Lab - SSRF (CRITICAL)
- Endpoint `/fetch?url=` permite acceso a endpoints internos
- Leak de credenciales: `admin:admin123`, `db_password:p@ssw0rd`
- Datos secretos expuestos
- **Fix aplicado:** Cambiado de `curl` subprocess a Python `requests`

### Juice Shop - LIMPIO
- Angular + CSP previene XSS reflejado
- Necesita análisis más profundo (IDOR, Broken Access Control, etc.)

---

## Problemas Encontrados durante las Pruebas

### 1. ~~Sin soporte de cookies/sesión (CRÍTICO)~~ ✅ RESUELTO
- ~~DVWA requiere login, nuestro scanner no pasa cookies a sqlmap~~
- **Solución implementada:** `--cookie` y `--header` flags en CLI, `ScanContext` struct
- sqlmap recibe `--cookie`, dalfox recibe `.cookie()`, reqwest client recibe Cookie header

### 2. sqlmap Falla por Firma Digital
- Windows Defender bloquea `sqlmap.py` como PUP
- No hay permisos de admin para agregar exclusiones
- **Solución actual:** Docker wrapper (`googlesky/sqlmap`)
- **Solución ideal:** Instalar sqlmap en Linux o usar WSL

### 3. No hay Crawling
- Solo testea endpoints que el usuario pasa manualmente
- No descubre la superficie de ataque completa
- **Solución:** Implementar crawler básico que siga links

### 4. XSS limitado a Reflejado
- Solo testea parámetros URL con dalfox
- No detecta Stored XSS (necesita login + persistencia)
- No detecta DOM XSS (necesita análisis estático de JS)

### 5. ~~SSRF no Implementado~~ ✅ RESUELTO
- ~~ssrfmap no está instalado~~
- **Solución implementada:** ssrfmap clone + wrapper .bat + scanner actualizado
- Detecta SSRF en lab (readfiles, portscan)

### 6. IDOR no Probado
- Scanner existe pero sin soporte de sesión
- No puede testear endpoints autenticados

### 7. ~~Sin Detección de WAF/Protecciones~~ parcialmente resuelto
- ~~No identifica WAF, CSP, rate limiting~~
- **Ahora detecta:** Headers de seguridad (CSP, HSTS, X-Frame-Options, etc.)
- **Pendiente:** Detección activa de WAF

### 8. ~~Sin Análisis de Headers de Seguridad~~ ✅ RESUELTO
- **Scanner implementado:** `src/core/scanners/headers.rs`
- Verifica 7 headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection

### 9. Sin Extracción de Tecnologías
- No identifica framework, versiones, tecnologías usadas

---

## Próximos Pasos (Roadmap)

### P0 - Inmediato (Esta semana) ✅ COMPLETADO
1. ~~**Agregar `--cookie` y `--header` al CLI**~~ ✅
   - Modificado `src/cli/mod.rs` para aceptar cookies y headers
   - Creado `ScanContext` para transportar auth a través de la cadena
   - sqlmap recibe `--cookie` y `--header`, dalfox recibe `.cookie()`
   - Testear con DVWA autenticado

2. ~~**Fix ssrf-lab.py + instalar ssrfmap**~~ ✅
   - ssrf-lab.py ya fue fixeado (cambiado a Python requests)
   - ssrfmap instalado via GitHub clone + wrapper .bat
   - `src/core/scanners/ssrf.rs` funcional

3. ~~**Scanner de headers de seguridad**~~ ✅
   - Creado `src/core/scanners/headers.rs`
   - Verifica 7 headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection
   - Detecta headers ausentes y débiles

### P1 - Corto Plazo (2 semanas)
4. **Extracción de tecnologías (tech fingerprint)**
   - Detectar framework, version, server header
   - Identificar librerías JS/CSS
   - Detectar CMS

5. **Scanner de secretos en código fuente**
   - API keys hardcodeadas
   - Tokens de autenticación
   - Credenciales en comentarios
   - .env files expuestos

6. **Mejorar reportes**
   - Agregar CVSS scores
   - Agregar remediation específica
   - Exportar en múltiples formatos

### P2 - Mediano Plazo (1 mes)
7. **Crawler básico de la aplicación**
   - Seguir links y forms
   - Descubrir endpoints API
   - Generar sitemap automático
   - Integrar con scanners existentes

8. **Stored XSS detection**
   - Enviar payload a forms
   - Verificar persistencia en diferentes contexts
   - Testear con diferentes usuarios

9. **DOM XSS analysis (static JS analysis)**
   - Parsear JavaScript
   - Identificar sinks (innerHTML, document.write, eval)
   - Taint analysis básico

### P3 - Largo Plazo (2+ meses)
10. **Subdomain enumeration**
11. **WAF detection**
12. **JWT/session analysis**
13. **GraphQL introspection**
14. **API testing (REST/GraphQL)**

---

## Playwright API Notes (v0.15.1)

### Launching Browser
```rust
let browser_type = playwright.playwright().chromium();
let browser = browser_type_obj.launch_with_options(launch_options).await?;
```

### Creating Context & Page
```rust
let context = browser.new_context().await?;
let page = context.new_page().await?;
```

### Route Interception
```rust
page.route("**/*", move |route| {
    Box::pin(async move {
        let response = route.fetch(None).await?;  // FetchResponse
        let body = response.body();  // &[u8]
        let headers = response.headers();  // &[(String, String)]
        route.fulfill_with_response(response).await
    })
}).await?;
```

### Handler Return Type
```rust
// Must return Result<(), playwright_rs::Error>
// Must use Box::pin(async { ... Ok(()) })
```

### Headers Access
```rust
let headers = route.request().headers();  // HashMap<String, String>
```

---

## Configuración de Desarrollo

### Build Commands
```bash
# Debug build (funcional pero lento)
cargo build

# Release build (timeout en 180s, necesita más tiempo)
cargo build --release

# Tests
cargo test
cargo test -- --nocapture  # con output
```

### Docker Commands
```bash
# Levantar todos los labs
docker-compose -f lab/docker-compose.yml up -d

# Verificar estado
docker ps

# Logs de un lab específico
docker logs dvwa
docker logs juice-shop
docker logs ssrf-lab

# Reiniciar un lab
docker-compose -f lab/docker-compose.yml restart dvwa
```

### Test Commands
```bash
# SQLi test (autenticado con cookies)
.\target\debug\jack-sparrow.exe scan -t "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --checks sqli --cookie "PHPSESSID=xxx; security=low"

# XSS test (con cookies via dalfox)
.\target\debug\jack-sparrow.exe scan -t "http://localhost/vulnerabilities/xss_r/?name=test&Submit=Submit" --checks xss --cookie "PHPSESSID=xxx; security=low"

# SSRF test
.\target\debug\jack-sparrow.exe scan -t "http://localhost:5000/fetch?url=http://127.0.0.1:5000/internal" --checks ssrf --config lab\scan-config.toml

# Security Headers test
.\target\debug\jack-sparrow.exe scan -t "http://localhost" --checks headers

# Con header custom
.\target\debug\jack-sparrow.exe scan -t "http://target/api/admin" --cookie "token=eyJ..." --header "Authorization: Bearer eyJ..."
```

---

## Notas Importantes

1. **Windows Defender bloquea sqlmap.py** - Usar Docker wrapper
2. **No hay permisos de admin** - No se puede agregar exclusiones de Defender
3. **Puerto 3000 en uso** - Juice Shop está en puerto 3001
4. **Docker Desktop necesita estar corriendo** - Los labs dependen de él
5. **sqlmap.bat wrapper** - `C:\Users\jpom1\AppData\Local\Temp\sqlmap.bat`
6. **dalfox usa `--cookies` (plural)** - No `--cookie`

---

## Checklist de Verificación

Antes de cada sesión, verificar:
- [x] Docker Desktop corriendo
- [x] Labs accesibles (DVWA:80, Juice:3001, SSRF:5000)
- [x] `cargo build` funciona sin errores
- [x] `cargo test` pasa (30/30)
- [x] dalfox disponible: `dalfox --version`
- [x] sqlmap wrapper funcional: `.\sqlmap.bat --version`
- [x] ssrfmap wrapper funcional: `.\ssrfmap.bat --help`

---

## Contacto y Contexto

- **Desarrollador:** jpom1
- **Proyecto:** Jack Sparrow - Herramienta CLI para pentesting automatizado
- **Objetivo:** Scanner completo que encuentre SQLi, XSS, IDOR, SSRF, y supply chain vulnerabilities
- **Stack:** Rust + Playwright + sqlmap + dalfox + Docker labs

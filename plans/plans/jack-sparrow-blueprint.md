# Jack Sparrow - Blueprint de Construcción

## Objetivo
Crear una herramienta profesional de pentesting web en Rust, enfocada en 5 vulnerabilidades clave: SQL Injection, XSS, IDOR, SSRF, y Software Supply Chain Failures. La herramienta orquesta herramientas externas probadas y minimiza la interacción del pentester.

## Arquitectura

```
jack-sparrow/
├── src/
│   ├── main.rs                    # Entry point, CLI dispatch
│   ├── lib.rs                     # Re-exports
│   ├── cli/
│   │   ├── mod.rs                 # Cli struct, Commands enum
│   │   ├── scan.rs                # ScanArgs
│   │   ├── record.rs              # RecordArgs (Playwright session)
│   │   └── report.rs              # ReportArgs
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── scan.rs                # execute(args) → runs scan
│   │   ├── record.rs              # execute(args) → records session
│   │   └── report.rs              # execute(args) → generates report
│   ├── core/
│   │   ├── mod.rs
│   │   ├── engine.rs              # ScanEngine, orchestrator
│   │   ├── recorder/              # Playwright session recorder
│   │   │   ├── mod.rs
│   │   │   ├── browser.rs         # Browser automation
│   │   │   └── har.rs             # HAR file generation
│   │   └── scanners/
│   │       ├── mod.rs             # Scanner trait
│   │       ├── sqli.rs            # SQLMap wrapper
│   │       ├── xss.rs             # dalfox-rs wrapper
│   │       ├── idor.rs            # Custom IDOR detector
│   │       ├── ssrf.rs            # ssrfmap wrapper
│   │       └── supply_chain.rs    # npm/pip/cargo audit wrapper
│   ├── shared/
│   │   ├── mod.rs
│   │   ├── types.rs               # Finding, VulnerabilityType, Severity
│   │   ├── config.rs              # Jack SparrowConfig
│   │   ├── error.rs               # Jack SparrowError enum
│   │   └── tool_checker.rs        # Verify external tools installed
│   └── output/
│       ├── mod.rs
│       ├── terminal.rs            # Colored terminal output
│       └── json.rs                # JSON output
├── lab/                           # Docker compose labs
│   ├── docker-compose.yml         # All labs
│   ├── dvwa/
│   ├── juice-shop/
│   └── webgoat/
├── tests/
│   ├── integration/
│   └── e2e/
├── Cargo.toml
├── Makefile
└── README.md
```

## Dependencias Clave

```toml
[dependencies]
# CLI
clap = { version = "4", features = ["derive"] }

# Async runtime
tokio = { version = "1", features = ["full"] }

# HTTP client (for tool orchestration)
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }

# Playwright for session recording
playwright-rs = "0.15"

# XSS scanning (dalfox wrapper)
dalfox-rs = "0.5.5"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
thiserror = "1"
anyhow = "1"

# Terminal output
colored = "2"
indicatif = "0.17"

# UUID for findings
uuid = { version = "1", features = ["v4", "serde"] }

# Chrono for timestamps
chrono = { version = "0.4", features = ["serde"] }

# Regex for pattern matching
regex = "1"

# TOML config
toml = "0.8"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

## Herramientas Externas Requeridas

| Herramienta | Propósito | Instalación |
|-------------|-----------|-------------|
| sqlmap | SQL Injection detection/exploitation | `pip install sqlmap` o binario |
| dalfox | XSS scanning | `cargo install dalfox` |
| ssrfmap | SSRF detection/exploitation | `git clone + pip install` |
| npm audit | Node.js supply chain | `npm install -g npm` |
| pip-audit | Python supply chain | `pip install pip-audit` |
| cargo audit | Rust supply chain | `cargo install cargo-audit` |

## Plan de Implementación

### Fase 1: Scaffolding y Configuración (Día 1)
**Archivos:** `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/cli/`, `src/shared/`

- [ ] Inicializar proyecto Rust con `cargo init`
- [ ] Configurar dependencias en `Cargo.toml`
- [ ] Crear estructura de directorios
- [ ] Implementar CLI con clap (scan, record, report)
- [ ] Definir tipos base: `Finding`, `VulnerabilityType`, `Severity`
- [ ] Implementar `Jack SparrowError` con thiserror
- [ ] Implementar `Jack SparrowConfig` (TOML)
- [ ] Crear `tool_checker.rs` para verificar herramientas externas

**Verificación:**
```bash
cargo build
cargo run -- --help
```

### Fase 2: Motor de Orquestación (Día 2)
**Archivos:** `src/core/engine.rs`, `src/core/scanners/mod.rs`

- [ ] Definir trait `Scanner` con método `scan()`
- [ ] Implementar `ScanEngine` que orquesta múltiples scanners
- [ ] Implementar ejecución concurrente de scanners
- [ ] Implementar manejo de errores por scanner
- [ ] Implementar timeout y cancelación

**Verificación:**
```bash
cargo test --lib
```

### Fase 3: Scanner SQL Injection (Día 3)
**Archivos:** `src/core/scanners/sqli.rs`

- [ ] Implementar wrapper sobre sqlmap
- [ ] Parsear salida JSON de sqlmap
- [ ] Convertir a tipo `Finding` interno
- [ ] Soporte para: error-based, blind, time-based
- [ ] Configuración: level, risk, threads

**Verificación:**
```bash
# Contra DVWA
cargo run -- scan --target http://localhost/dvwa --checks sqli
```

### Fase 4: Scanner XSS con dalfox-rs (Día 4)
**Archivos:** `src/core/scanners/xss.rs`

- [ ] Integrar `dalfox-rs` como dependencia
- [ ] Implementar wrapper con configuración
- [ ] Soporte para: reflected, stored, DOM-based
- [ ] Parsear resultados dalfox a `Finding`
- [ ] Configuración: workers, timeout, waf-evasion

**Verificación:**
```bash
cargo run -- scan --target http://localhost/dvwa --checks xss
```

### Fase 5: Scanner SSRF (Día 5)
**Archivos:** `src/core/scanners/ssrf.rs`

- [ ] Implementar wrapper sobre ssrfmap
- [ ] Generar archivos de request temporales
- [ ] Parsear resultados de ssrfmap
- [ ] Soporte para módulos: readfiles, portscan, networkscan
- [ ] Configuración: level, modules

**Verificación:**
```bash
cargo run -- scan --target http://localhost/ssrf-app --checks ssrf
```

### Fase 6: Scanner IDOR (Día 6-7)
**Archivos:** `src/core/scanners/idor.rs`

- [ ] Implementar detector de parámetros de objeto
- [ ] Probador de IDs secuenciales
- [ ] Comparación de respuestas (status, length, content)
- [ ] Detección de patrones: id, user_id, account_id, etc.
- [ ] Configuración: param-names, range, threshold

**Verificación:**
```bash
cargo run -- scan --target http://localhost/api --checks idor
```

### Fase 7: Scanner Supply Chain (Día 8)
**Archivos:** `src/core/scanners/supply_chain.rs`

- [ ] Detectar ecosistema del target (Node, Python, Rust)
- [ ] Orquestar npm audit / pip-audit / cargo audit
- [ ] Parsear resultados a `Finding`
- [ ] Clasificar por severidad (critical, high, medium, low)
- [ ] Generar reporte de dependencias vulnerables

**Verificación:**
```bash
cargo run -- scan --target /path/to/project --checks supply-chain
```

### Fase 8: Session Recorder con Playwright (Día 9-10)
**Archivos:** `src/core/recorder/`

- [ ] Integrar `playwright-rs`
- [ ] Implementar grabación de sesión
- [ ] Capturar requests y responses
- [ ] Exportar a formato HAR
- [ ] Reutilizar sesión grabada para escaneos

**Verificación:**
```bash
cargo run -- record --output session.har
cargo run -- scan --session session.har --checks xss,sqli
```

### Fase 9: Reporter (Día 11)
**Archivos:** `src/output/`

- [ ] Implementar salida JSON estructurada
- [ ] Implementar salida terminal coloreada
- [ ] Resumen de hallazgos por severidad
- [ ] Estadísticas de escaneo

**Verificación:**
```bash
cargo run -- scan --target http://localhost --output findings.json
```

### Fase 10: Laboratorios y Tests (Día 12-14)
**Archivos:** `lab/`, `tests/`

- [ ] Crear Docker Compose con DVWA, Juice Shop, WebGoat
- [ ] Crear apps de prueba para SSRF y Supply Chain
- [ ] Escribir tests de integración contra laboratorios
- [ ] Escribir tests E2E con assert_cmd
- [ ] Documentar métricas de éxito

**Verificación:**
```bash
docker-compose up -d
cargo test
make test-e2e
```

### Fase 11: Documentación y Polish (Día 15)
**Archivos:** `README.md`, `Makefile`

- [ ] Documentar instalación de herramientas externas
- [ ] Documentar uso de cada scanner
- [ ] Crear Makefile con targets comunes
- [ ] Crear guía de laboratorios
- [ ] Ejecutar escaneo completo y documentar resultados

## Laboratorios de Prueba

### DVWA (Damn Vulnerable Web Application)
- **SQLi:** `/vulnerabilities/sqli/`
- **XSS:** `/vulnerabilities/xss_r/`
- **URL:** `http://localhost:80/dvwa`

### OWASP Juice Shop
- **XSS:** Various endpoints
- **SQLi:** Search functionality
- **IDOR:** `/rest/products/` with ID manipulation
- **URL:** `http://localhost:3000`

### WebGoat
- **SSRF:** XXE/SSRF lessons
- **IDOR:** Access control lessons
- **URL:** `http://localhost:8080/WebGoat`

### Custom SSRF Lab
```python
# ssrf_lab.py
from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    result = subprocess.run(['curl', url], capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    app.run(port=5000)
```

## Métricas de Éxito

| Métrica | Objetivo |
|---------|----------|
| SQLi Detection Rate | >90% contra DVWA |
| XSS Detection Rate | >85% contra DVWA/Juice Shop |
| SSRF Detection Rate | >80% contra lab custom |
| False Positive Rate | <10% |
| Scan Time (single target) | <5 minutos |
| Binary Size | <10 MB |

## Comandos de Verificación por Fase

```bash
# Verificar herramientas externas
cargo run -- check-tools

# Escaneo completo
cargo run -- scan --target http://localhost:80/dvwa --all

# Escaneo específico
cargo run -- scan --target http://localhost:80/dvwa --checks sqli,xss

# Con sesión grabada
cargo run -- scan --session session.har --checks all

# Generar reporte
cargo run -- report --input findings.json --format html --output report.html
```

## Notas de Implementación

1. **Herramientas externas:** Verificar instalación antes de ejecutar
2. **Permisos:** Algunos scans requieren permisos elevados (ssrfmap)
3. **Rate limiting:** Respetar rate limits de las herramientas
4. **Logging:** Guardar logs detallados para debugging
5. **Cancelación:** Soporte para Ctrl+C graceful shutdown

---

*Última actualización: 2026-09-13*

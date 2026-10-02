# 🏴‍☠️ Tutorial de Jack Sparrow — Guía completa para nuevos usuarios

Bienvenido a **Jack Sparrow**, una herramienta profesional de pentesting web que
detecta **30 tipos de vulnerabilidades** desde una sola línea de comando.

Esta guía está pensada para que puedas instalar la herramienta, ejecutar tu
primer escaneo, entender los resultados y avanzar hacia flujos de trabajo
avanzados (autenticación, reportes, laboratorios), sin importar tu nivel.

> **⚠️ Aviso legal y ético**: solo usa Jack Sparrow contra sistemas que te
> pertenezcan o para los que tengas **autorización explícita por escrito**.
> Escanear sistemas ajenos sin permiso es ilegal en la mayoría de países.

---

## Tabla de contenidos

1. [¿Qué hace Jack Sparrow?](#1--qué-hace-jack-sparrow)
2. [Requisitos previos](#2-requisitos-previos)
3. [Instalación](#3-instalación)
4. [Herramientas externas opcionales](#4-herramientas-externas-opcionales)
5. [Primeros pasos](#5-primeros-pasos)
6. [Tu primer escaneo](#6-tu-primer-escaneo)
7. [Todos los checks explicados](#7-todos-los-checks-explicados)
8. [Escaneos autenticados](#8-escaneos-autenticados)
9. [Scanners opt-in (flags avanzados)](#9-scanners-opt-in-flags-avanzados)
10. [Wordlists personalizadas](#10-wordlists-personalizadas)
11. [Grabación de sesiones con navegador](#11-grabación-de-sesiones-con-navegador)
12. [Configuración (jack-sparrow.toml)](#12-configuración-jack-sparrowtoml)
13. [Reportes y formatos de salida](#13-reportes-y-formatos-de-salida)
14. [Laboratorios Docker para practicar](#14-laboratorios-docker-para-practicar)
15. [Cómo interpretar los resultados](#15-cómo-interpretar-los-resultados)
16. [Solución de problemas](#16-solución-de-problemas)
17. [Preguntas frecuentes (FAQ)](#17-preguntas-frecuentes-faq)
18. [Buenas prácticas](#18-buenas-prácticas)

---

## 1. 🏴‍☠️ ¿Qué hace Jack Sparrow?

Jack Sparrow es un **orquestador de escaneos de seguridad web**. En lugar de
obligarte a instalar y recordar la sintaxis de 15 herramientas diferentes, las
invoca por ti, combina sus resultados y los presenta en un reporte unificado.

**Qué lo distingue:**

- **30 scanners** — desde SQL Injection y XSS hasta HTTP Smuggling y Cache Poisoning.
- **Ejecución concurrente** — todos los scanners corren en paralelo con `tokio`.
- **Crawler integrado** — rastrea el sitio (respetando `robots.txt`, con deduplicación
  por filtro Bloom y rate limiting por dominio) para alimentar a los scanners.
- **Degradación elegante** — si falta una herramienta externa (sqlmap, dalfox...),
  la herramienta sigue funcionando con los scanners nativos y te avisa.
- **Reportes profesionales** — JSON, HTML (tema oscuro, listo para PDF), Markdown y CSV,
  con puntuación CVSS y remediación por hallazgo.
- **Multiplataforma** — binarios para Linux (x86/ARM64), macOS (Intel/Apple Silicon) y Windows.

---

## 2. Requisitos previos

| Requisito | Versión mínima | Notas |
|-----------|----------------|-------|
| **Rust + Cargo** | 1.70+ | Solo si compilas desde código |
| **Python 3** | 3.8+ | Opcional — para `sqlmap` y `pip-audit` |
| **Node.js** | 18+ | Opcional — para auditorías `npm` |
| **Git** | cualquiera | Solo para clonar el repositorio |
| **Docker** | cualquiera | Solo si quieres levantar los laboratorios |

**Instalar Rust** (si no lo tienes):

```powershell
# Windows / Linux / macOS — desde https://rustup.rs
winget install Rustlang.Rustup      # Windows
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Linux/macOS
```

Comprueba la instalación:

```bash
rustc --version   # debe mostrar 1.70 o superior
cargo --version
```

---

## 3. Instalación

### Opción A — Descargar el binario (recomendada para usuarios finales)

1. Entra en [Releases](https://github.com/Pabl0l/jack-sparrow/releases).
2. Descarga el archivo de tu plataforma:

| Plataforma | Archivo |
|------------|---------|
| Windows 64-bit | `sparrow-x86_64-pc-windows-msvc.exe.zip` |
| Linux Intel | `sparrow-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (Raspberry Pi, servidores ARM) | `sparrow-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `sparrow-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon (M1/M2/M3/M4) | `sparrow-aarch64-apple-darwin.tar.gz` |

3. Descomprime y ponlo en tu `PATH`:

```powershell
# Windows (PowerShell como administrador)
Expand-Archive sparrow-*.zip -DestinationPath C:\Tools\
# Añade C:\Tools al PATH, o mueve sparrow.exe a una carpeta ya en el PATH

# Linux / macOS
tar -xzf sparrow-x86_64-unknown-linux-gnu.tar.gz
sudo mv sparrow /usr/local/bin/
chmod +x /usr/local/bin/sparrow
```

4. Verifica:

```bash
sparrow version
# Jack Sparrow 0.6.1
```

5. Abre el tutorial interactivo (recomendado justo después de instalar):

```bash
sparrow tutorial
# → se abre en tu navegador el tutorial HTML autocontenido (sin red)
# Alternativa: sparrow tutorial --save tutorial.html
```

Dentro del tutorial escribe `mission start` para jugar al **Modo Misión**: 12 niveles
donde te dan un objetivo y un alcance, y tienes que tipear el comando real de `sparrow`
con la sintaxis correcta para pasar de nivel (XP, estrellas, rangos y retos que cambian
en cada partida).

### Opción B — Compilar desde código

```bash
git clone https://github.com/Pabl0l/jack-sparrow.git
cd jack-sparrow
cargo build --release
```

El binario queda en `target/release/sparrow`:

```powershell
# Windows
.\target\release\sparrow.exe version

# Linux / macOS
./target/release/sparrow version
```

### Opción C — Instalar como comando global

```bash
cd jack-sparrow
cargo install --path .
```

Esto instala `sparrow` en `~/.cargo/bin` (asegúrate de que esa carpeta esté en
tu `PATH`). Después podrás usarlo desde cualquier directorio.

---

## 4. Herramientas externas opcionales

Jack Sparrow detecta automáticamente qué herramientas tienes instaladas. Si
falta alguna, **el escaneo continúa igualmente** con los scanners nativos y solo
se omite el check dependiente.

Ejecuta siempre al principio:

```bash
sparrow check-tools
```

Verás algo como:

```
✔ sqlmap      instalado
✔ dalfox      instalado
✘ ssrfmap     no encontrado  → check ssrf usará el motor nativo
✔ pip-audit   instalado
✔ cargo-audit instalado
```

Para instalarlas todas (en Linux/macOS):

```bash
make install-deps
```

Manualmente, según lo que necesites:

```bash
# SQL Injection (el más importante)
pip install sqlmap

# XSS
cargo install dalfox

# SSRF
git clone https://github.com/swisskyrepo/ssrfmap.git
cd ssrfmap && pip install -r requirements.txt && cd ..

# Supply Chain (Python / Rust)
pip install pip-audit
cargo install cargo-audit
```

> **No usas Windows o no quieres Python?** No pasa nada: Jack Sparrow incluye
> scanners nativos (SQLi, SSRF, XSS) que no requieren herramientas externas.

---

## 5. Primeros pasos

Seis comandos para familiarizarte:

```bash
# 1. Tutorial interactivo (empieza aquí si es tu primera vez)
#    Abre en el navegador una guía estilo terminal con todo el tutorial
sparrow tutorial

# 2. Versión instalada
sparrow version

# 3. Ayuda general
sparrow --help

# 4. Ayuda específica del escaneo (lista todos los flags)
sparrow scan --help

# 5. Verificar herramientas externas
sparrow check-tools

# 6. Generar un archivo de configuración por defecto
sparrow init-config --output jack-sparrow.toml
```

---

## 6. Tu primer escaneo

### Escaneo básico (todo por defecto)

```bash
sparrow scan --target http://localhost/dvwa
```

Esto ejecuta los **scanners base** en paralelo y muestra los hallazgos por
pantalla con colores (🔴 Crítico, 🟠 Alto, 🟡 Medio, 🔵 Bajo, ⚪ Informativo).

### Escaneo selectivo (lo más habitual)

```bash
sparrow scan --target http://localhost/dvwa --checks sqli,xss,headers
```

`--checks` acepta una lista separada por comas. Solo se ejecutan esos scanners:
más rápido y más limpio el resultado.

### Escaneo con reporte HTML

```powershell
sparrow scan --target http://localhost/dvwa --checks all --output report.html --format html
```

Abre `report.html` en el navegador. Es un reporte con tema oscuro, puntuación
CVSS y recomendaciones: puedes imprimirlo a PDF con `Ctrl+P` → *Guardar como PDF*.

### Ajustar concurrencia y timeout

```bash
sparrow scan --target https://mi-app.example.com \
  --checks all \
  --concurrency 8 \
  --timeout 600
```

| Flag | Por defecto | Cuándo subirlo |
|------|-------------|----------------|
| `--concurrency` | `4` | Máquinas con buen ancho de banda y servidores resistentes |
| `--timeout` | `300` (5 min) | Objetivos lentos o escaneos `--checks all` grandes |

### Salida JSON para procesar programáticamente

```bash
sparrow scan --target http://localhost --checks headers,tech --output results.json --format json
```

Útil para tuberías CI/CD o para alimentar dashboards.

---

## 7. Todos los checks explicados

Lista completa que puedes pasar a `--checks` (separados por comas):

### Checks incluidos por defecto

| Check | Qué detecta | Herramienta |
|-------|-------------|-------------|
| `sqli` | SQL Injection (nivel/risk/tamper configurables) | sqlmap + motor nativo |
| `xss` | Todos los XSS (reflected + stored + DOM) | dalfox + motores nativos |
| `xss-reflected` | Solo XSS reflejado | dalfox |
| `xss-stored` | Solo XSS persistente (inyecta en formularios y verifica persistencia) | motor nativo |
| `xss-dom` | Solo DOM XSS (análisis estático de JavaScript: source → sink) | motor nativo |
| `idor` | Referencia directa a objetos inseguras (IDs secuenciales, enumeración de rutas) | motor nativo |
| `ssrf` | Server-Side Request Forgery | ssrfmap + motor nativo |
| `supply-chain` | Dependencias vulnerables | npm audit / pip-audit / cargo-audit |
| `headers` | 7 cabeceras de seguridad (CSP, HSTS, X-Frame-Options...) | motor nativo |
| `tech` | Fingerprinting: framework, versión, CMS, servidor | motor nativo |
| `secrets` | API keys, tokens y credenciales expuestas en el código fuente | motor nativo |
| `subdomains` | Enumeración de subdominios (Certificate Transparency + brute-force) | motor nativo |
| `waf` | Detección de WAF (12 fingerprints: Cloudflare, AWS, Akamai...) | motor nativo |
| `jwt` | Análisis JWT: decodificación, entropía, secretos comunes, claims | motor nativo |
| `graphql` | Introspección GraphQL: esquema, mutaciones peligrosas, argumentos inyectables | motor nativo |
| `api` | Seguridad de API: CORS, métodos HTTP, rate limiting, divulgación de errores | motor nativo |
| `cloud-metadata` | SSRF a metadatos cloud (AWS/GCP/Azure IMDS) con ofuscación de IPs | motor nativo |
| `xxe` | XML External Entity (lectura de ficheros, SSRF vía XXE) | motor nativo |
| `ssti` | Template injection (Jinja2, Smarty, Freemarker, ...) | motor nativo |
| `all` | **Todos los anteriores** (es el valor por defecto) | — |

### Checks opt-in (se activan con flags, ver sección 9)

| Flag | Qué activa |
|------|------------|
| `--browser` | XSS vía navegador real (Playwright) |
| `--oauth` | Flujos OAuth/OIDC (CSRF, open redirect) |
| `--rate-limit` | Bypass de rate limiting (cambio de método, spoofing de IP...) |
| `--jwt-bruteforce` | Fuerza bruta HMAC + confusión de algoritmo (requiere `--header` con token) |
| `--cors` | Pruebas CORS en profundidad (reflexión de Origin, null origin, wildcard) |
| `--takeover` | Takeover de subdominios (20 firmas de servicios + análisis CNAME) |
| `--websocket` | Seguridad WebSocket (auth ausente, CSWSH, validación de origin) |
| `--api-fuzz` | Fuzzing de parámetros API (25 parámetros, payloads de inyección) |
| `--smuggling` | HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, H2) |
| `--auth-bypass` | Bypass de autenticación (credenciales por defecto, inyección de cabeceras) |
| `--graphql-attack` | Ataques GraphQL (batch DoS, abuso de mutaciones, extracción de esquema) |
| `--cache-poisoning` | Web Cache Poisoning (headers unkeyed, parameter cloaking) |

---

## 8. Escaneos autenticados

Muchas vulnerabilidades solo son visibles **después de iniciar sesión**. Tres formas de hacerlo —y se pueden **combinar**: si pasas varias fuentes, la precedencia es `--cookie` > login automático > sesión grabada (en conflictos de nombre manda la más explícita).

### A) Con cookie (la más rápida)

```bash
sparrow scan --target http://localhost/dvwa \
  --checks sqli,xss,idor \
  --cookie "PHPSESSID=abc123; security=low"
```

> **Consejo**: extrae la cookie desde las DevTools del navegador
> (F12 → Red → cualquier petición → Cabeceras → Cookie).

### B) Con cabeceras personalizadas (tokens, API keys)

```bash
sparrow scan --target https://api.example.com/v1 \
  --checks api,idor,secrets \
  --header "Authorization: Bearer eyJhbGciOi..." \
  --header "X-Api-Key: mi-clave-secreta"
```

`--header` es **repetible**: pasa una cabecera por cada flag, formato `"Clave: Valor"`.

### C) Con login automático por formulario

Si el sitio usa un formulario de usuario/contraseña:

```bash
sparrow scan --target http://localhost/dvwa \
  --checks all \
  --login-url http://localhost/dvwa/login.php \
  --login-user admin \
  --login-pass password
```

Si los campos del formulario tienen otros nombres:

```bash
sparrow scan --target http://mi-app.local \
  --checks all \
  --login-url http://mi-app.local/session \
  --login-user juan@empresa.com \
  --login-pass "MiClave123" \
  --login-field-user email \
  --login-field-pass clave \
  --login-field "tenant=acme"
```

| Flag | Descripción |
|------|-------------|
| `--login-url` | URL que recibe el POST del login |
| `--login-user` / `--login-pass` | Credenciales |
| `--login-field-user` | Nombre del campo de usuario (defecto: `username`) |
| `--login-field-pass` | Nombre del campo de contraseña (defecto: `password`) |
| `--login-field` | Campos extra del formulario, formato `"nombre=valor"` (repetible) |

Jack Sparrow descubre solo los campos ocultos de la página (tokens CSRF como
el `user_token` de DVWA) y **recoge las cookies tanto del GET inicial como del
POST de login**, así que funciona con apps PHP que emiten el `PHPSESSID` al
abrir sesión y no lo repiten después. Puedes añadir `--cookie` encima: se
fusiona y en conflicto manda tu valor.

---

## 9. Scanners opt-in (flags avanzados)

Algunos scanners son potentes pero pueden ser **ruidosos o lentos**, así que se
activan explícitamente:

```bash
sparrow scan --target https://app.example.com \
  --checks all \
  --cors \
  --takeover \
  --smuggling \
  --auth-bypass
```

Ejemplo completo con todos los opt-in:

```bash
sparrow scan --target https://app.example.com \
  --checks all \
  --browser --visible \
  --oauth \
  --rate-limit \
  --cors \
  --takeover \
  --websocket \
  --api-fuzz \
  --smuggling \
  --auth-bypass \
  --graphql-attack \
  --cache-poisoning
```

Detalles de los más útiles:

### `--browser` (XSS con navegador real)

Usa Playwright para renderizar las páginas y detectar XSS que un scanner
estático no ve:

```bash
sparrow scan --target http://localhost:3001 --checks xss --browser
```

- `--visible` — muestra la ventana del navegador (útil para depurar).
- Requiere Playwright: `playwright install chromium` (ver sección 16).

### `--jwt-bruteforce` (opt-in por seguridad)

Como puede ser lento, se activa aparte y **necesita el token** en una cabecera:

```bash
sparrow scan --target https://app.example.com \
  --checks jwt \
  --jwt-bruteforce \
  --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Prueba: secretos comunes (lista de 30), confusión de algoritmo (`alg: none`,
`HS256` contra clave pública) y fuerza bruta HMAC.

---

## 10. Wordlists personalizadas

Sustituye las listas por defecto de subdominios, rutas, parámetros o contraseñas:

```bash
sparrow scan --target example.com \
  --checks subdomains,sqli,idor \
  --wordlist-subdomain C:\wordlists\subdomains.txt \
  --wordlist-path C:\wordlists\paths.txt \
  --wordlist-param C:\wordlists\params.txt \
  --wordlist-password C:\wordlists\rockyou-top.txt
```

Formato: un elemento por línea, en un fichero de texto UTF-8.

> Puedes combinar `--wordlist-*` con `--checks`: la wordlist afecta al scanner
> correspondiente.

---

## 11. Grabación de sesiones con navegador

Para escanear aplicaciones que usan mucho JavaScript o flujos complejos,
grabe primero tu sesión manualmente y despues escanea con ella:

```bash
# 1. Grabar (se abre Chromium; navega y logueate; Ctrl+C para terminar)
sparrow record --output session.har --browser chromium

# 2. Escanear usando la sesión grabada
sparrow scan --target http://localhost:3001 --checks all --session session.har
```

| Flag `record` | Descripción |
|---------------|-------------|
| `--output` | Fichero HAR 1.2 de salida (defecto: `session.har`) |
| `--browser` | `chromium` (defecto), `firefox` o `webkit` |
| `--headless` | Sin ventana visible |

El archivo `.har` contiene peticiones, cookies y tokens de tu navegación. Al
pasarlo con `--session`, Jack Sparrow **extrae las cookies del dominio del
objetivo** (de las cookies de cada petición/respuesta, o de la cabecera
`Cookie` si el HAR no las lista) y las usa en el escaneo, como si fueras tú.
Si además pasas `--login-*` o `--cookie`, se fusionan con esta precedencia:
`--cookie` > login > sesión grabada.

```bash
# Las cookies del HAR del objetivo se aplican solas:
sparrow scan --target http://localhost:3001 --checks all \
  --session session.har --cookie "security=low"
```

---

## 12. Configuración (jack-sparrow.toml)

Genera la plantilla:

```bash
sparrow init-config --output jack-sparrow.toml
```

Pásala a cualquier comando con la flag global `-c` / `--config`:

```bash
sparrow -c jack-sparrow.toml scan --target http://localhost
```

Ejemplo de archivo completo:

```toml
[general]
max_concurrent = 4          # scanners en paralelo
timeout_secs = 300          # timeout global por escaneo
user_agent = "JackSparrow/0.6.1"
verbose = false             # true = log detallado

[scanners.sqli]
level = 3                   # sqlmap --level (1-5)
risk = 1                    # sqlmap --risk (1-3)
threads = 4

[scanners.xss]
workers = 50                # hilos de dalfox
waf_evasion = false         # evasión de WAF (más lento)

[scanners.idor]
param_names = ["id", "user_id", "account_id"]
id_range = [1, 100]         # rango de IDs a probar
similarity_threshold = 0.8  # similitud mínima para comparar respuestas

[scanners.ssrf]
level = 2
modules = ["readfiles", "portscan"]

[scanners.supply_chain]
check_npm = true
check_pip = true
check_cargo = true
```

**Recomendación**: deja los valores por defecto hasta que sepas qué haces; sube
`level`/`risk` de SQLi solo cuando quieras un escaneo más profundo (y más lento).

---

## 13. Reportes y formatos de salida

| `--format` | Uso recomendado |
|------------|-----------------|
| `json` (defecto) | Integración programática, CI/CD, dashboards |
| `html` | Informe para clientes/gerencia — tema oscuro, CVSS, `Ctrl+P` → PDF |
| `markdown` | Documentación interna, wikis, pull requests |
| `csv` | Importar a Excel/Google Sheets para métricas |

```bash
# Informe para cliente
sparrow scan --target https://app.example.com --checks all \
  --output informe.html --format html

# CSV para hoja de cálculo
sparrow scan --target https://app.example.com --checks all \
  --output hallazgos.csv --format csv

# JSON para CI
sparrow scan --target https://staging.example.com --checks all \
  --output results.json --format json
```

Cada hallazgo incluye: severidad, puntuación CVSS, descripción, evidencia,
CWE de referencia y **remediación paso a paso**.

### En CI/CD (ejemplo GitHub Actions)

```yaml
- name: Security scan
  run: |
    sparrow scan --target ${{ vars.STAGING_URL }} --checks all \
      --output scan.json --format json
- name: Fail if critical findings
  run: |
    jq -e '.findings[] | select(.severity == "Critical")' scan.json && exit 1 || exit 0
```

---

## 14. Laboratorios Docker para practicar

Si quieres aprender sin tocar nada de producción, el repositorio incluye apps
vulnerables en Docker:

```bash
make lab-up      # levanta DVWA, Juice Shop, WebGoat y SSRF Lab
make lab-down    # los para
```

O directamente con Docker Compose:

```bash
cd lab
docker compose up -d
```

| Laboratorio | URL | Para practicar |
|-------------|-----|----------------|
| DVWA | http://localhost | SQLi, XSS, IDOR |
| Juice Shop | http://localhost:3001 | XSS moderno, CSP, API REST |
| WebGoat | http://localhost:8080 | Lecciones OWASP |
| SSRF Lab | http://localhost:5000 | Detección SSRF |

Ejemplo de práctica guiada:

```bash
# 1. Levanta DVWA y logueate (admin/password)
make lab-up

# 2. Escanea el objetivo
sparrow scan --target http://localhost \
  --checks sqli,xss,idor,headers \
  --cookie "PHPSESSID=abc123; security=low" \
  --output practica.html --format html

# 3. Abre practica.html y compara con lo que ves en DVWA
```

---

## 15. Cómo interpretar los resultados

### Severidades

| Severidad | Significado | Acción típica |
|-----------|-------------|----------------|
| 🔴 **Critical** | Explotable de forma remota con impacto total (p.ej. SQLi) | Corregir **ya** |
| 🟠 **High** | Impacto serio, explotación sencilla (p.ej. XSS almacenado) | Corregir en este sprint |
| 🟡 **Medium** | Requiere condiciones adicionales o impacto limitado | Planificar |
| 🔵 **Low** | Impacto menor o difícil de explotar | Mejorar cuando se pueda |
| ⚪ **Info** | Contexto útil (versiones, tecnologías) sin fallo directo | Registrar |

### Qué mirar en cada hallazgo

1. **Severity + CVSS** — prioriza primero por CVSS si hay empates.
2. **Evidence** — la prueba concreta (petición/respuesta) de que existe.
3. **Remediation** — cómo corregirlo; sigue el CWE para profundizar.
4. **Confidence** — hallazgos con evidencia dura son más fiables que los
   inferidos.

### Errores frecuentes de interpretación

- **Falsos positivos**: compara siempre la evidencia manualmente antes de
  reportar; baja el `risk` de sqlmap o desactiva `waf_evasion` si hay ruido.
- **Falsos negativos**: un escaneo sin `--cookie` no ve nada tras el login;
  usa la sección 8.
- **WAF bloqueando**: si detectas WAF (`--checks waf`), los otros checks pueden
  fallar en silencio; reintenta con menos concurrencia.

---

## 16. Solución de problemas

### `error: no se encontró la orden 'sparrow'`

- Si compilaste: usa la ruta completa (`./target/release/sparrow`).
- Si instalaste con `cargo install`: reinicia la terminal y verifica que
  `~/.cargo/bin` esté en el `PATH`.

### Los checks de `sqli` o `supply-chain` se omiten

```bash
sparrow check-tools
```

Instala la herramienta que marque como ausente (sección 4). El resto del
escaneo funciona igual sin ella.

### `--browser` falla: "Playwright browser type not found"

```bash
# Instala el runtime de Playwright
playwright install chromium
# o desde Node
npx playwright install chromium
```

### El escaneo tarda demasiado

- Reduce `--checks` a lo que te interesa.
- Baja `--concurrency` si el servidor es lento, súbelo si la red lo permite.
- Evita `--checks all` contra objetivos grandes; segmenta por categorías.

### Errores de conexión / timeouts

- Comprueba que la URL sea alcanzable desde tu máquina.
- Sube `--timeout` (ej. `--timeout 600`).
- Si hay VPN o proxy corporativo, configúralo en el sistema (reqwest respeta
  las variables de entorno `HTTP_PROXY`/`HTTPS_PROXY`).

### Reporte HTML en blanco

Ábrelo con `Ctrl+P` → *Guardar como PDF* en el navegador; el HTML ya está
pensado para imprimirse.

### En Windows: `cargo build` falla por OpenSSL

Los binarios oficiales de Releases ya vienen resueltos. Si compilas desde
código en Windows, no necesitas OpenSSL (se usa SChannel); si usas Linux ARM,
la compilación trae OpenSSL "vendored" automáticamente.

---

## 17. Preguntas frecuentes (FAQ)

**¿Necesito instalar todas las herramientas externas?**
No. Solo `sqlmap` es especialmente recomendable para SQLi. Todo lo demás tiene
alternativas nativas o es opcional.

**¿Puedo usarlo contra un bug bounty?**
Sí, siempre que las reglas del programa lo permitan. Empieza con
`--checks headers,tech,secrets` para un perfilamiento de bajo ruido.

**¿Es agresivo con el servidor?**
El crawler respeta `robots.txt` y aplica rate limiting por dominio. Ajusta
`--concurrency` y `max_concurrent` en la config para regularlo.

**¿Cómo actualizo a una versión nueva?**

```bash
# Binario: descarga el nuevo release
# Desde código:
git pull
cargo install --path .
```

**¿Dónde reporto un fallo de la herramienta?**
En [Issues](https://github.com/Pabl0l/jack-sparrow/issues). Si es sensible,
lee primero `SECURITY.md`.

---

## 18. Buenas prácticas

1. **Autorización primero** — confirma que tienes permiso por escrito.
2. **Empieza pequeño** — `--checks headers,tech` en un objetivo nuevo; luego amplía.
3. **Usa los laboratorios** — practica en DVWA/Juice Shop antes de tocar producción.
4. **Autentica cuando cuente** — la mayoría de hallazgos viven tras el login.
5. **Guarda los reportes** — `--format html` para archivo, `json` para diff entre versiones.
6. **Re-verifica manualmente** — confirma cada hallazgo antes de reportarlo.
7. **Actualiza** — la base de scanners crece en cada release.

---

## Siguiente paso

- 📖 [README del proyecto](README.md) — tabla completa de los 30 scanners y arquitectura.
- 🧪 [Laboratorios](#14-laboratorios-docker-para-practicar) — entorno local para practicar.
- 🐛 [Issues](https://github.com/Pabl0l/jack-sparrow/issues) — dudas y reportes.

¡Bon viaje! 🏴‍☠️

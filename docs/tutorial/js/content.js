/* ============================================================
   sparrow-tutorial — contenido del tutorial (TUTORIAL.md)
   Tipos de línea:
   h       → heading (neon VT323)
   p       → párrafo normal
   dim     → texto atenuado
   ok      → ✔ éxito (neon)
   warn    → ⚠ aviso (ámbar)
   cmd     → comando copiable (bloque)
   code    → bloque de código
   table   → tabla {head, rows}
   link    → enlace {label, url}
   gap     → línea en blanco
   ============================================================ */

const BANNER = String.raw`
 ╭─────────────────────────────────────────────────────────────────╮
 │                                                                 │
 │   ███████╗██████╗  █████╗ ██████╗ ██████╗  ██████╗ ██╗    ██╗   │
 │   ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║    ██║   │
 │   ███████╗██████╔╝███████║██████╔╝██████╔╝██║   ██║██║ █╗ ██║   │
 │   ╚════██║██╔═══╝ ██╔══██║██╔══██╗██╔══██╗██║   ██║██║███╗██║   │
 │   ███████║██║     ██║  ██║██║  ██║██║  ██║╚██████╔╝╚███╔███╔╝   │
 │   ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝    │
 │                                                                 │
 ╰──[ ADVANCED PENTEST TOOL ]──────────────────────[ BY PABL0L ]───╯

    >_ Ready to hack.
`;

const TUTORIAL = {

  /* ---------------- meta ---------------- */
  banner: [
    { t: 'ascii', v: BANNER },
    { t: 'dim', v: '   Tutorial interactivo (v1.0) · contenido generado desde TUTORIAL.md' },
    { t: 'dim', v: '   https://github.com/Pabl0l/jack-sparrow' },
    { t: 'gap' },
    { t: 'p', v: 'Escribe `help` para ver los comandos disponibles. Cada comando abre una sección del tutorial.' },
  ],

  boot: [
    { t: 'ok', v: 'Jack Sparrow Terminal v0.6.1 ... cargado' },
    { t: 'ok', v: 'Módulos del tutorial .... 18/18 listos' },
    { t: 'ok', v: 'Shell interactiva .......... lista' },
    { t: 'gap' },
  ],

  help: [
    { t: 'h', v: 'Comandos disponibles' },
    { t: 'p', v: 'Escribe cualquiera de estos comandos (o pulsa los botones de arriba):' },
    { t: 'gap' },
    { t: 'code', v: [
      '  SECCIONES DEL TUTORIAL',
      '    intro         ¿Qué es Jack Sparrow y qué lo distingue',
      '    install       Instalación (binario / código / cargo install)',
      '    tools         Herramientas externas opcionales (sqlmap, dalfox...)',
      '    start         Primeros pasos y comandos esenciales',
      '    scan          Tu primer escaneo (básico → avanzado)',
      '    checks        Los 30 scanners y sus keywords',
      '    auth          Escaneos autenticados (cookie / header / login)',
      '    advanced      Scanners opt-in (flags avanzados)',
      '    wordlists     Wordlists personalizadas',
      '    session       Grabación de sesiones con navegador',
      '    config        Archivo de configuración jack-sparrow.toml',
      '    reports       Reportes: JSON, HTML, Markdown, CSV + CI/CD',
      '    labs          Laboratorios Docker para practicar',
      '    interpret     Cómo interpretar severidades y hallazgos',
      '    troubleshoot  Solución de problemas comunes',
      '    faq           Preguntas frecuentes',
      '    best          Buenas prácticas',
      '',
      '  UTILIDAD',
      '    help          Esta lista',
      '    version       Versión de la herramienta',
      '    whoami        Quién está detrás',
      '    github        Enlaces al repositorio',
      '    clear         Limpiar pantalla (Ctrl+L)',
    ].join('\n') },
    { t: 'gap' },
    { t: 'dim', v: 'Tip: usa Tab para autocompletar y ↑/↓ para el historial.' },
  ],

  /* ---------------- 1. intro ---------------- */
  intro: [
    { t: 'h', v: '1 · ¿Qué hace Jack Sparrow?' },
    { t: 'p', v: 'Es un orquestador de escaneos de seguridad web: en lugar de recordar la sintaxis de 15 herramientas, las invoca por ti, combina resultados y los presenta en un reporte unificado.' },
    { t: 'gap' },
    { t: 'ok', v: '30 scanners — desde SQL Injection y XSS hasta HTTP Smuggling y Cache Poisoning' },
    { t: 'ok', v: 'Ejecución concurrente — todos los scanners en paralelo con tokio' },
    { t: 'ok', v: 'Crawler integrado — respeta robots.txt, deduplica con filtro Bloom, rate limiting por dominio' },
    { t: 'ok', v: 'Degradación elegante — si falta sqlmap/dalfox, sigue funcionando con motores nativos' },
    { t: 'ok', v: 'Reportes profesionales — JSON, HTML (tema oscuro, PDF), Markdown, CSV con CVSS y remediación' },
    { t: 'ok', v: 'Multiplataforma — Linux (x86/ARM64), macOS (Intel/Apple Silicon), Windows' },
    { t: 'gap' },
    { t: 'warn', v: 'Solo úsalo contra sistemas propios o con autorización explícita por escrito.' },
    { t: 'gap' },
    { t: 'link', label: '📄 Tutorial completo (TUTORIAL.md)', url: 'https://github.com/Pabl0l/jack-sparrow/blob/main/TUTORIAL.md' },
  ],

  /* ---------------- 2. install ---------------- */
  install: [
    { t: 'h', v: '3 · Instalación' },
    { t: 'p', v: 'Tres caminos. Requisito mínimo: Rust 1.70+ solo si compilas desde código.' },
    { t: 'gap' },
    { t: 'p', v: 'Opción A — binario (recomendada):' },
    { t: 'code', v: [
      '# Descarga desde Releases (elige tu plataforma)',
      'https://github.com/Pabl0l/jack-sparrow/releases',
      '',
      '# Linux',
      'tar -xzf sparrow-x86_64-unknown-linux-gnu.tar.gz',
      'sudo mv sparrow /usr/local/bin/ && chmod +x /usr/local/bin/sparrow',
      '',
      '# Windows (PowerShell)',
      'Expand-Archive sparrow-*.zip -DestinationPath C:\\Tools\\',
    ].join('\n') },
    { t: 'gap' },
    { t: 'p', v: 'Opción B — compilar desde código:' },
    { t: 'cmd', v: 'git clone https://github.com/Pabl0l/jack-sparrow.git\ncd jack-sparrow\ncargo build --release' },
    { t: 'gap' },
    { t: 'p', v: 'Opción C — comando global:' },
    { t: 'cmd', v: 'cargo install --path .' },
    { t: 'gap' },
    { t: 'p', v: 'Verifica la instalación:' },
    { t: 'cmd', v: 'sparrow version' },
    { t: 'ok', v: 'Jack Sparrow 0.6.1' },
    { t: 'gap' },
    { t: 'table', head: ['Plataforma', 'Artefacto'], rows: [
      ['Windows 64-bit', 'sparrow-windows-amd64.exe.zip'],
      ['Linux Intel', 'sparrow-linux-amd64.tar.gz'],
      ['Linux ARM64', 'sparrow-linux-arm64.tar.gz'],
      ['macOS Intel', 'sparrow-macos-amd64.tar.gz'],
      ['macOS Apple Silicon', 'sparrow-macos-macos-arm64.tar.gz'],
    ] },
  ],

  /* ---------------- 3. tools ---------------- */
  tools: [
    { t: 'h', v: '4 · Herramientas externas opcionales' },
    { t: 'p', v: 'Si falta alguna, el escaneo continúa igual con los scanners nativos. Comprueba siempre al principio:' },
    { t: 'cmd', v: 'sparrow check-tools' },
    { t: 'gap' },
    { t: 'table', head: ['Herramienta', 'Para qué', 'Instalación'], rows: [
      ['sqlmap', 'SQL Injection', 'pip install sqlmap'],
      ['dalfox', 'XSS', 'cargo install dalfox'],
      ['ssrfmap', 'SSRF', 'git clone github.com/swisskyrepo/ssrfmap'],
      ['pip-audit', 'Supply Chain Py', 'pip install pip-audit'],
      ['cargo-audit', 'Supply Chain Rust', 'cargo install cargo-audit'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'Instalación rápida (Linux/macOS):' },
    { t: 'cmd', v: 'make install-deps' },
    { t: 'gap' },
    { t: 'dim', v: 'sqlmap es la única especialmente recomendable. El resto son opcionales.' },
  ],

  /* ---------------- 4. start ---------------- */
  start: [
    { t: 'h', v: '5 · Primeros pasos' },
    { t: 'p', v: 'Cinco comandos para familiarizarte:' },
    { t: 'gap' },
    { t: 'code', v: [
      'sparrow version              # versión instalada',
      'sparrow --help               # ayuda general',
      'sparrow scan --help          # todos los flags de escaneo',
      'sparrow check-tools          # herramientas externas',
      'sparrow init-config          # genera jack-sparrow.toml',
    ].join('\n') },
    { t: 'gap' },
    { t: 'dim', v: 'Siguiente paso sugerido → comando `scan`' },
  ],

  /* ---------------- 5. scan ---------------- */
  scan: [
    { t: 'h', v: '6 · Tu primer escaneo' },
    { t: 'p', v: 'Escaneo completo (todo por defecto):' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost/dvwa' },
    { t: 'gap' },
    { t: 'p', v: 'Escaneo selectivo (lo más habitual — más rápido y limpio):' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost/dvwa --checks sqli,xss,headers' },
    { t: 'gap' },
    { t: 'p', v: 'Con reporte HTML (tema oscuro, CVSS, listo para PDF con Ctrl+P):' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost --checks all --output report.html --format html' },
    { t: 'gap' },
    { t: 'p', v: 'Ajustar concurrencia y timeout:' },
    { t: 'cmd', v: 'sparrow scan --target https://app.example.com --checks all --concurrency 8 --timeout 600' },
    { t: 'gap' },
    { t: 'table', head: ['Flag', 'Defecto', 'Cuándo subirlo'], rows: [
      ['--concurrency', '4', 'Máquinas con buen ancho de banda'],
      ['--timeout', '300 s', 'Objetivos lentos o --checks all grandes'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'JSON para CI/CD o dashboards:' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost --checks headers,tech --output results.json --format json' },
  ],

  /* ---------------- 6. checks ---------------- */
  checks: [
    { t: 'h', v: '7 · Los 30 checks' },
    { t: 'p', v: 'Lista para --checks (separados por comas). Los incluidos por defecto:' },
    { t: 'gap' },
    { t: 'table', head: ['Check', 'Detecta'], rows: [
      ['sqli', 'SQL Injection (sqlmap + motor nativo)'],
      ['xss', 'XSS total (reflected + stored + DOM)'],
      ['xss-reflected', 'XSS reflejado (dalfox)'],
      ['xss-stored', 'XSS persistente (inyección en formularios)'],
      ['xss-dom', 'DOM XSS (análisis estático source → sink)'],
      ['idor', 'IDs secuenciales y enumeración de rutas'],
      ['ssrf', 'Server-Side Request Forgery'],
      ['supply-chain', 'Dependencias vulnerables (npm/pip/cargo)'],
      ['headers', '7 cabeceras de seguridad (CSP, HSTS...)'],
      ['tech', 'Framework, versión, CMS, servidor'],
      ['secrets', 'API keys y credenciales expuestas'],
      ['subdomains', 'crt.sh + brute-force'],
      ['waf', '12 fingerprints de WAF'],
      ['jwt', 'Decodificación, entropía, secretos comunes'],
      ['graphql', 'Introspección y mutaciones peligrosas'],
      ['api', 'CORS, métodos, rate limiting, errores'],
      ['cloud-metadata', 'AWS/GCP/Azure IMDS'],
      ['xxe', 'XML External Entity'],
      ['ssti', 'Template injection (6 engines)'],
      ['all', 'Todos los anteriores (defecto)'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'Opt-in (se activan con flags → comando `advanced`):' },
    { t: 'dim', v: 'browser · oauth · rate-limit · jwt-bruteforce · cors · takeover · websocket · api-fuzz · smuggling · auth-bypass · graphql-attack · cache-poisoning' },
  ],

  /* ---------------- 7. auth ---------------- */
  auth: [
    { t: 'h', v: '8 · Escaneos autenticados' },
    { t: 'p', v: 'La mayoría de vulnerabilidades viven tras el login. Tres formas:' },
    { t: 'gap' },
    { t: 'p', v: 'A) Cookie (la más rápida):' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost/dvwa \\\n  --checks sqli,xss,idor \\\n  --cookie "PHPSESSID=abc123; security=low"' },
    { t: 'dim', v: 'Extrae la cookie desde DevTools → Red → Cabeceras → Cookie.' },
    { t: 'gap' },
    { t: 'p', v: 'B) Cabeceras (tokens, API keys) — repetible:' },
    { t: 'cmd', v: 'sparrow scan --target https://api.example.com/v1 \\\n  --checks api,idor,secrets \\\n  --header "Authorization: Bearer eyJhbGciOi..." \\\n  --header "X-Api-Key: mi-clave"' },
    { t: 'gap' },
    { t: 'p', v: 'C) Login automático por formulario:' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost/dvwa \\\n  --checks all \\\n  --login-url http://localhost/dvwa/login.php \\\n  --login-user admin \\\n  --login-pass password' },
    { t: 'gap' },
    { t: 'table', head: ['Flag', 'Descripción'], rows: [
      ['--login-url', 'URL que recibe el POST del login'],
      ['--login-user / --login-pass', 'Credenciales'],
      ['--login-field-user', 'Campo de usuario (defecto: username)'],
      ['--login-field-pass', 'Campo de contraseña (defecto: password)'],
      ['--login-field', 'Campo extra "nombre=valor" (repetible)'],
    ] },
  ],

  /* ---------------- 8. advanced ---------------- */
  advanced: [
    { t: 'h', v: '9 · Scanners opt-in (flags avanzados)' },
    { t: 'p', v: 'Potentes pero ruidosos/s lentos → se activan explícitamente:' },
    { t: 'gap' },
    { t: 'cmd', v: 'sparrow scan --target https://app.example.com \\\n  --checks all \\\n  --cors --takeover --smuggling --auth-bypass' },
    { t: 'gap' },
    { t: 'table', head: ['Flag', 'Activa'], rows: [
      ['--browser', 'XSS con navegador real (Playwright) · --visible para depurar'],
      ['--oauth', 'Flujos OAuth/OIDC (CSRF, open redirect)'],
      ['--rate-limit', 'Bypass de rate limiting (método, spoofing IP...)'],
      ['--jwt-bruteforce', 'Fuerza bruta HMAC + alg confusion (requiere token en --header)'],
      ['--cors', 'CORS en profundidad (Origin, null, wildcard)'],
      ['--takeover', 'Takeover de subdominios (20 firmas + CNAME)'],
      ['--websocket', 'Seguridad WebSocket (auth, CSWSH, origin)'],
      ['--api-fuzz', 'Fuzzing de parámetros API (25 params)'],
      ['--smuggling', 'HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, H2)'],
      ['--auth-bypass', 'Credenciales por defecto, inyección de cabeceras'],
      ['--graphql-attack', 'Batch DoS, abuso de mutaciones'],
      ['--cache-poisoning', 'Headers unkeyed, parameter cloaking'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'Ejemplo con navegador (requiere playwright install chromium):' },
    { t: 'cmd', v: 'sparrow scan --target http://localhost:3001 --checks xss --browser' },
    { t: 'gap' },
    { t: 'p', v: 'JWT brute-force (opt-in con token):' },
    { t: 'cmd', v: 'sparrow scan --target https://app.example.com \\\n  --checks jwt --jwt-bruteforce \\\n  --header "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."' },
  ],

  /* ---------------- 9. wordlists ---------------- */
  wordlists: [
    { t: 'h', v: '10 · Wordlists personalizadas' },
    { t: 'p', v: 'Sustituye las listas por defecto (formato: un elemento por línea, UTF-8):' },
    { t: 'gap' },
    { t: 'cmd', v: 'sparrow scan --target example.com \\\n  --checks subdomains,sqli,idor \\\n  --wordlist-subdomain subdomains.txt \\\n  --wordlist-path paths.txt \\\n  --wordlist-param params.txt \\\n  --wordlist-password passwords.txt' },
    { t: 'gap' },
    { t: 'dim', v: 'Se combinan con --checks: cada wordlist alimenta a su scanner.' },
  ],

  /* ---------------- 10. session ---------------- */
  session: [
    { t: 'h', v: '11 · Grabación de sesiones con navegador' },
    { t: 'p', v: 'Para apps con mucho JS o flujos complejos: graba tu sesión manualmente y despues escanea con ella.' },
    { t: 'gap' },
    { t: 'code', v: [
      '# 1. Grabar (se abre Chromium; navega y logueate; Ctrl+C para terminar)',
      'sparrow record --output session.har --browser chromium',
      '',
      '# 2. Escanear usando la sesión grabada',
      'sparrow scan --target http://localhost:3001 --checks all --session session.har',
    ].join('\n') },
    { t: 'gap' },
    { t: 'table', head: ['Flag (record)', 'Descripción'], rows: [
      ['--output', 'Fichero HAR 1.2 (defecto: session.har)'],
      ['--browser', 'chromium (defecto), firefox, webkit'],
      ['--headless', 'Sin ventana visible'],
    ] },
    { t: 'gap' },
    { t: 'dim', v: 'El .har contiene peticiones, cookies y tokens que se reutilizan en el escaneo.' },
  ],

  /* ---------------- 11. config ---------------- */
  config: [
    { t: 'h', v: '12 · Configuración (jack-sparrow.toml)' },
    { t: 'cmd', v: 'sparrow init-config --output jack-sparrow.toml' },
    { t: 'p', v: 'Úsala en cualquier comando con la flag global -c / --config:' },
    { t: 'cmd', v: 'sparrow -c jack-sparrow.toml scan --target http://localhost' },
    { t: 'gap' },
    { t: 'code', v: [
      '[general]',
      'max_concurrent = 4          # scanners en paralelo',
      'timeout_secs = 300          # timeout global',
      'user_agent = "JackSparrow/0.6.1"',
      'verbose = false',
      '',
      '[scanners.sqli]',
      'level = 3                   # sqlmap --level (1-5)',
      'risk = 1                    # sqlmap --risk (1-3)',
      'threads = 4',
      '',
      '[scanners.xss]',
      'workers = 50',
      'waf_evasion = false',
      '',
      '[scanners.idor]',
      'param_names = ["id", "user_id", "account_id"]',
      'id_range = [1, 100]',
      'similarity_threshold = 0.8',
    ].join('\n') },
    { t: 'gap' },
    { t: 'dim', v: 'Deja los valores por defecto hasta que sepas qué haces.' },
  ],

  /* ---------------- 12. reports ---------------- */
  reports: [
    { t: 'h', v: '13 · Reportes y formatos' },
    { t: 'table', head: ['--format', 'Uso recomendado'], rows: [
      ['json (defecto)', 'CI/CD, dashboards, integración'],
      ['html', 'Informe para cliente — CVSS, Ctrl+P → PDF'],
      ['markdown', 'Docs internas, wikis, PRs'],
      ['csv', 'Excel / Google Sheets'],
    ] },
    { t: 'gap' },
    { t: 'code', v: [
      '# Informe para cliente',
      'sparrow scan --target https://app.example.com --checks all \\',
      '  --output informe.html --format html',
      '',
      '# JSON para CI',
      'sparrow scan --target https://staging.example.com --checks all \\',
      '  --output results.json --format json',
    ].join('\n') },
    { t: 'gap' },
    { t: 'p', v: 'Cada hallazgo incluye: severidad, CVSS, descripción, evidencia, CWE y remediación paso a paso.' },
    { t: 'gap' },
    { t: 'p', v: 'Fallo en CI si hay críticos (GitHub Actions):' },
    { t: 'code', v: [
      '- run: sparrow scan --target ${{ vars.STAGING_URL }} --checks all \\',
      '    --output scan.json --format json',
      '- run: jq -e \'.findings[] | select(.severity == "Critical")\' scan.json \\',
      '    && exit 1 || exit 0',
    ].join('\n') },
  ],

  /* ---------------- 13. labs ---------------- */
  labs: [
    { t: 'h', v: '14 · Laboratorios Docker para practicar' },
    { t: 'p', v: 'Apps vulnerables incluidas en el repo — practica sin tocar producción:' },
    { t: 'gap' },
    { t: 'cmd', v: 'make lab-up      # levanta todo\nmake lab-down    # los para' },
    { t: 'gap' },
    { t: 'table', head: ['Laboratorio', 'URL', 'Para practicar'], rows: [
      ['DVWA', 'http://localhost', 'SQLi, XSS, IDOR'],
      ['Juice Shop', 'http://localhost:3001', 'XSS moderno, CSP, API REST'],
      ['WebGoat', 'http://localhost:8080', 'Lecciones OWASP'],
      ['SSRF Lab', 'http://localhost:5000', 'Detección SSRF'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'Práctica guiada:' },
    { t: 'code', v: [
      'make lab-up',
      'sparrow scan --target http://localhost \\',
      '  --checks sqli,xss,idor,headers \\',
      '  --cookie "PHPSESSID=abc123; security=low" \\',
      '  --output practica.html --format html',
    ].join('\n') },
  ],

  /* ---------------- 14. interpret ---------------- */
  interpret: [
    { t: 'h', v: '15 · Cómo interpretar los resultados' },
    { t: 'table', head: ['Severidad', 'Significado', 'Acción'], rows: [
      ['CRITICAL', 'Explotable remoto con impacto total (SQLi)', 'Corregir YA'],
      ['HIGH', 'Impacto serio, explotación sencilla', 'Este sprint'],
      ['MEDIUM', 'Requiere condiciones adicionales', 'Planificar'],
      ['LOW', 'Impacto menor o difícil de explotar', 'Cuando se pueda'],
      ['INFO', 'Contexto útil sin fallo directo', 'Registrar'],
    ] },
    { t: 'gap' },
    { t: 'p', v: 'En cada hallazgo revisa:' },
    { t: 'code', v: [
      '1. Severity + CVSS   → prioridad',
      '2. Evidence          → prueba concreta (petición/respuesta)',
      '3. Remediation       → cómo corregir (CWE para profundizar)',
      '4. Confidence        → evidencia dura vs inferida',
    ].join('\n') },
    { t: 'gap' },
    { t: 'warn', v: 'Falsos positivos: verifica la evidencia manualmente antes de reportar.' },
    { t: 'warn', v: 'Falsos negativos: sin --cookie no ves nada tras el login (comando `auth`).' },
    { t: 'warn', v: 'WAF bloqueando: reduce --concurrency y revisa --checks waf.' },
  ],

  /* ---------------- 15. troubleshoot ---------------- */
  troubleshoot: [
    { t: 'h', v: '16 · Solución de problemas' },
    { t: 'gap' },
    { t: 'p', v: '"No se encontró la orden sparrow"' },
    { t: 'dim', v: '→ Usa la ruta completa (./target/release/sparrow) o reinicia la terminal tras cargo install (~/.cargo/bin en PATH).' },
    { t: 'gap' },
    { t: 'p', v: 'Los checks de sqli/supply-chain se omiten' },
    { t: 'dim', v: '→ sparrow check-tools e instala lo que marque ausente. El resto del escaneo funciona igual.' },
    { t: 'gap' },
    { t: 'p', v: '--browser falla: "Playwright browser type not found"' },
    { t: 'cmd', v: 'playwright install chromium' },
    { t: 'gap' },
    { t: 'p', v: 'El escaneo tarda demasiado' },
    { t: 'dim', v: '→ Reduce --checks, ajusta --concurrency, evita --checks all contra objetivos grandes.' },
    { t: 'gap' },
    { t: 'p', v: 'Errores de conexión / timeouts' },
    { t: 'dim', v: '→ Sube --timeout 600, comprueba alcance de la URL, configura HTTP_PROXY/HTTPS_PROXY si hay proxy.' },
    { t: 'gap' },
    { t: 'p', v: 'Reporte HTML en blanco' },
    { t: 'dim', v: '→ Ábrelo con Ctrl+P → Guardar como PDF en el navegador.' },
  ],

  /* ---------------- 16. faq ---------------- */
  faq: [
    { t: 'h', v: '17 · Preguntas frecuentes' },
    { t: 'gap' },
    { t: 'p', v: '¿Necesito todas las herramientas externas?' },
    { t: 'dim', v: '→ No. Solo sqlmap es especialmente recomendable; todo lo demás tiene alternativas nativas.' },
    { t: 'gap' },
    { t: 'p', v: '¿Puedo usarlo en bug bounty?' },
    { t: 'dim', v: '→ Sí, si las reglas del programa lo permiten. Empieza con --checks headers,tech,secrets (bajo ruido).' },
    { t: 'gap' },
    { t: 'p', v: '¿Es agresivo con el servidor?' },
    { t: 'dim', v: '→ Respeta robots.txt y aplica rate limiting por dominio. Ajusta --concurrency y max_concurrent.' },
    { t: 'gap' },
    { t: 'p', v: '¿Cómo actualizo?' },
    { t: 'cmd', v: '# Binario: nuevo release\ngit pull && cargo install --path .' },
    { t: 'gap' },
    { t: 'p', v: '¿Dónde reporto un fallo de la herramienta?' },
    { t: 'dim', v: '→ GitHub Issues · https://github.com/Pabl0l/jack-sparrow/issues (si es sensible: SECURITY.md)' },
  ],

  /* ---------------- 17. best ---------------- */
  best: [
    { t: 'h', v: '18 · Buenas prácticas' },
    { t: 'gap' },
    { t: 'code', v: [
      '1. Autorización primero  → permiso por escrito antes de escanear',
      '2. Empieza pequeño       → --checks headers,tech en un objetivo nuevo',
      '3. Practica en labs      → DVWA/Juice Shop antes de producción',
      '4. Autentica cuando cuente → la mayoría de hallazgos viven tras el login',
      '5. Guarda reportes       → html para archivo, json para diff entre versiones',
      '6. Re-verifica           → confirma cada hallazgo antes de reportarlo',
      '7. Actualiza             → los scanners crecen en cada release',
    ].join('\n') },
    { t: 'gap' },
    { t: 'ok', v: '¡Bon viaje! 🏴‍☠️' },
    { t: 'gap' },
    { t: 'link', label: '🐙 GitHub · Pabl0l/jack-sparrow', url: 'https://github.com/Pabl0l/jack-sparrow' },
    { t: 'link', label: '📄 TUTORIAL.md completo', url: 'https://github.com/Pabl0l/jack-sparrow/blob/main/TUTORIAL.md' },
    { t: 'link', label: '⬇️ Releases (binarios)', url: 'https://github.com/Pabl0l/jack-sparrow/releases' },
  ],

  /* ---------------- utilería ---------------- */
  version: [
    { t: 'p', v: 'sparrow 0.6.1 (jack-sparrow v0.6.1)' },
    { t: 'dim', v: '30 scanners · 570+ tests · MIT License · Rust 2021' },
    { t: 'dim', v: 'Terminal del tutorial: v1.0 · contenido desde TUTORIAL.md' },
  ],

  whoami: [
    { t: 'p', v: 'Pablo Olivera — Técnico en Mantenimiento de Sistemas, Bug Fixer & Builder.' },
    { t: 'dim', v: 'Automatización, ciberseguridad, redes Cisco, desarrollo web y AI-assisted development.' },
    { t: 'gap' },
    { t: 'link', label: '🌐 Portafolio', url: 'https://github.com/Pabl0l' },
    { t: 'link', label: '🐙 GitHub · Pabl0l', url: 'https://github.com/Pabl0l' },
  ],

  github: [
    { t: 'link', label: '🐙 Repositorio', url: 'https://github.com/Pabl0l/jack-sparrow' },
    { t: 'link', label: '⬇️ Releases (binarios v0.6.1)', url: 'https://github.com/Pabl0l/jack-sparrow/releases' },
    { t: 'link', label: '📄 TUTORIAL.md', url: 'https://github.com/Pabl0l/jack-sparrow/blob/main/TUTORIAL.md' },
    { t: 'link', label: '🧪 Issues', url: 'https://github.com/Pabl0l/jack-sparrow/issues' },
    { t: 'link', label: '📋 Actions (CI)', url: 'https://github.com/Pabl0l/jack-sparrow/actions' },
  ],
};

/* Comandos disponibles (orden del help + utilería) */
const COMMAND_NAMES = [
  'help', 'intro', 'install', 'tools', 'start', 'scan', 'checks', 'auth',
  'advanced', 'wordlists', 'session', 'config', 'reports', 'labs',
  'interpret', 'troubleshoot', 'faq', 'best', 'version', 'whoami',
  'github', 'clear', 'banner',
];

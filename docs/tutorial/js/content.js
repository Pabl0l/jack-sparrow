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
    { t: 'ok', v: 'Modo misión (12 niveles) ... listo → escribe `mission start`' },
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
      '',
      '  MODO MISIÓN (juego de 12 niveles)',
      '    mission       Portada y estado de la partida',
      '    mission start Nueva partida (retos aleatorios)',
      '    mission status Mapa de niveles, XP y reto actual',
      '    hint          Pista del reto actual (−1★)',
      '    rank          Rangos y XP',
      '    abort         Abandona la partida',
    ].join('\n') },
    { t: 'gap' },
    { t: 'dim', v: 'Tip: usa Tab para autocompletar y ↑/↓ para el historial.' },
  ],

  /* ---------------- modo misión (juego) ---------------- */
  mission: [
    { t: 'h', v: 'Modo Misión — aprende sparrow jugando 🏴‍☠️' },
    { t: 'p', v: 'Campaña de **12 niveles** con retos reales: te doy un objetivo, un alcance y una explicación, y tú escribes el comando de `sparrow` con la sintaxis correcta para superarlo.' },
    { t: 'gap' },
    { t: 'code', v: [
      'mission start     # nueva partida (los retos cambian en cada run)',
      'mission status    # mapa de niveles, XP y reto actual',
      'mission reset     # borra el progreso',
      'hint              # pista del reto actual (−1 estrella)',
      'rank              # rangos y XP acumulada',
      'abort             # abandona la partida',
    ].join('\n') },
    { t: 'gap' },
    { t: 'p', v: 'Cada nivel explica qué flag o keyword vas a usar y muestra la sintaxis con `[concepto]` entre corchetes: tu trabajo es sustituirlos por los valores concretos del reto.' },
    { t: 'dim', v: 'El progreso se guarda en tu navegador: si recargas la página, sigues donde estabas.' },
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

/* Envuelve un valor en código inline (`valor`) dentro de los textos */
const C = (s) => String.fromCharCode(96) + s + String.fromCharCode(96);

/* Keywords válidas para --checks (misma lista que parse_checks del motor) */
const CHECKS = [
  'sqli', 'xss', 'idor', 'ssrf', 'headers', 'tech', 'secrets', 'subdomains', 'waf',
  'jwt', 'graphql', 'api', 'cloud-metadata', 'xxe', 'ssti', 'form', 'csrf', 'upload',
  'supply-chain',
];

/* ============================================================
   Modo Misión — 12 niveles.
   Cada `tasks[i](rng)` genera un reto concreto a partir de la
   semilla de la partida (URLs, checks, ficheros y tokens cambian
   en cada run). Contrato del reto:
     goal   → enunciado con los valores concretos del reto
     syntax → plantilla con [concepto] entre corchetes
     hint   → pista que imprime `hint`
     tokens → prefijo obligatorio (subcomando real de sparrow)
     alts   → prefijos alternativos aceptados (opcional)
     flags  → flags obligatorios con sus valores esperados
   ============================================================ */
const MISSIONS = [

  /* ── 01 · Reconocimiento ─────────────────────────────────────── */
  {
    id: 1, icon: '🔍', title: 'Reconocimiento', pick: 3,
    theory: [
      { t: 'p', v: 'Antes de escanear, comprueba que la instalación responde. Sintaxis general: `sparrow [subcomando] [flags]`.' },
      { t: 'code', v: [
        'sparrow version            # versión instalada',
        'sparrow --help             # ayuda general (-h también vale)',
        'sparrow scan --help        # ayuda del subcomando scan',
        'sparrow check-tools        # herramientas externas disponibles',
        'sparrow init-config        # genera jack-sparrow.toml',
      ].join('\n') },
      { t: 'dim', v: 'Lo que va tras # es comentario: no forma parte del comando.' },
      { t: 'gap' },
    ],
    tasks: [
      () => ({
        goal: 'Comprueba qué versión de sparrow tienes instalada.',
        syntax: 'sparrow [subcomando]', hint: 'El subcomando se llama `version`.',
        tokens: ['sparrow', 'version'],
      }),
      () => ({
        goal: 'Muestra la ayuda general de la CLI.',
        syntax: 'sparrow [flag-de-ayuda]', hint: 'El flag de ayuda es `--help`.',
        tokens: ['sparrow', '--help'], alts: [['sparrow', '-h']],
      }),
      () => ({
        goal: 'Consulta la ayuda específica del subcomando `scan`.',
        syntax: 'sparrow scan [flag-de-ayuda]', hint: 'Subcomando + flag: `scan --help`.',
        tokens: ['sparrow', 'scan', '--help'], alts: [['sparrow', 'scan', '-h']],
      }),
      () => ({
        goal: 'Verifica qué herramientas externas (sqlmap, dalfox…) tienes disponibles.',
        syntax: 'sparrow [subcomando]', hint: 'El subcomando es `check-tools`, con guiones.',
        tokens: ['sparrow', 'check-tools'],
      }),
    ],
  },

  /* ── 02 · Tu primer escaneo ──────────────────────────────────── */
  {
    id: 2, icon: '🚀', title: 'Tu primer escaneo', pick: 3,
    theory: [
      { t: 'p', v: 'Sintaxis base de un escaneo: lo obligatorio es la URL objetivo con `-t` (forma corta) o `--target` (forma larga).' },
      { t: 'code', v: [
        'sparrow scan -t [target-url]                              # todo por defecto',
        'sparrow scan -t [target-url] --checks [keyword]           # solo un check',
        'sparrow scan --target [target-url] --checks headers,tech  # varios, en coma',
      ].join('\n') },
      { t: 'dim', v: 'Por defecto `--checks` es `all`: en el reto "por defecto" no hace falta escribirlo.' },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.url();
        return {
          goal: 'Escanea ' + C(u) + ' con la configuración por defecto (todos los checks).',
          syntax: 'sparrow scan -t [target-url]', hint: 'Solo necesitas el target: no toques `--checks`.',
          tokens: ['sparrow', 'scan'], flags: [{ names: ['-t', '--target'], value: u }],
        };
      },
      (r) => {
        const u = r.url();
        return {
          goal: 'Sobre ' + C(u) + ', comprueba únicamente las cabeceras de seguridad (CSP, HSTS…).',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `headers`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['headers'] }],
        };
      },
      (r) => {
        const u = r.url();
        return {
          goal: 'Sobre ' + C(u) + ', identifica framework, CMS y versión (fingerprinting).',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword de fingerprinting es `tech`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['tech'] }],
        };
      },
      (r) => {
        const u = r.url();
        return {
          goal: 'Sobre ' + C(u) + ', busca SQL Injection.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `sqli`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['sqli'] }],
        };
      },
      (r) => {
        const u = r.url();
        return {
          goal: 'Sobre ' + C(u) + ', detecta si hay un WAF delante del servidor.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `waf`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['waf'] }],
        };
      },
    ],
  },

  /* ── 03 · Alcance selectivo ──────────────────────────────────── */
  {
    id: 3, icon: '🎯', title: 'Alcance selectivo', pick: 3,
    theory: [
      { t: 'p', v: 'Un escaneo útil define **alcance**: los checks exactos que quieres correr. Varios con comas y **sin espacios**.' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks sqli,xss',
        'sparrow scan -t [target-url] --checks [keyword-1],[keyword-2],[keyword-3]',
      ].join('\n') },
      { t: 'table', head: ['Grupo', 'Keywords'], rows: [
        ['Web clásica', 'sqli, xss, idor, csrf, form, upload'],
        ['API', 'api, graphql, jwt, api-fuzz'],
        ['Infra', 'subdomains, waf, ssrf, cloud-metadata'],
        ['XML / Plantillas', 'xxe, ssti'],
      ] },
      { t: 'dim', v: 'El orden no importa: `xss,sqli` es lo mismo que `sqli,xss`.' },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.any();
        const c = r.subset(['idor', 'ssrf', 'waf', 'secrets', 'jwt', 'graphql', 'api', 'subdomains'], 2);
        return {
          goal: 'Sobre ' + C(u) + ', corre exactamente los checks ' + C(c.join(',')) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords]',
          hint: 'Dos keywords separadas por coma, sin espacios.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: c }],
        };
      },
      (r) => {
        const u = r.any();
        const c = r.subset(CHECKS, 3);
        return {
          goal: 'Sobre ' + C(u) + ', acota el escaneo a ' + C(c.join(',')) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords]',
          hint: 'Tres keywords en coma: ' + C(c.join(',')) + '.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: c }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'Sobre ' + C(u) + ', audita la API REST: CORS, métodos HTTP y su esquema GraphQL.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords]',
          hint: 'Dos keywords: `api` y `graphql`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['graphql', 'api'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'Sobre ' + C(u) + ', ejecuta el trío clásico de bug bounty: SQLi, XSS e IDOR.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords]',
          hint: 'Las tres keywords: `sqli`, `xss`, `idor`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['sqli', 'xss', 'idor'] }],
        };
      },
      (r) => {
        const u = r.any();
        const c = r.subset(['xxe', 'ssti', 'cloud-metadata', 'csrf', 'upload', 'form'], 2);
        return {
          goal: 'Sobre ' + C(u) + ', enfócate en ' + C(c.join(',')) + ' y nada más.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords]',
          hint: 'Exactamente ' + C(c.join(',')) + '.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: c }],
        };
      },
    ],
  },

  /* ── 04 · El catálogo de checks ──────────────────────────────── */
  {
    id: 4, icon: '🗂️', title: 'El catálogo de checks', pick: 3,
    theory: [
      { t: 'p', v: 'Aquí traducimos **qué queremos detectar** en la keyword correcta:' },
      { t: 'code', v: [
        '# quiero detectar inyección SQL →',
        'sparrow scan -t [target-url] --checks sqli',
        '# quiero revisar cabeceras de seguridad →',
        'sparrow scan -t [target-url] --checks headers',
      ].join('\n') },
      { t: 'dim', v: 'La lista completa está en la sección `checks` del tutorial.' },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' busca credenciales, tokens y API keys expuestas en las respuestas.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `secrets`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['secrets'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' detecta si los endpoints XML aceptan entidades externas (lectura de ficheros).',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `xxe`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['xxe'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' prueba inyección de plantillas (Jinja2, Twig, Freemarker…) que puede derivar en RCE.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `ssti`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['ssti'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' comprueba si AWS/GCP/Azure exponen sus metadatos de instancia (IMDS).',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `cloud-metadata`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['cloud-metadata'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' enumera subdominios vía Certificate Transparency (crt.sh) y brute-force.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `subdomains`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['subdomains'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' analiza los JWT de sesión: decodificación, entropía de la firma y secretos débiles.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `jwt`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['jwt'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' audita las dependencias de npm/pip/cargo con vulnerabilidades conocidas.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `supply-chain`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['supply-chain'] }],
        };
      },
      (r) => {
        const u = r.any();
        return {
          goal: 'En ' + C(u) + ' detecta si el formulario de login es vulnerable a inyección en campos POST.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword]', hint: 'La keyword es `form`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['form'] }],
        };
      },
    ],
  },

  /* ── 05 · Autenticación con cookie ───────────────────────────── */
  {
    id: 5, icon: '🍪', title: 'Autenticación con cookie', pick: 3,
    theory: [
      { t: 'p', v: 'La mayoría de vulnerabilidades viven **tras el login**. Con `--cookie` reutilizas tu sesión del navegador (DevTools → Red → cabecera Cookie).' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks [keywords] \\',
        '  --cookie "[nombre-cookie]=[valor]; [flag]=[valor]"',
        '',
        '# o con una cookie simple, sin espacios:',
        'sparrow scan -t [target-url] --checks [keywords] --cookie [session=valor]',
      ].join('\n') },
      { t: 'dim', v: 'Si el valor tiene espacios **hay que ponerlo entre comillas**; si no, no haría falta.' },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.url(), c = r.session();
        return {
          goal: 'Escanea ' + C(u) + ' con `sqli,xss` usando la sesión ' + C(c) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --cookie "[cookie]"',
          hint: 'La cookie lleva espacios → va entre comillas dobles.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['sqli', 'xss'] }, { names: ['--cookie'], value: c }],
        };
      },
      (r) => {
        const u = r.url(), c = r.bare();
        return {
          goal: 'Escanea ' + C(u) + ' comprobando solo `idor`, autenticándote con la cookie ' + C(c) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword] --cookie [cookie]',
          hint: 'Esta cookie no tiene espacios: puedes escribirla tal cual o entre comillas.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['idor'] }, { names: ['--cookie'], value: c }],
        };
      },
      (r) => {
        const u = r.url(), c = r.session();
        const ch = r.subset(['headers', 'tech', 'api', 'csrf'], 2);
        return {
          goal: 'Escanea ' + C(u) + ' con los checks ' + C(ch.join(',')) + ' usando la cookie ' + C(c) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --cookie "[cookie]"',
          hint: 'Comillas por los espacios de la cookie; checks separados por coma.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ch }, { names: ['--cookie'], value: c }],
        };
      },
      (r) => {
        const u = r.url(), c = r.session();
        return {
          goal: 'Escanea ' + C(u) + ' con la configuración por defecto pero con la sesión ' + C(c) + ' (sin tocar `--checks`).',
          syntax: 'sparrow scan -t [target-url] --cookie "[cookie]"',
          hint: 'Solo target + cookie: nada de `--checks` en este reto.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--cookie'], value: c }],
        };
      },
    ],
  },

  /* ── 06 · Cabeceras de autorización ──────────────────────────── */
  {
    id: 6, icon: '🔑', title: 'Cabeceras de autorización', pick: 3,
    theory: [
      { t: 'p', v: 'Las APIs usan **headers**. `--header` es repetible y el formato es `"Clave: Valor"` (con espacios → comillas).' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks [keyword] \\',
        '  --header "Authorization: Bearer [token]"',
        '',
        '# dos cabeceras a la vez: repite el flag',
        'sparrow scan -t [target-url] --checks [keyword] \\',
        '  --header "[clave-1]: [valor-1]" --header "[clave-2]: [valor-2]"',
      ].join('\n') },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.any(), h = 'Authorization: Bearer ' + r.token();
        return {
          goal: 'Escanea ' + C(u) + ' (check `api`) con la cabecera ' + C(h) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword] --header "[clave]: [valor]"',
          hint: 'Espacios dentro del valor → comillas dobles.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['api'] }, { names: ['--header'], value: h }],
        };
      },
      (r) => {
        const u = r.any(), h = 'X-API-Key: ' + r.apiKey();
        return {
          goal: 'Escanea ' + C(u) + ' con la cabecera de API key ' + C(h) + ' (checks por defecto).',
          syntax: 'sparrow scan -t [target-url] --header "[clave]: [valor]"',
          hint: 'No hace falta `--checks`: solo target y la cabecera.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--header'], value: h }],
        };
      },
      (r) => {
        const u = r.any(), h1 = 'Authorization: Bearer ' + r.token(), h2 = 'X-Request-Id: ' + r.id();
        return {
          goal: 'Escanea ' + C(u) + ' con las dos cabeceras ' + C(h1) + ' y ' + C(h2) + ' (checks `api,graphql`).',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --header "[c1]: [v1]" --header "[c2]: [v2]"',
          hint: 'Repite `--header` una vez por cabecera.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: u },
            { names: ['--checks'], checks: ['api', 'graphql'] },
            { names: ['--header'], values: [h1, h2], multi: true },
          ],
        };
      },
      (r) => {
        const u = r.any(), h = 'X-Internal-Token: ' + r.token();
        return {
          goal: 'Escanea ' + C(u) + ' con los checks `waf,secrets` y la cabecera ' + C(h) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --header "[clave]: [valor]"',
          hint: 'Target + dos keywords + cabecera entre comillas.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['waf', 'secrets'] }, { names: ['--header'], value: h }],
        };
      },
    ],
  },

  /* ── 07 · Reportes ───────────────────────────────────────────── */
  {
    id: 7, icon: '📄', title: 'Reportes', pick: 3,
    theory: [
      { t: 'p', v: 'Un hallazgo sin reporte no existe. `--output` (`-o`) escribe el fichero y `--format` elige el formato.' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks [keywords] \\',
        '  --output [informe.html] --format html',
        '',
        '# cortos equivalentes:',
        'sparrow scan -t [target-url] -o [informe.json] --format json',
      ].join('\n') },
      { t: 'table', head: ['format', 'Para qué'], rows: [
        ['html', 'Informe oscuro con CVSS → PDF con Ctrl+P'],
        ['json', 'CI/CD y dashboards'],
        ['markdown', 'Issues y documentación'],
        ['csv', 'Importar a Excel/Sheets'],
      ] },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.any(), f = r.file('html');
        return {
          goal: 'Sobre ' + C(u) + ' corre `headers,tech` y guarda el resultado en ' + C(f) + ' como HTML.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --output [archivo] --format html',
          hint: 'Dos flags: `--output` con el nombre y `--format html`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['headers', 'tech'] }, { names: ['-o', '--output'], value: f }, { names: ['--format'], value: 'html' }],
        };
      },
      (r) => {
        const u = r.any(), f = r.file('json');
        return {
          goal: 'Sobre ' + C(u) + ' corre `sqli,xss` y escribe ' + C(f) + ' en JSON usando la forma corta de output.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] -o [archivo] --format json',
          hint: 'La forma corta de `--output` es `-o`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['sqli', 'xss'] }, { names: ['-o', '--output'], value: f }, { names: ['--format'], value: 'json' }],
        };
      },
      (r) => {
        const u = r.any(), f = r.file('md');
        return {
          goal: 'Sobre ' + C(u) + ' corre `api` y exporta un informe Markdown en ' + C(f) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword] --format [formato] --output [archivo]',
          hint: '`--format markdown` y el nombre en `--output`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['api'] }, { names: ['-o', '--output'], value: f }, { names: ['--format'], value: 'markdown' }],
        };
      },
      (r) => {
        const u = r.any(), f = r.file('csv');
        return {
          goal: 'Sobre ' + C(u) + ' corre `idor,ssrf` y exporta a CSV en ' + C(f) + ' para hoja de cálculo.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --output [archivo] --format csv',
          hint: '`--format csv` (el orden de los flags da igual).',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['idor', 'ssrf'] }, { names: ['-o', '--output'], value: f }, { names: ['--format'], value: 'csv' }],
        };
      },
    ],
  },

  /* ── 08 · Rendimiento ────────────────────────────────────────── */
  {
    id: 8, icon: '⚙️', title: 'Rendimiento', pick: 3,
    theory: [
      { t: 'p', v: 'Ajusta concurrencia y tiempo máximo según el objetivo. Ambos flags esperan **números**.' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks [keywords] \\',
        '  --concurrency [nº-scanners] --timeout [segundos]',
        '',
        '# objetivo lento + escaneo completo:',
        'sparrow scan -t [target-url] --checks all --timeout [segundos]',
      ].join('\n') },
      { t: 'table', head: ['Flag', 'Defecto', 'Cuándo subirlo'], rows: [
        ['--concurrency', '4', 'Máquinas con buen ancho de banda'],
        ['--timeout', '300', 'Objetivos lentos o `--checks all`'],
      ] },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.any(), c = r.int(2, 12), t = r.pick([120, 180, 420, 600, 900]);
        return {
          goal: 'Escanea ' + C(u) + ' con ' + C(String(c)) + ' scanners en paralelo y timeout de ' + C(String(t)) + ' s (checks por defecto).',
          syntax: 'sparrow scan -t [target-url] --concurrency [nº] --timeout [segundos]',
          hint: '`--concurrency` y `--timeout` llevan números, sin comillas.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--concurrency'], value: String(c) }, { names: ['--timeout'], value: String(t) }],
        };
      },
      (r) => {
        const u = r.any(), c = r.int(2, 16), ch = r.subset(['sqli', 'xss', 'idor', 'ssrf', 'waf'], 2);
        return {
          goal: 'Sobre ' + C(u) + ' corre ' + C(ch.join(',')) + ' con ' + C(String(c)) + ' scanners en paralelo.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --concurrency [nº]',
          hint: 'Checks en coma + `--concurrency` con número.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ch }, { names: ['--concurrency'], value: String(c) }],
        };
      },
      (r) => {
        const u = r.any(), t = r.pick([240, 360, 480, 720]);
        return {
          goal: 'Lanza el escaneo completo de ' + C(u) + ' con timeout de ' + C(String(t)) + ' s.',
          syntax: 'sparrow scan -t [target-url] --checks all --timeout [segundos]',
          hint: 'Aquí `--checks` sí se escribe: valor `all`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['all'] }, { names: ['--timeout'], value: String(t) }],
        };
      },
      (r) => {
        const u = r.any(), c = r.int(3, 10), t = r.pick([150, 300, 600]);
        return {
          goal: 'Escanea ' + C(u) + ' (checks por defecto) con ' + C(String(c)) + ' en paralelo y timeout ' + C(String(t)) + ' s.',
          syntax: 'sparrow scan -t [target-url] --concurrency [nº] --timeout [segundos]',
          hint: 'Sin `--checks`: solo target + los dos números.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--concurrency'], value: String(c) }, { names: ['--timeout'], value: String(t) }],
        };
      },
    ],
  },

  /* ── 09 · Scanners opt-in ────────────────────────────────────── */
  {
    id: 9, icon: '🧨', title: 'Scanners opt-in', pick: 3,
    theory: [
      { t: 'p', v: 'Algunos scanners son **potentes o lentos**: van con su propio flag además de la keyword de `--checks`.' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks [keyword] --[flag-opt-in]',
        '',
        '# ejemplos reales:',
        'sparrow scan -t [target-url] --checks oauth --oauth',
        'sparrow scan -t [target-url] --checks rate-limit --rate-limit',
        'sparrow scan -t [target-url] --checks cors --cors',
      ].join('\n') },
      { t: 'table', head: ['Keyword', 'Flag obligatorio'], rows: [
        ['oauth', '--oauth'], ['rate-limit', '--rate-limit'], ['jwt-bruteforce', '--jwt-bruteforce'],
        ['cors', '--cors'], ['subdomain-takeover', '--takeover'], ['websocket', '--websocket'],
        ['api-fuzz', '--api-fuzz'], ['browser-xss', '--browser'], ['smuggling', '--smuggling'],
        ['auth-bypass', '--auth-bypass'], ['graphql-attack', '--graphql-attack'], ['cache-poisoning', '--cache-poisoning'],
      ] },
      { t: 'gap' },
    ],
    tasks: (() => {
      const PAIRS = [
        ['oauth', '--oauth'], ['rate-limit', '--rate-limit'], ['cors', '--cors'],
        ['subdomain-takeover', '--takeover'], ['websocket', '--websocket'], ['api-fuzz', '--api-fuzz'],
        ['browser-xss', '--browser'], ['smuggling', '--smuggling'], ['auth-bypass', '--auth-bypass'],
        ['graphql-attack', '--graphql-attack'], ['cache-poisoning', '--cache-poisoning'],
        ['jwt-bruteforce', '--jwt-bruteforce'],
      ];
      return PAIRS.map(([kw, flag]) => (r) => {
        const u = r.any();
        return {
          goal: 'Sobre ' + C(u) + ' activa el scanner de ' + C(kw) + ' — este es opt-in: sin su flag no se ejecuta.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword] --[flag-opt-in]',
          hint: 'La keyword ' + C(kw) + ' necesita su flag ' + C(flag) + '.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: [kw] }, { names: [flag], bool: true }],
        };
      });
    })(),
  },

  /* ── 10 · Wordlists y configuración ──────────────────────────── */
  {
    id: 10, icon: '📚', title: 'Wordlists y configuración', pick: 3,
    theory: [
      { t: 'p', v: 'Personaliza los diccionarios de fuerza bruta y la configuración global.' },
      { t: 'code', v: [
        'sparrow init-config                          # genera jack-sparrow.toml',
        'sparrow init-config -o [archivo.toml]        # en otra ruta',
        '',
        'sparrow scan -t [target-url] --checks subdomains \\',
        '  --wordlist-subdomain [lista.txt]',
        '',
        'sparrow scan -t [target-url] --checks [keyword] --wordlist-path [lista.txt]',
      ].join('\n') },
      { t: 'dim', v: 'Flags de wordlists: `--wordlist-subdomain`, `--wordlist-path`, `--wordlist-param`, `--wordlist-password`.' },
      { t: 'gap' },
    ],
    tasks: [
      () => ({
        goal: 'Genera el archivo de configuración por defecto `jack-sparrow.toml`.',
        syntax: 'sparrow [subcomando]', hint: 'El subcomando es `init-config`.',
        tokens: ['sparrow', 'init-config'],
      }),
      () => ({
        goal: 'Genera la configuración pero con el nombre `mi-config.toml`.',
        syntax: 'sparrow init-config -o [archivo.toml]', hint: '`-o` (o `--output`) cambia el fichero de salida.',
        tokens: ['sparrow', 'init-config'],
        flags: [{ names: ['-o', '--output'], value: 'mi-config.toml' }],
      }),
      (r) => {
        const u = r.any(), w = r.wordlist();
        return {
          goal: 'Enumera subdominios de ' + C(u) + ' usando tu wordlist propia ' + C(w) + '.',
          syntax: 'sparrow scan -t [target-url] --checks subdomains --wordlist-subdomain [lista.txt]',
          hint: 'La keyword es `subdomains` y el flag es `--wordlist-subdomain` (singular).',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['subdomains'] }, { names: ['--wordlist-subdomain'], value: w }],
        };
      },
      (r) => {
        const u = r.any(), w = r.wordlist();
        return {
          goal: 'Fuerza rutas ocultas en ' + C(u) + ' con tu diccionario ' + C(w) + ' (checks por defecto).',
          syntax: 'sparrow scan -t [target-url] --wordlist-path [lista.txt]',
          hint: 'Solo target + `--wordlist-path`: nada de `--checks`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--wordlist-path'], value: w }],
        };
      },
      (r) => {
        const u = r.any(), w = r.wordlist();
        return {
          goal: 'Sobre ' + C(u) + ' prueba parámetros con tu lista ' + C(w) + ' usando el fuzzing de API.',
          syntax: 'sparrow scan -t [target-url] --checks [keyword] --wordlist-param [lista.txt]',
          hint: 'La keyword de fuzzing es `api-fuzz` (y recuerda su flag `--api-fuzz`).',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: u },
            { names: ['--checks'], checks: ['api-fuzz'] },
            { names: ['--api-fuzz'], bool: true },
            { names: ['--wordlist-param'], value: w },
          ],
        };
      },
      (r) => {
        const u = r.any(), w = r.wordlist();
        return {
          goal: 'Escanea ' + C(u) + ' con los checks por defecto y el diccionario de parámetros ' + C(w) + '.',
          syntax: 'sparrow scan -t [target-url] --wordlist-param [lista.txt]',
          hint: 'Sin `--checks` en este reto: solo target + wordlist.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--wordlist-param'], value: w }],
        };
      },
    ],
  },

  /* ── 11 · Laboratorios y práctica guiada ─────────────────────── */
  {
    id: 11, icon: '🧪', title: 'Laboratorios y práctica', pick: 3,
    theory: [
      { t: 'p', v: 'Practica contra los labs del repo (DVWA, Juice Shop, WebGoat, SSRF Lab) — nunca contra sistemas ajenos.' },
      { t: 'code', v: [
        'make lab-up                                   # levanta los labs Docker',
        '',
        'sparrow scan -t [target-url] --checks [keywords] \\',
        '  --cookie "[cookie]" \\',
        '  --output [informe.html] --format html',
      ].join('\n') },
      { t: 'table', head: ['Lab', 'URL', 'Para practicar'], rows: [
        ['DVWA', 'http://localhost', 'SQLi, XSS, IDOR'],
        ['Juice Shop', 'http://localhost:3001', 'XSS moderno, CSP, API REST'],
        ['WebGoat', 'http://localhost:8080', 'Lecciones OWASP'],
        ['SSRF Lab', 'http://localhost:5000', 'Detección SSRF'],
      ] },
      { t: 'gap' },
    ],
    tasks: [
      () => ({
        goal: 'Levanta todos los laboratorios Docker del repositorio.',
        syntax: 'make [objetivo]', hint: 'El objetivo de Make para levantar todo es `lab-up`.',
        tokens: ['make', 'lab-up'],
      }),
      () => ({
        goal: 'Cierra los laboratorios Docker del repositorio.',
        syntax: 'make [objetivo]', hint: 'El objetivo opuesto a `lab-up` es `lab-down`.',
        tokens: ['make', 'lab-down'],
      }),
      (r) => {
        const c = r.session(), f = r.file('html');
        const ch = r.subset(['sqli', 'xss', 'idor'], 2);
        return {
          goal: 'Sobre DVWA (' + C('http://localhost') + ') corre ' + C(ch.join(',')) + ' con la cookie ' + C(c) + ' y guarda el informe en ' + C(f) + ' (HTML).',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --cookie "[cookie]" --output [archivo] --format html',
          hint: 'Cinco piezas: target, checks, cookie (con comillas), output y format.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: 'http://localhost' },
            { names: ['--checks'], checks: ch },
            { names: ['--cookie'], value: c },
            { names: ['-o', '--output'], value: f },
            { names: ['--format'], value: 'html' },
          ],
        };
      },
      (r) => {
        const c = r.int(3, 12), ch = r.subset(['xss', 'headers', 'tech', 'api', 'secrets'], 3);
        return {
          goal: 'Audita Juice Shop (' + C('http://localhost:3001') + ') con los checks ' + C(ch.join(',')) + ' y ' + C(String(c)) + ' scanners en paralelo.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --concurrency [nº]',
          hint: 'La URL de Juice Shop es la del puerto 3001.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: 'http://localhost:3001' },
            { names: ['--checks'], checks: ch },
            { names: ['--concurrency'], value: String(c) },
          ],
        };
      },
      (r) => {
        const h = 'Authorization: Bearer ' + r.token();
        return {
          goal: 'Contra el SSRF Lab (' + C('http://localhost:5000') + ') corre `ssrf,cloud-metadata` con la cabecera ' + C(h) + '.',
          syntax: 'sparrow scan -t [target-url] --checks [keywords] --header "[clave]: [valor]"',
          hint: 'URL del puerto 5000 + dos keywords + cabecera entre comillas.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: 'http://localhost:5000' },
            { names: ['--checks'], checks: ['ssrf', 'cloud-metadata'] },
            { names: ['--header'], value: h },
          ],
        };
      },
      (r) => {
        const t = r.pick([180, 300, 450]);
        return {
          goal: 'Contra WebGoat (' + C('http://localhost:8080') + ') lanza el escaneo completo con timeout de ' + C(String(t)) + ' s.',
          syntax: 'sparrow scan -t [target-url] --checks all --timeout [segundos]',
          hint: 'URL del puerto 8080, `--checks all` y el número en segundos.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: 'http://localhost:8080' },
            { names: ['--checks'], checks: ['all'] },
            { names: ['--timeout'], value: String(t) },
          ],
        };
      },
    ],
  },

  /* ── 12 · Reto final ─────────────────────────────────────────── */
  {
    id: 12, icon: '🏁', title: 'Reto final', pick: 3,
    theory: [
      { t: 'p', v: 'Último nivel: combina todo — alcance total, autenticación, rendimiento y reporte. Este es el comando que usarías en un pentest real.' },
      { t: 'code', v: [
        'sparrow scan -t [target-url] --checks all',
        'sparrow scan -t [target-url] --checks all \\',
        '  --cookie "[cookie]" --concurrency [nº] --timeout [segundos] \\',
        '  --output [informe.html] --format html',
      ].join('\n') },
      { t: 'warn', v: 'Con `--checks all` el escaneo es largo: úsalo contra labs propios, no contra cualquier objetivo.' },
      { t: 'gap' },
    ],
    tasks: [
      (r) => {
        const u = r.url();
        return {
          goal: 'Ejecuta el escaneo completo de ' + C(u) + '.',
          syntax: 'sparrow scan -t [target-url] --checks all', hint: '`--checks all` es la forma de pedir todo.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['all'] }],
        };
      },
      (r) => {
        const u = r.url(), f = r.file('html');
        return {
          goal: 'Escaneo completo de ' + C(u) + ' guardado como HTML en ' + C(f) + '.',
          syntax: 'sparrow scan -t [target-url] --checks all --output [archivo] --format html',
          hint: 'Añade `--output` y `--format html` al escaneo completo.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['all'] }, { names: ['-o', '--output'], value: f }, { names: ['--format'], value: 'html' }],
        };
      },
      (r) => {
        const u = r.any(), c = r.int(6, 16), t = r.pick([420, 600, 780]);
        return {
          goal: 'Escaneo completo de ' + C(u) + ' con ' + C(String(c)) + ' scanners en paralelo y timeout ' + C(String(t)) + ' s.',
          syntax: 'sparrow scan -t [target-url] --checks all --concurrency [nº] --timeout [segundos]',
          hint: 'Los dos flags numéricos, además de `all`.',
          tokens: ['sparrow', 'scan'],
          flags: [{ names: ['-t', '--target'], value: u }, { names: ['--checks'], checks: ['all'] }, { names: ['--concurrency'], value: String(c) }, { names: ['--timeout'], value: String(t) }],
        };
      },
      (r) => {
        const u = r.any(), ck = r.session(), f = r.file('json');
        return {
          goal: 'Pentest autenticado de ' + C(u) + ': escaneo completo con la cookie ' + C(ck) + ', exportado a JSON en ' + C(f) + '.',
          syntax: 'sparrow scan -t [target-url] --checks all --cookie "[cookie]" --output [archivo] --format json',
          hint: 'Cinco flags: target, all, cookie con comillas, output y format.',
          tokens: ['sparrow', 'scan'],
          flags: [
            { names: ['-t', '--target'], value: u },
            { names: ['--checks'], checks: ['all'] },
            { names: ['--cookie'], value: ck },
            { names: ['-o', '--output'], value: f },
            { names: ['--format'], value: 'json' },
          ],
        };
      },
    ],
  },
];

/* Comandos disponibles (orden del help + utilería) */
const COMMAND_NAMES = [
  'mission', 'mission start', 'mission status', 'mission reset', 'hint', 'rank', 'abort',
  'help', 'intro', 'install', 'tools', 'start', 'scan', 'checks', 'auth',
  'advanced', 'wordlists', 'session', 'config', 'reports', 'labs',
  'interpret', 'troubleshoot', 'faq', 'best', 'version', 'whoami',
  'github', 'clear', 'banner',
];

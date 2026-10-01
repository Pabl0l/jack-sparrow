/* ============================================================
   sparrow-tutorial — motor de terminal
   ============================================================ */
(() => {
  'use strict';

  const output = document.getElementById('output');
  const form = document.getElementById('promptForm');
  const input = document.getElementById('cmdInput');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const history = [];
  let histIdx = -1;
  let running = false;   // hay una salida en curso
  let skip = false;      // petición de salto

  /* ---------------- utilidades ---------------- */
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const scrollDown = () => { output.scrollTop = output.scrollHeight; };

  function md(s) {
    // `inline code` → <code>
    return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
  }

  /* ---------------- render de líneas ---------------- */
  function lineEl(l) {
    const div = document.createElement('div');
    div.className = 'l ' + (l.t || 'p');

    if (l.t === 'ascii') {
      div.textContent = l.v;
    } else if (l.t === 'code' || l.t === 'cmd') {
      div.textContent = l.v;
    } else if (l.t === 'table') {
      const tb = document.createElement('table');
      const thead = tb.createTHead();
      const hr = thead.insertRow();
      l.head.forEach((h) => { const th = document.createElement('th'); th.textContent = h; hr.appendChild(th); });
      const trb = tb.createTBody();
      l.rows.forEach((r) => {
        const tr = trb.insertRow();
        r.forEach((c) => { const td = tr.insertCell(); td.textContent = c; });
      });
      div.appendChild(tb);
    } else if (l.t === 'link') {
      const a = document.createElement('a');
      a.href = l.url; a.target = '_blank'; a.rel = 'noopener';
      a.textContent = l.label;
      div.appendChild(a);
    } else if (l.t === 'echo') {
      div.innerHTML = '<span class="u">visitor@sparrow</span>:<span class="p">~</span>$ <span class="c">' + esc(l.v) + '</span>';
    } else {
      div.innerHTML = md(l.v || '');
    }
    return div;
  }

  async function print(lines, instant) {
    running = true;
    for (const l of lines) {
      output.appendChild(lineEl(l));
      if (!instant && !reduced && !skip) {
        const isText = ['p', 'dim', 'ok', 'warn', 'echo'].includes(l.t);
        await sleep(isText ? 90 : 170);
      }
      scrollDown();
    }
    running = false;
  }

  /* ---------------- comandos ---------------- */
  const HELP_COMMANDS = {
    help: 'Lista de comandos', intro: 'Qué es Jack Sparrow', install: 'Instalación',
    tools: 'Herramientas externas', start: 'Primeros pasos', scan: 'Primer escaneo',
    checks: 'Los 30 checks', auth: 'Escaneos autenticados', advanced: 'Flags opt-in',
    wordlists: 'Wordlists', session: 'Sesiones grabadas', config: 'Configuración TOML',
    reports: 'Reportes y CI/CD', labs: 'Laboratorios Docker', interpret: 'Interpretar hallazgos',
    troubleshoot: 'Problemas comunes', faq: 'Preguntas frecuentes', best: 'Buenas prácticas',
    version: 'Versión', whoami: 'Autor', github: 'Enlaces', clear: 'Limpiar', banner: 'Banner',
  };

  async function run(raw, instant) {
    const cmd = raw.trim().toLowerCase();
    if (!cmd) return;
    skip = false;

    if (cmd !== history[0]) history.unshift(cmd);
    histIdx = -1;

    try {
      // echo del comando
      await print([{ t: 'echo', v: raw.trim() }], instant);

      if (cmd === 'clear' || cmd === 'cls') {
        output.innerHTML = '';
        return;
      }
      if (cmd === 'banner') {
        await print(TUTORIAL.banner, instant);
        return;
      }
      if (cmd === 'sudo') {
        await print([{ t: 'warn', v: 'nice try. aquí solo hay permisos de lectura 😉' }], instant);
        return;
      }

      // modo misión: comandos del juego y retos (tienen prioridad)
      if (window.GAME && GAME.isCmd(cmd)) {
        await print(GAME.run(raw.trim()), instant);
        return;
      }

      if (TUTORIAL[cmd]) {
        await print(TUTORIAL[cmd], instant);
        return;
      }

      // ayuda y errores
      if (cmd === '?' || cmd === 'man') {
        await print(TUTORIAL.help, instant);
        return;
      }

      // dentro de una partida, cualquier otra entrada se valida como reto
      if (window.GAME && GAME.active()) {
        await print(GAME.run(raw.trim()), instant);
        return;
      }

      await print([
        { t: 'warn', v: 'comando no encontrado: ' + cmd },
        { t: 'dim', v: 'Escribe `help` para ver los ' + COMMAND_NAMES.length + ' comandos disponibles.' },
      ], instant);
    } finally {
      skip = false;
    }
  }

  /* ---------------- eventos del prompt ---------------- */
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const v = input.value;
    input.value = '';
    run(v, false);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (histIdx < history.length - 1) { histIdx++; input.value = history[histIdx]; }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx > 0) { histIdx--; input.value = history[histIdx]; }
      else { histIdx = -1; input.value = ''; }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const v = input.value.toLowerCase();
      if (v) {
        const m = COMMAND_NAMES.filter((c) => c.startsWith(v));
        if (m.length === 1) input.value = m[0];
        else if (m.length > 1) print([{ t: 'dim', v: m.join('  ') }], true);
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      output.innerHTML = '';
    } else if (e.key === 'c' && e.ctrlKey && !window.getSelection().toString()) {
      e.preventDefault();
      input.value = '';
    }
  });

  // clic en cualquier parte del terminal → foco en input
  document.getElementById('terminal').addEventListener('click', (e) => {
    if (window.getSelection().toString()) return;
    input.focus();
  });

  // botones del nav → ejecutar comando
  document.querySelectorAll('.chips button').forEach((b) => {
    b.addEventListener('click', () => { run(b.dataset.cmd, false); input.focus(); });
  });

  // salto de animación: Enter con input vacío durante una salida en curso
  document.addEventListener('keydown', (e) => { if (running && e.key === 'Enter' && !input.value) skip = true; });

  /* ---------------- fondo matrix ---------------- */
  function rain() {
    const c = document.getElementById('rain');
    const ctx = c.getContext('2d');
    let w, cols, drops;
    const chars = 'アイウエオカキクケコサシスセソ0123456789S P A R R O W'.replace(/ /g, '');

    function size() {
      w = window.innerWidth;
      c.width = w;
      c.height = window.innerHeight;
      cols = Math.floor(w / 16);
      drops = Array(cols).fill(0).map(() => Math.random() * -40);
    }
    size();
    window.addEventListener('resize', size);

    if (reduced) { // un solo frame estático
      ctx.fillStyle = '#39ff14';
      drops.forEach((y, i) => ctx.fillText(chars[(i * 7) % chars.length], i * 16, y * 16));
      return;
    }

    setInterval(() => {
      ctx.fillStyle = 'rgba(10, 10, 10, 0.10)';
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.fillStyle = '#39ff14';
      ctx.font = '14px monospace';
      drops.forEach((y, i) => {
        ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * 16, y * 16);
        if (y * 16 > c.height && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.5;
      });
    }, 55);
  }

  /* ---------------- arranque ---------------- */
  async function boot() {
    rain();
    await print(TUTORIAL.boot, reduced);
    await print(TUTORIAL.banner, reduced);
    const restored = window.GAME ? GAME.restore() : null;
    if (restored) await print(restored, reduced);
    await print([{ t: 'gap' }], true);
    if (!reduced) await sleep(250);
    input.focus();
  }
  boot();
})();

/* ============================================================
   sparrow-tutorial — Modo Misión (12 niveles · partida aleatoria)

   Cada partida nueva genera una semilla distinta: URLs, checks,
   cookies, ficheros, tokens y la selección de retos cambian en
   cada run. El jugador escribe el comando real de sparrow con la
   sintaxis correcta para superar cada reto.

   API (usada por terminal.js):
     GAME.isCmd(cmd)   → ¿la entrada pertenece al modo misión?
     GAME.run(raw)     → array de líneas a imprimir
     GAME.restore()    → líneas si había partida guardada
     GAME.active()     → hay partida en curso
   ============================================================ */
(() => {
  'use strict';

  const STORE = 'sparrow-mission-v1';
  const MAX_LEVEL = 12;
  const RANKS = [
    [0, 'Grumete'], [300, 'Marinero'], [800, 'Piloto'],
    [1400, 'Contramaestre'], [2100, 'Primer Oficial'], [2700, 'Capitán'],
  ];
  const PRAISE = ['¡Correcto!', '¡Bien!', '¡En el blanco!', '¡Ejecutado!', '¡Así se hace!'];

  /* ---------------- pools (contenido generado por semilla) ---------------- */
  const LABS = [
    'http://localhost', 'http://localhost/dvwa', 'http://localhost:3001',
    'http://localhost:8080', 'http://localhost:5000',
  ];
  const ANYS = [
    'https://app.example.com', 'http://dev.staging.example.net', 'https://shop.example.org',
    'http://192.168.1.40/dvwa', 'https://api.example.io', 'http://blog.example.dev',
  ];

  /* ---------------- PRNG determinista por semilla ---------------- */
  const hash = (s) => {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  };

  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function makeRng(seed) {
    const rand = mulberry32(seed);
    const int = (a, b) => a + Math.floor(rand() * (b - a + 1));
    const pick = (arr) => arr[int(0, arr.length - 1)];
    const shuffle = (arr) => {
      const a = arr.slice();
      for (let i = a.length - 1; i > 0; i--) { const j = int(0, i); const x = a[i]; a[i] = a[j]; a[j] = x; }
      return a;
    };
    const hex = (n) => { let s = ''; for (let i = 0; i < n; i++) s += int(0, 15).toString(16); return s; };
    return {
      int, pick, shuffle,
      subset: (arr, n) => shuffle(arr).slice(0, Math.min(n, arr.length)),
      lab: () => pick(LABS),
      any: () => pick(ANYS),
      url: () => (rand() < 0.4 ? pick(LABS) : pick(ANYS)),
      file: (ext) => `informe-${hex(4)}.${ext}`,
      wordlist: () => `wordlist-${hex(3)}.txt`,
      session: () => `PHPSESSID=${hex(8)}; security=low`,
      bare: () => `session=${hex(12)}`,
      token: () => hex(32),
      apiKey: () => `sk_live_${hex(24)}`,
      id: () => hex(6),
    };
  }

  /* ---------------- estado ---------------- */
  let run = null;

  function load() {
    try {
      const raw = localStorage.getItem(STORE);
      if (!raw) return null;
      const s = JSON.parse(raw);
      return s && typeof s.seed === 'number' ? s : null;
    } catch (e) { return null; }
  }
  function save() { try { localStorage.setItem(STORE, JSON.stringify(run)); } catch (e) { /* sin storage */ } }
  /** ¿El navegador permite persistir? (modo incógito, cuotas, cookies bloqueadas) */
  function storageOk() {
    try {
      localStorage.setItem(STORE + '-probe', '1');
      localStorage.removeItem(STORE + '-probe');
      return true;
    } catch (e) { return false; }
  }
  function wipe() { try { localStorage.removeItem(STORE); } catch (e) { /* sin storage */ } }

  const active = () => !!run && !run.done;
  const levelOf = (n) => MISSIONS[n - 1];
  const rng = (parts) => makeRng(hash(parts.join(':')));

  function levelTasks(n) {
    const lvl = levelOf(n);
    return rng([run.seed, 'level', n]).shuffle(lvl.tasks).slice(0, Math.min(lvl.pick, lvl.tasks.length));
  }
  function currentSpec() {
    const tasks = levelTasks(run.level);
    const def = tasks[Math.min(run.task, tasks.length - 1)];
    return def(rng([run.seed, 'task', run.level, run.task]));
  }
  const starsOf = (n) => '★'.repeat(n) + '☆'.repeat(Math.max(0, 3 - n));
  function rankOf(xp) {
    let name = RANKS[0][1];
    for (const [t, n] of RANKS) if (xp >= t) name = n;
    return name;
  }

  /* ---------------- tokenizador (respeta comillas y comentarios) ---------------- */
  function tokenize(str) {
    const out = [];
    let cur = '', quoted = false, open = null;
    const push = () => { if (cur || quoted) out.push(cur); cur = ''; quoted = false; };
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (open) { if (ch === open) open = null; else cur += ch; quoted = true; continue; }
      if (ch === '"' || ch === "'") { open = ch; quoted = true; continue; }
      if (ch === '#' && !cur && !quoted) break;   // comentario de shell
      if (/\s/.test(ch)) { push(); continue; }
      cur += ch;
    }
    push();
    return out;
  }

  const sameSet = (a, b) => a.length === b.length && a.slice().sort().join(',') === b.slice().sort().join(',');

  /* ---------------- validación estricta de sintaxis ---------------- */
  function validate(raw, spec) {
    const toks = tokenize(raw);
    const prefixes = [spec.tokens].concat(spec.alts || []);
    const match = prefixes.find((p) => p.every((t, i) => toks[i] === t));

    if (!match) {
      return [`La orden debe empezar por \`${spec.tokens.join(' ')}\` — has escrito \`${toks.join(' ') || '(nada)'}\`.`];
    }

    const known = new Map();
    const flags = spec.flags || [];
    flags.forEach((f) => f.names.forEach((n) => known.set(n, f)));
    const seen = new Map();          // flag spec → [valores]
    const extra = [];                // argumentos posicionales sobrantes
    const errs = [];
    let quotesIssue = false;

    const add = (f, v) => { if (!seen.has(f)) seen.set(f, []); seen.get(f).push(v); };
    const flagName = (f) => f.names[f.names.length - 1];

    let i = match.length;
    while (i < toks.length) {
      const tok = toks[i];
      if (tok.startsWith('-')) {
        let name = tok, inline = null;
        const eq = tok.indexOf('=');
        if (eq > 0) { name = tok.slice(0, eq); inline = tok.slice(eq + 1); }
        const f = known.get(name);
        if (!f) { errs.push(`Flag no reconocido para este reto: \`${name}\`.`); i++; continue; }
        if (inline !== null) { add(f, inline); i++; continue; }
        const next = toks[i + 1];
        if (next !== undefined && !next.startsWith('-')) { add(f, next); i += 2; continue; }
        add(f, null);                 // flag sin valor
        i += 1;
      } else {
        extra.push(tok);
        i += 1;
      }
    }

    for (const f of flags) {
      const vals = seen.get(f) || [];
      if (!vals.length) {
        errs.push(`Falta el flag \`${flagName(f)}\`${f.bool ? '' : ' con su valor'}.`);
        continue;
      }
      if (f.bool) continue;
      const want = f.value !== undefined ? f.value : f.checks ? f.checks.join(',') : (f.values || []).join(' ');
      const val = vals[0];

      if (f.checks) {
        const got = String(val || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
        if (!sameSet(got, f.checks.map((c) => c.toLowerCase()))) {
          errs.push(`\`--checks\` debe ser exactamente \`${f.checks.join(',')}\` (has escrito \`${val || 'nada'}\`).`);
        }
      } else if (f.values) {
        for (const v of f.values) {
          if (!vals.includes(v)) errs.push(`Falta la cabecera \`${v}\` en \`${flagName(f)}\`.`);
        }
      } else if (val !== want) {
        if (want.includes(' ') && raw.includes(want)) {
          quotesIssue = true;
          errs.push(`\`${flagName(f)}\` lleva espacios: envuelve el valor entre comillas → \`${flagName(f)} "${want}"\`.`);
        } else {
          errs.push(`\`${flagName(f)}\` espera \`${want}\` pero has escrito \`${val === null || val === undefined ? '(sin valor)' : val}\`.`);
        }
      }
    }

    if (!quotesIssue) for (const x of extra) errs.push(`Sobra el argumento \`${x}\`.`);
    return errs;
  }

  /* ---------------- construcción de salida ---------------- */
  const hud = () => ({
    t: 'hud',
    v: `NIVEL ${String(run.level).padStart(2, '0')}/${MAX_LEVEL} · RETO ${run.task + 1}/${levelTasks(run.level).length} · XP ${run.xp} · estrellas ${run.stars} · rango: ${rankOf(run.xp)}`,
  });

  function taskLines() {
    const spec = currentSpec();
    const lvl = levelOf(run.level);
    return [
      { t: 'gap' },
      { t: 'goal', v: `RETO ${run.task + 1}/${levelTasks(run.level).length} · ${lvl.icon} ${spec.goal}` },
      { t: 'dim', v: `sintaxis: \`${spec.syntax}\`` },
    ];
  }

  function levelIntro() {
    const lvl = levelOf(run.level);
    return [
      { t: 'h', v: `NIVEL ${lvl.id} · ${lvl.icon} ${lvl.title}` },
    ].concat(lvl.theory, [{ t: 'gap' }], [hud()], taskLines());
  }

  function mapRows() {
    return MISSIONS.map((m) => {
      let state;
      if (run.done || run.level > m.id) state = '✅ superado';
      else if (run.level === m.id) state = '▶️ en curso';
      else state = '🔒 bloqueado';
      return [String(m.id).padStart(2, '0'), `${m.icon} ${m.title}`, state];
    });
  }

  function statusLines() {
    if (run.done) return victoryLines();
    return [
      { t: 'h', v: 'Mapa de la campaña' },
      { t: 'table', head: ['#', 'Nivel', 'Estado'], rows: mapRows() },
      { t: 'gap' },
      { t: 'p', v: 'Rango actual: ' + rankOf(run.xp) + ' · XP acumulada: ' + run.xp },
      hud(),
    ].concat(taskLines());
  }

  function victoryLines() {
    return [
      { t: 'h', v: '🏁 ¡Campaña completada!' },
      { t: 'ok', v: `${MAX_LEVEL}/${MAX_LEVEL} niveles superados · ${run.xp} XP · ${run.stars} estrellas` },
      { t: 'ok', v: `Rango final: ${rankOf(run.xp)}` },
      { t: 'gap' },
      { t: 'p', v: 'Cada `mission start` genera una campaña nueva: otras URLs, otros checks, otros retos.' },
      { t: 'dim', v: 'o escribe `help` para seguir leyendo el tutorial.' },
    ];
  }

  /* ---------------- avance ---------------- */
  function advance() {
    const hinted = !!run.hinted;
    run.xp += hinted ? 20 : 50;
    run.stars += hinted ? 2 : 3;
    run.task += 1;
    run.hinted = false;

    const lines = [
      { t: 'ok', v: hinted ? `Reto superado con pista (+20 XP, ${starsOf(2)})` : `Reto superado (+50 XP, ${starsOf(3)})` },
    ];

    const tasks = levelTasks(run.level);
    if (run.task >= tasks.length) {
      run.xp += 100;
      run.level += 1;
      run.task = 0;
      if (run.level > MAX_LEVEL) {
        run.done = true;
        save();
        return lines.concat([{ t: 'gap' }], victoryLines());
      }
      lines.push(
        { t: 'gap' },
        { t: 'ok', v: `NIVEL COMPLETADO · +100 XP · rango: ${rankOf(run.xp)}` },
      );
      save();
      return lines.concat(levelIntro());
    }

    save();
    return lines.concat(taskLines(), [hud()]);
  }

  /* ---------------- comandos del modo misión ---------------- */
  function startCmd() {
    if (active()) {
      return [
        { t: 'warn', v: 'Ya hay una partida en curso. Escribe `mission status` o `mission reset` para empezar otra.' },
        hud(),
      ];
    }
    run = { seed: Math.floor(Math.random() * 0x7fffffff), level: 1, task: 0, xp: 0, stars: 0, hinted: false };
    save();
    return [
      { t: 'h', v: '🏴‍☠️ Nueva campaña — Modo Misión' },
      { t: 'p', v: '12 niveles · cada partida cambia los objetivos, checks y flags. Solo vales escribiendo el comando real de `sparrow` con la sintaxis correcta.' },
      { t: 'dim', v: 'Comandos del juego: `mission status` · `hint` (pista, −1 estrella) · `rank` · `abort`' },
      { t: 'gap' },
      { t: 'ok', v: `Semilla de partida: #${run.seed}` },
      storageOk() ? null : { t: 'warn', v: '⚠️ Este navegador no permite guardar datos (localStorage): el progreso se perderá al recargar o cerrar la pestaña.' },
    ].filter(Boolean).concat(levelIntro());
  }

  function resetCmd() {
    if (!run) return [{ t: 'dim', v: 'No hay ninguna partida guardada. Empieza con `mission start`.' }];
    wipe();
    run = null;
    return [{ t: 'ok', v: 'Progreso borrado. `mission start` genera una campaña nueva.' }];
  }

  function abortCmd() {
    if (!run) return [{ t: 'dim', v: 'No hay ninguna partida en curso.' }];
    const msg = run.done ? 'Campaña cerrada.' : `Partida abandonada en el nivel ${run.level} (${run.xp} XP).`;
    wipe();
    run = null;
    return [{ t: 'warn', v: msg + ' Escribe `mission start` para otra campaña.' }];
  }

  function hintCmd() {
    if (!active()) return [{ t: 'dim', v: 'Sin reto activo. Empieza con `mission start`.' }];
    const spec = currentSpec();
    const lines = [
      { t: 'h', v: '💡 Pista' },
      { t: 'p', v: spec.hint },
      { t: 'dim', v: 'sintaxis del reto: `' + spec.syntax + '`' },
    ];
    if (!run.hinted) {
      run.hinted = true;
      save();
      lines.push({ t: 'warn', v: 'Usar pista en este reto deja el reto en 2★ y recorta el XP a +20.' });
    }
    return lines;
  }

  function rankCmd() {
    const xp = run ? run.xp : 0;
    const rows = RANKS.map(([t, n]) => [n, `${t} XP`, xp >= t ? '✔ conseguido' : `faltan ${t - xp} XP`]);
    return [
      { t: 'h', v: '🏆 Rangos' },
      { t: 'table', head: ['Rango', 'Requisito', 'Estado'], rows },
      { t: 'gap' },
      { t: 'dim', v: 'XP por reto: 50 sin pista / 20 con pista · +100 por nivel · +3★ sin pista.' },
    ];
  }

  function missionCmd(arg) {
    if (arg === 'start') return startCmd();
    if (arg === 'reset') return resetCmd();
    if (arg === 'status' || arg === '') {
      if (!run) return TUTORIAL.mission;
      return statusLines();
    }
    return [
      { t: 'warn', v: `subcomando desconocido: mission ${arg}` },
      { t: 'dim', v: 'Válidos: `mission start` · `mission status` · `mission reset`' },
    ];
  }

  function tryChallenge(raw) {
    if (!active()) {
      return TUTORIAL.mission.concat([
        { t: 'gap' },
        { t: 'warn', v: 'El modo misión no está activo: escribe `mission start` para jugar.' },
      ]);
    }
    const spec = currentSpec();
    const errs = validate(raw, spec);
    if (errs.length) {
      return errs.map((e) => ({ t: 'warn', v: e })).concat([
        { t: 'dim', v: `sintaxis del reto: \`${spec.syntax}\`` },
        { t: 'dim', v: 'Escribe `hint` si te atascas.' },
        hud(),
      ]);
    }
    const praise = PRAISE[Math.floor(Math.random() * PRAISE.length)];
    return [{ t: 'ok', v: `${praise} comando válido ✓` }].concat(advance());
  }

  /* ---------------- API ---------------- */
  function isCmd(c) {
    return c === 'mission' || c.startsWith('mission ')
      || c === 'hint' || c === 'abort' || c === 'rank'
      || c.startsWith('sparrow ') || c === 'sparrow'
      || c.startsWith('make ');
  }

  function handle(raw) {
    const s = raw.trim();
    const low = s.toLowerCase();
    if (low === 'mission' || low.startsWith('mission ')) return missionCmd(s.slice(7).trim().toLowerCase());
    if (low === 'hint') return hintCmd();
    if (low === 'abort') return abortCmd();
    if (low === 'rank') return rankCmd();
    return tryChallenge(s);
  }

  function restore() {
    run = load();
    if (!run) return null;
    if (run.done) return [{ t: 'ok', v: 'Campaña anterior completada ✔' }].concat(victoryLines());
    return [
      { t: 'ok', v: `Partida restaurada (semilla #${run.seed}) · ${rankOf(run.xp)}` },
      hud(),
    ].concat(taskLines());
  }

  window.GAME = { isCmd, run: handle, restore, active };

  /* Hook para tests (solo si el entorno lo marca antes de cargar el script) */
  if (window.__MISSION_TEST__) {
    window.GAME._debug = () => ({
      state: run,
      spec: active() ? currentSpec() : null,
      levelTasks: active() ? levelTasks(run.level).length : 0,
    });
  }
})();

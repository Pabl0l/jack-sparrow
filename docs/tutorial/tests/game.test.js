/* ============================================================
   Test de humo del Modo Misión (sin dependencias)

     node docs/tutorial/tests/game.test.js

   Carga content.js + game.js en un VM con localStorage simulado
   y verifica: arranque, validación estricta, comillas obligatorias,
   avance de nivel, victoria, persistencia y variabilidad entre
   partidas.
   ============================================================ */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const dir = path.join(__dirname, '..');
const SRC = {
  content: fs.readFileSync(path.join(dir, 'js', 'content.js'), 'utf8'),
  game: fs.readFileSync(path.join(dir, 'js', 'game.js'), 'utf8'),
};

let passed = 0;
const ok = (cond, msg) => {
  if (!cond) { console.error('✗ ' + msg); process.exitCode = 1; }
  else { passed++; console.log('✓ ' + msg); }
};

/** Crea un entorno aislado con un almacén de persistencia compartible. */
function makeEnv(shared) {
  const store = shared || {};
  const ctx = {
    window: { __MISSION_TEST__: true },
    console,
    localStorage: {
      getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
      removeItem: (k) => { delete store[k]; },
    },
  };
  vm.createContext(ctx);
  vm.runInContext(SRC.content, ctx, { filename: 'content.js' });
  vm.runInContext(SRC.game, ctx, { filename: 'game.js' });
  return { ctx, store, G: ctx.window.GAME };
}

/** Reconstruye el comando exacto que pide un reto. */
function build(spec, quote) {
  const q = quote === false ? (v) => v : (v) => '"' + v + '"';
  let cmd = spec.tokens.join(' ');
  for (const f of spec.flags || []) {
    const name = f.names[f.names.length - 1];
    if (f.bool) { cmd += ' ' + name; continue; }
    if (f.checks) { cmd += ' ' + name + ' ' + f.checks.join(','); continue; }
    if (f.values) { for (const v of f.values) cmd += ' ' + name + ' ' + q(v); continue; }
    cmd += ' ' + name + ' ' + q(f.value);
  }
  return cmd;
}

const text = (lines) => lines.map((l) => l.v || '').join('\n');
const has = (lines, re) => re.test(text(lines));

/* ── 1. arranque ──────────────────────────────────────────── */
const { G, store } = makeEnv();
ok(G && typeof G.run === 'function', 'GAME se expone en window');
ok(!G.active(), 'no hay partida activa al cargar');

const start = G.run('mission start');
ok(has(start, /NIVEL 1/), 'mission start imprime el nivel 1');
ok(has(start, /RETO 1\//), 'mission start imprime el primer reto');
ok(has(start, /Nueva campaña/), 'mission start crea campaña');
ok(G.active(), 'la partida queda activa');

/* ── 2. validación estricta ───────────────────────────────── */
const wrong = G.run('escanear la web porfa');
ok(has(wrong, /debe empezar por/), 'entrada sin prefijo → error de prefijo');
ok(has(wrong, /sintaxis del reto/), 'el error recuerda la sintaxis');

const spec1 = G._debug().spec;
const good = G.run(build(spec1));
ok(has(good, /superado|COMPLETADO/), 'el comando correcto supera el reto: ' + build(spec1));
ok(G._debug().state.task === 1 || G._debug().state.level === 2, 'avanza al siguiente reto');

/* ── 3. comillas obligatorias cuando el valor lleva espacios ─ */
const st = G._debug().state;
st.level = 5; st.task = 0; st.hinted = false;
let cookieSpec = null;
for (let t = 0; t < 3 && !cookieSpec; t++) {
  st.task = t;
  const s = G._debug().spec;
  const f = (s.flags || []).find((x) => Array.isArray(x.names) && x.names.includes('--cookie'));
  if (f && f.value && f.value.includes(' ')) cookieSpec = s;
}
ok(!!cookieSpec, 'la nivel 5 genera un reto de cookie con espacios');
if (cookieSpec) {
  const sinComillas = build(cookieSpec, false);
  const fail = G.run(sinComillas);
  ok(has(fail, /comillas/), 'cookie sin comillas → pide comillas: ' + sinComillas);
  const conComillas = G.run(build(cookieSpec, true));
  ok(has(conComillas, /superado|COMPLETADO/), 'cookie entre comillas → supera el reto');
}

/* ── 4. checks: conjunto exacto, orden libre ──────────────── */
const st2 = G._debug().state;
st2.level = 3; st2.task = 0;
const spec3 = G._debug().spec;
const checksFlag = spec3.flags.find((f) => f.checks);
const reordered = spec3.tokens.join(' ')
  + ' ' + spec3.flags.filter((f) => !f.checks)
      .map((f) => f.names[f.names.length - 1] + ' "' + f.value + '"').join(' ')
  + ' --checks ' + checksFlag.checks.slice().reverse().join(',');
const reord = G.run(reordered);
ok(has(reord, /superado|COMPLETADO/), 'el orden de --checks no importa: ' + reordered);

const badChecks = G.run(spec3.tokens.join(' ') + ' --checks sqli');
ok(has(badChecks, /debe ser exactamente/), 'checks incompletos → error');

/* ── 5. victoria ──────────────────────────────────────────── */
const st3 = G._debug().state;
st3.level = 12; st3.task = G._debug().levelTasks - 1; st3.hinted = false;
const last = G.run(build(G._debug().spec));
ok(has(last, /¡Campaña completada!/), 'completar el nivel 12 → victoria');
ok(!G.active(), 'la partida termina al ganar');

/* ── 6. persistencia entre sesiones ───────────────────────── */
const env2 = makeEnv(store);
ok(env2.G.restore() !== null, 'restore() recupera la partida guardada');
ok(has(env2.G.restore(), /completada|Partida restaurada/), 'restore() informa del estado guardado');
env2.G.run('mission reset');
ok(!env2.G.active(), 'mission reset borra el progreso');

/* ── 7. cada partida es distinta ──────────────────────────── */
function signatures() {
  const e = makeEnv();
  e.G.run('mission start');
  const sigs = [];
  for (let l = 1; l <= 12; l++) {
    const st4 = e.G._debug().state;
    st4.level = l; st4.task = 0;
    sigs.push(JSON.stringify(e.G._debug().spec));
    if (e.G._debug().state.done) break;
  }
  return sigs.join('|');
}
const a = signatures();
const b = signatures();
ok(a !== b, 'dos partidas generan retos distintos');

/* ── 8. pista y rangos ────────────────────────────────────── */
const env3 = makeEnv();
env3.G.run('mission start');
const hint = env3.G.run('hint');
ok(has(hint, /Pista/) && has(hint, /sintaxis del reto/), 'hint explica la sintaxis');
ok(env3.G._debug().state.hinted === true, 'hint marca el reto como pistado');
const ranks = env3.G.run('rank');
ok(has(ranks, /Rangos/) && ranks.some((l) => l.t === 'table'), 'rank lista los rangos');
const map = env3.G.run('mission status');
ok(has(map, /Mapa de la campaña/), 'mission status muestra el mapa de niveles');

console.log('\n' + passed + ' aserciones superadas');

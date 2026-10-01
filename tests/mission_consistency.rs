//! # Consistencia CLI ↔ Modo Misión (weakness #29)
//!
//! Los retos del Modo Misión (`docs/tutorial/js/content.js → MISSIONS`) enseñan
//! sintaxis **real** de sparrow: keywords de `--checks`, flags y subcomandos.
//! Si la CLI cambia (flag renombrado, keyword eliminada, subcomando nuevo), un
//! reto podría rechazar un comando que en realidad es válido.
//!
//! Este test extrae lo que enseña `MISSIONS` y lo cruza con las fuentes de
//! verdad del repo:
//!   - `src/core/engine.rs → parse_checks`  → keywords válidas de `--checks`
//!   - `src/cli/mod.rs`                    → flags (long/short) y subcomandos
//!
//! Falla con un mensaje accionable cuando cualquiera de los dos lados cambia.
use regex::Regex;
use std::collections::BTreeSet;
use std::fs;

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("no se pudo leer {rel}: {e}"))
}

/// Bloque `const MISSIONS = [ ... ];` del contenido del tutorial.
fn missions_block() -> String {
    let src = read("docs/tutorial/js/content.js");
    let start = src
        .find("const MISSIONS = [")
        .expect("content.js debe definir `const MISSIONS`");
    let end = src[start..]
        .find("\n];")
        .map(|i| start + i)
        .expect("el bloque MISSIONS debe cerrarse con `];`");
    src[start..end].to_string()
}

/// Literales `'...'` dentro de un fragmento JS (sin comillas anidadas).
fn literals(fragment: &str) -> Vec<String> {
    let re = Regex::new(r"'([a-z0-9-]+)'").expect("regex válida");
    re.captures_iter(fragment)
        .map(|c| c[1].to_string())
        .collect()
}

/// Primer campo plano de un array JS: `['a', 'b']` → `a`, `b`.
fn array_field(block: &str, key: &str) -> Vec<Vec<String>> {
    let re = Regex::new(&format!(r"{key}:\s*\[([^\]]*)\]")).expect("regex válida");
    re.captures_iter(block).map(|c| literals(&c[1])).collect()
}

/// `CamelCase` → `camel-case` (nombres de subcomando de clap).
fn kebab(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Keywords aceptadas por `parse_checks` (incluye alias y `all`).
fn valid_checks() -> BTreeSet<String> {
    let src = read("src/core/engine.rs");
    let start = src
        .find("fn parse_checks")
        .expect("engine.rs debe definir parse_checks");
    let end = src[start..]
        .find("Ok(types)")
        .map(|i| start + i)
        .expect("parse_checks debe terminar en Ok(types)");
    let region = &src[start..end];
    let re = Regex::new(r#""([a-z0-9][a-z0-9-]*)""#).expect("regex válida");
    re.captures_iter(region).map(|c| c[1].to_string()).collect()
}

/// Flags `--largo` declarados en la CLI (derivan del nombre del campo).
fn long_flags() -> BTreeSet<String> {
    let src = read("src/cli/mod.rs");
    // Campos de structs (`pub target:`) y de variantes de enum (`target:` sin `pub`).
    let re = Regex::new(r"(?m)^\s+([a-z][a-z0-9_]*):").expect("regex válida");
    let mut set: BTreeSet<String> = re
        .captures_iter(&src)
        .map(|c| format!("--{}", c[1].replace('_', "-")))
        .collect();
    // La ayuda la inyecta clap en todos los comandos.
    set.insert("--help".into());
    set
}

/// Flags cortos `-x` declarados con `#[arg(short, ...)]` (primera letra del campo).
fn short_flags() -> BTreeSet<String> {
    let src = read("src/cli/mod.rs");
    let re = Regex::new(r"#\[arg\(([^)]*)\)\]\s*\n\s+(?:pub\s+)?([a-z][a-z0-9_]*):")
        .expect("regex válida");
    let mut set: BTreeSet<String> = re
        .captures_iter(&src)
        .filter(|c| c[1].contains("short"))
        .map(|c| format!("-{}", c[2].chars().next().expect("campo no vacío")))
        .collect();
    // Ayuda de clap (`-h`).
    set.insert("-h".into());
    set
}

/// Subcomandos de clap (`CheckTools` → `check-tools`).
fn subcommands() -> BTreeSet<String> {
    let src = read("src/cli/mod.rs");
    let start = src
        .find("pub enum Commands")
        .expect("cli/mod.rs debe definir Commands");
    let re = Regex::new(r"(?m)^    ([A-Z][A-Za-z0-9]*)").expect("regex válida");
    let mut set: BTreeSet<String> = re
        .captures_iter(&src[start..])
        .map(|c| kebab(&c[1]))
        .collect();
    // Ayuda generada por clap.
    set.insert("help".into());
    set
}

#[test]
fn mission_challenges_use_real_cli_syntax() {
    let block = missions_block();

    /* ---- qué enseña MISSIONS ---- */
    let mut checks_taught: BTreeSet<String> = array_field(&block, "checks")
        .into_iter()
        .flatten()
        .collect();
    let names_taught: BTreeSet<String> =
        array_field(&block, "names").into_iter().flatten().collect();
    let tokens_taught: Vec<Vec<String>> = array_field(&block, "tokens");

    // `alts: [['sparrow','-h']]` — arrays anidados, se extrae a mano.
    let alts_re = Regex::new(r"alts:\s*\[\[([^\]]*)\]\]").expect("regex válida");
    let alts_taught: Vec<String> = alts_re
        .captures_iter(&block)
        .flat_map(|c| literals(&c[1]))
        .collect();

    // Pares `[keyword, --flag]` del nivel 9 (PAIRS) y de las tablas de teoría.
    // (Descarta `names: ['-t', '--target']` y `alts: [['sparrow', '--help']]`.)
    let pair_re =
        Regex::new(r"\[\s*'([a-z][a-z0-9-]*)'\s*,\s*'(--[a-z0-9-]+)'\s*\]").expect("regex válida");
    let pairs_taught: Vec<(String, String)> = pair_re
        .captures_iter(&block)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .filter(|(k, _)| k != "sparrow" && k != "make")
        .collect();

    // Red de seguridad: si un regex deja de casar, el test no puede pasar en vacío.
    assert!(
        checks_taught.len() >= 15,
        "solo se extrajeron {} keywords de --checks: revisa el regex de `checks:`",
        checks_taught.len()
    );
    assert!(
        names_taught.len() >= 10,
        "solo se extrajeron {} flags: revisa el regex de `names:`",
        names_taught.len()
    );
    assert!(
        tokens_taught.len() >= 15,
        "solo se extrajeron {} `tokens:`: revisa el regex",
        tokens_taught.len()
    );
    assert!(
        pairs_taught.len() >= 12,
        "solo se extrajeron {} pares [keyword, --flag]: revisa el regex",
        pairs_taught.len()
    );

    /* ---- fuentes de verdad de la CLI ---- */
    let cli_checks = valid_checks();
    let cli_long = long_flags();
    let cli_short = short_flags();
    let cli_subs = subcommands();

    // Los pares keyword↔flag (nivel 9 y tablas) alimentan las mismas comprobaciones.
    checks_taught.extend(pairs_taught.iter().map(|(k, _)| k.clone()));

    /* ---- 1. keywords de --checks ---- */
    let bad_checks: Vec<_> = checks_taught
        .iter()
        .filter(|k| !cli_checks.contains(k.as_str()))
        .collect();
    assert!(
        bad_checks.is_empty(),
        "MISSIONS enseña keywords que parse_checks ya no acepta: {bad_checks:?}. \
         Sincroniza los retos con `src/core/engine.rs`."
    );

    /* ---- 2. flags (long y cortos) ---- */
    let mut flags_taught: BTreeSet<String> = names_taught
        .iter()
        .filter(|n| n.starts_with('-'))
        .cloned()
        .collect();
    // Prefijos declarados en `tokens:` (`sparrow --help`) y en `alts`.
    flags_taught.extend(
        tokens_taught
            .iter()
            .flat_map(|t| t.iter())
            .chain(alts_taught.iter())
            .filter(|t| t.starts_with('-'))
            .cloned(),
    );
    // La ayuda la genera clap en todos los comandos.
    flags_taught.extend(pairs_taught.iter().map(|(_, f)| f.clone()));
    flags_taught.extend(["--help".to_string(), "-h".to_string()]);

    let bad_long: Vec<_> = flags_taught
        .iter()
        .filter(|f| f.starts_with("--"))
        .filter(|f| !cli_long.contains(f.as_str()))
        .collect();
    let bad_short: Vec<_> = flags_taught
        .iter()
        .filter(|f| f.starts_with('-') && !f.starts_with("--"))
        .filter(|f| !cli_short.contains(f.as_str()))
        .collect();
    assert!(
        bad_long.is_empty(),
        "MISSIONS enseña flags --largo inexistentes en la CLI: {bad_long:?}. \
         Revisa `src/cli/mod.rs`."
    );
    assert!(
        bad_short.is_empty(),
        "MISSIONS enseña flags cortos inexistentes en la CLI: {bad_short:?}. \
         Revisa `#[arg(short)]` en `src/cli/mod.rs`."
    );

    /* ---- 3. subcomandos (`sparrow <sub>` / `make <objetivo>`) ---- */
    let mut subs_taught: BTreeSet<String> = BTreeSet::new();
    let mut make_taught: BTreeSet<String> = BTreeSet::new();
    for t in &tokens_taught {
        if t.len() < 2 || t[1].starts_with('-') {
            continue; // `['sparrow', '--help']` → flag, ya cubierto arriba
        }
        match t[0].as_str() {
            "sparrow" => {
                subs_taught.insert(t[1].clone());
            }
            "make" => {
                make_taught.insert(t[1].clone());
            }
            other => panic!("`tokens` con prefijo inesperado: {other:?}"),
        }
    }
    for a in &alts_taught {
        if a != "sparrow" && !a.starts_with('-') {
            subs_taught.insert(a.clone());
        }
    }
    let bad_subs: Vec<_> = subs_taught
        .iter()
        .filter(|s| !cli_subs.contains(s.as_str()))
        .collect();
    assert!(
        bad_subs.is_empty(),
        "MISSIONS enseña subcomandos inexistentes en la CLI: {bad_subs:?}. \
         Revisa `enum Commands` en `src/cli/mod.rs`."
    );

    // Objetivos de Make (`make lab-up`): deben existir en el Makefile real.
    let makefile = read("Makefile");
    let bad_make: Vec<_> = make_taught
        .iter()
        .filter(|t| !makefile.contains(&format!("{t}:")))
        .collect();
    assert!(
        bad_make.is_empty(),
        "MISSIONS enseña objetivos de Make inexistentes: {bad_make:?}. Revisa el `Makefile`."
    );
}

#[test]
fn mission_levels_are_well_formed() {
    let block = missions_block();

    let ids: Vec<usize> = Regex::new(r"id:\s*(\d+)")
        .expect("regex válida")
        .captures_iter(&block)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        ids,
        (1..=12).collect::<Vec<_>>(),
        "debe haber 12 niveles 1..12"
    );

    // Cada nivel declara `pick: N` y al menos N retos (`tokens:` por nivel).
    let picks: Vec<usize> = Regex::new(r"pick:\s*(\d+)")
        .expect("regex válida")
        .captures_iter(&block)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(picks.len(), 12, "los 12 niveles deben declarar `pick`");
    assert!(
        picks.iter().all(|&p| (1..=5).contains(&p)),
        "pick razonable"
    );

    // Toda apertura de nivel tiene teoría y toda tarea tiene su sintaxis.
    assert_eq!(
        Regex::new(r"theory:\s*\[")
            .expect("regex válida")
            .find_iter(&block)
            .count(),
        12,
        "los 12 niveles deben explicar su teoría"
    );
    assert!(
        Regex::new(r"syntax:\s*'")
            .expect("regex válida")
            .find_iter(&block)
            .count()
            >= 40,
        "cada reto debe mostrar su plantilla de sintaxis con [concepto]"
    );
}

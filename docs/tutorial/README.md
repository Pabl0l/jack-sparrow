# docs/tutorial — Tutorial interactivo de Jack Sparrow 🏴‍☠️

Tutorial **estilo terminal** (estética *Matrix* del portafolio: neon `#39ff14`, VT323 / JetBrains Mono, rain de fondo, CRT) basado en [`TUTORIAL.md`](../../TUTORIAL.md), con un **Modo Misión** jugable: 12 niveles donde tienes que tipear el comando real de `sparrow`.

## Cómo se usa

```bash
sparrow tutorial                          # lo escribe en temp y lo abre en el navegador
sparrow tutorial --save ruta/tuto.html    # solo guarda (CI, archivado)
```

También puedes abrir `index.html` directamente aquí (carga `css/` y `js/` relativos).

## Modo Misión (el juego)

```text
mission start     # nueva partida — 12 niveles, retos aleatorios
mission status    # mapa de niveles, XP, estrellas y reto actual
mission reset     # borra el progreso
hint              # pista del reto actual (deja el reto en 2★)
rank              # rangos: Grumete → Marinero → Piloto → Contramaestre → Primer Oficial → Capitán
abort             # abandona la partida
```

- **Cómo se pasa un reto**: te dan un objetivo (URL + alcance) y una explicación del flag/keyword a usar; escribes el comando con la sintaxis correcta y el validador lo comprueba (prefijo, flags, valores, comillas cuando el valor lleva espacios, conjunto exacto de `--checks` — el orden no importa).
- **Sintaxis con `[concepto]`**: cada reto muestra `sintaxis: sparrow scan -t [target-url] --checks [keywords]` — tu trabajo es sustituir los corchetes por los valores del enunciado.
- **Cada partida es distinta**: una semilla genera las URLs, checks, cookies, tokens, ficheros y qué retos entran en cada nivel.
- **Progreso**: se guarda en `localStorage` (recargas y sigues donde estabas). XP 50 reto / 20 con pista, +100 por nivel.

| Nivel | Tema | Nivel | Tema |
|-------|------|-------|------|
| 01 | Reconocimiento | 07 | Reportes |
| 02 | Tu primer escaneo | 08 | Rendimiento |
| 03 | Alcance selectivo | 09 | Scanners opt-in |
| 04 | El catálogo de checks | 10 | Wordlists y configuración |
| 05 | Autenticación con cookie | 11 | Laboratorios y práctica |
| 06 | Cabeceras de autorización | 12 | Reto final |

## Cómo funciona

- `src/commands/tutorial.rs` ensambla el sitio en un **único HTML autocontenido**
  (`include_str!` de index + css + js) con `open` para lanzar el navegador.
- Sin dependencia de red (salvo Google Fonts, con fallback a Courier).

## Estructura

```
docs/tutorial/
├── index.html            # shell + nav + footer
├── css/style.css         # tema Matrix + estilos de reto/HUD
├── js/content.js         # contenido (TUTORIAL.md) + definición de MISSIONS
├── js/game.js            # motor del Modo Misión (PRNG, validador, XP, persistencia)
├── js/terminal.js        # motor de terminal: boot, banner, render, comandos, rain
├── tests/game.test.js    # test de humo del modo misión (node, sin dependencias)
└── README.md
```

## Interacción

| Acción | Resultado |
|--------|-----------|
| `mission start` | Empieza una campaña del Modo Misión |
| `help` | Lista de comandos |
| `install` `scan` `checks` `auth`... | Imprime cada sección del tutorial |
| Botones del nav | Ejecutan el comando equivalente |
| `Tab` / `↑` `↓` | Autocompletado / historial |
| Enter (input vacío) | Salta la animación |
| `Ctrl+L` / `clear` | Limpia la pantalla |
| `sudo` | Easter egg 😉 |

El banner ASCII es el oficial de `src/main.rs → print_banner()`.

## Tests

```bash
node docs/tutorial/tests/game.test.js     # 25 aserciones del Modo Misión
cargo test --lib tutorial                 # ensamblado (inline de assets + game.js)
cargo test --test e2e                     # `tutorial --save` autocontenido
```

**Fuente de contenido**: [`TUTORIAL.md`](../../TUTORIAL.md) · si cambia el tutorial, actualizar `js/content.js`.

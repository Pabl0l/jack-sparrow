# docs/tutorial — Tutorial interactivo de Jack Sparrow 🏴‍☠️

Tutorial **estilo terminal** (estética *Matrix* del portafolio: neon `#39ff14`, VT323 / JetBrains Mono, rain de fondo, CRT) basado en [`TUTORIAL.md`](../../TUTORIAL.md).

## Cómo se usa

```bash
sparrow tutorial                          # lo escribe en temp y lo abre en el navegador
sparrow tutorial --save ruta/tuto.html    # solo guarda (CI, archivado)
```

También puedes abrir `index.html` directamente aquí (carga `css/` y `js/` relativos).

## Cómo funciona

- `src/commands/tutorial.rs` ensambla el sitio en un **único HTML autocontenido**
  (`include_str!` de index + css + js) con `open` para lanzar el navegador.
- Sin dependencia de red (salvo Google Fonts, con fallback a Courier).

## Estructura

```
docs/tutorial/
├── index.html        # shell + nav + footer
├── css/style.css     # tema Matrix
├── js/content.js     # contenido del tutorial (TUTORIAL.md) como líneas tipadas
├── js/terminal.js    # motor: boot, banner, render, comandos, rain
└── README.md
```

## Interacción

| Acción | Resultado |
|--------|-----------|
| `help` | Lista de los 24 comandos |
| `install` `scan` `checks` `auth`... | Imprime cada sección del tutorial |
| Botones del nav | Ejecutan el comando equivalente |
| `Tab` / `↑` `↓` | Autocompletado / historial |
| Enter (input vacío) | Salta la animación |
| `Ctrl+L` / `clear` | Limpia la pantalla |
| `sudo` | Easter egg 😉 |

El banner ASCII es el oficial de `src/main.rs → print_banner()`.

**Fuente de contenido**: [`TUTORIAL.md`](../../TUTORIAL.md) · si cambia el tutorial, actualizar `js/content.js`.

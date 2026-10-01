//! `sparrow tutorial` — embebe el tutorial HTML interactivo y lo abre en el
//! navegador. Pensado como primer paso justo después de instalar la herramienta.
//!
//! El HTML fuente vive en `docs/tutorial/` (index + css + js). Aquí se ensambla
//! en un único documento autocontenido para que funcione sin red ni ficheros
//! externos.
use crate::shared::error::JackSparrowError;
use colored::Colorize;
use std::path::Path;

const INDEX: &str = include_str!("../../docs/tutorial/index.html");
const CSS: &str = include_str!("../../docs/tutorial/css/style.css");
const CONTENT_JS: &str = include_str!("../../docs/tutorial/js/content.js");
const TERMINAL_JS: &str = include_str!("../../docs/tutorial/js/terminal.js");

/// Ensambla el tutorial en un único HTML autocontenido (inline de CSS y JS).
pub fn assemble() -> String {
    INDEX
        .replace(
            r#"<link rel="stylesheet" href="css/style.css">"#,
            &format!("<style>\n{CSS}\n</style>"),
        )
        .replace(
            r#"<script src="js/content.js"></script>"#,
            &format!("<script>\n{CONTENT_JS}\n</script>"),
        )
        .replace(
            r#"<script src="js/terminal.js"></script>"#,
            &format!("<script>\n{TERMINAL_JS}\n</script>"),
        )
}

/// Ejecuta el comando `sparrow tutorial`.
///
/// * Con `save`: escribe el HTML en la ruta indicada (sin abrir navegador —
///   pensado para CI y para archivar el tutorial junto a un informe).
/// * Sin `save`: lo escribe en el directorio temporal y lo abre en el
///   navegador por defecto.
pub fn execute_tutorial(save: Option<&Path>) -> Result<(), JackSparrowError> {
    let page = assemble();

    if let Some(path) = save {
        std::fs::write(path, &page)?;
        println!(
            "\n{} {}",
            "Tutorial saved to:".green().bold(),
            path.display()
        );
        println!("{}", "Open it in your browser to get started.".dimmed());
        return Ok(());
    }

    let path = std::env::temp_dir().join("sparrow-tutorial.html");
    std::fs::write(&path, &page)?;

    open::that(&path).map_err(|e| {
        JackSparrowError::Io(std::io::Error::other(format!(
            "Wrote {} but could not open the browser: {}",
            path.display(),
            e
        )))
    })?;

    println!(
        "\n{} {}",
        "Opening tutorial:".green().bold(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_inlines_assets() {
        let page = assemble();
        // El CSS y el JS quedan embebidos (sin referencias externas a ficheros).
        assert!(page.contains("--neon: #39ff14"));
        assert!(page.contains("COMMAND_NAMES"));
        assert!(!page.contains(r#"href="css/style.css""#));
        assert!(!page.contains(r#"src="js/terminal.js""#));
    }

    #[test]
    fn test_assemble_keeps_banner_and_content() {
        let page = assemble();
        assert!(page.contains("ADVANCED PENTEST TOOL"));
        assert!(page.contains("sparrow scan --target"));
        assert!(page.contains("lang=\"es\""));
    }
}

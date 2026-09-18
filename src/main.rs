use clap::Parser;
use colored::*;
use std::process;

mod cli;
mod commands;
mod core;
mod output;
mod shared;

use cli::Cli;
use shared::error::JackSparrowError;

fn print_banner() {
    println!(
        "{}",
        r#"
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
"#
    .green()
    .bold()
    );
    println!(
        "{}",
        "    >_ Ready to hack.".bright_green().bold()
    );
    println!();
}

#[tokio::main]
async fn main() -> Result<(), JackSparrowError> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Print banner before any CLI parsing
    print_banner();

    let cli = Cli::parse();

    // Execute command
    let result = commands::execute(cli).await;

    if let Err(e) = result {
        eprintln!("{}: {}", "Error".red().bold(), e);
        process::exit(1);
    }

    Ok(())
}

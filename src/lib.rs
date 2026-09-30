//! Jack Sparrow — web application security scanner.
//!
//! The binary in `main.rs` is a thin CLI wrapper around this library.

// CLI-style entry points (e.g. `execute_scan`) legitimately take many
// parameters; boxing them would obscure call sites for no runtime gain.
#![allow(clippy::too_many_arguments)]

pub mod cli;
pub mod commands;
pub mod core;
pub mod output;
pub mod shared;

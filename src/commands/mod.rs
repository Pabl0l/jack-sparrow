use crate::cli::{Cli, Commands};
use crate::core::engine::ScanEngine;
use crate::output::report::{self, ReportFormat};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use colored::Colorize;
use std::path::PathBuf;

/// Execute a CLI command
pub async fn execute(cli: Cli) -> Result<(), JackSparrowError> {
	// Load config
	let config = match cli.config {
		Some(path) => JackSparrowConfig::from_file(&path)?,
		None => JackSparrowConfig::default(),
	};

	// Validate config
	config.validate()?;

	match cli.command {
		Commands::Scan {
			target,
			checks,
			session,
			output,
			format,
			concurrency,
			timeout,
			cookie,
			header,
			login_url,
			login_user,
			login_pass,
			login_field_user,
			login_field_pass,
			login_field,
		} => {
			execute_scan(
				&target,
				&checks,
				session.as_deref(),
				output.as_deref(),
				&format,
				concurrency,
				timeout,
				cookie.as_deref(),
				&header,
				login_url.as_deref(),
				login_user.as_deref(),
				login_pass.as_deref(),
				&login_field_user,
				&login_field_pass,
				&login_field,
				&config,
			)
			.await
		}
		Commands::Record {
			output,
			browser,
			headless,
		} => execute_record(&output, &browser, headless).await,
		Commands::CheckTools => execute_check_tools(&config),
		Commands::InitConfig { output } => execute_init_config(&output),
		Commands::Version => {
			println!("Jack Sparrow 0.4.0");
			Ok(())
		}
	}
}

/// Parse header strings from CLI ("Key: Value") into tuples.
fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
	raw.iter()
		.filter_map(|h| {
			let mut parts = h.splitn(2, ':');
			let key = parts.next()?.trim().to_string();
			let value = parts.next()?.trim().to_string();
			if key.is_empty() {
				None
			} else {
				Some((key, value))
			}
		})
		.collect()
}

/// Execute scan command
async fn execute_scan(
	target: &str,
	checks: &str,
	session: Option<&std::path::Path>,
	output: Option<&std::path::Path>,
	format: &str,
	concurrency: usize,
	timeout: u64,
	cookie: Option<&str>,
	raw_headers: &[String],
	login_url: Option<&str>,
	login_user: Option<&str>,
	login_pass: Option<&str>,
	login_field_user: &str,
	login_field_pass: &str,
	login_fields: &[String],
	config: &JackSparrowConfig,
) -> Result<(), JackSparrowError> {
	println!(
		"\n{}",
		format!("Scanning: {}", target).bold().cyan()
	);
	println!("Checks: {}", checks);
	println!("Concurrency: {}", concurrency);
	println!("Timeout: {}s", timeout);

	// Build scan context — start with explicit cookies/headers
	let mut context = ScanContext {
		cookies: cookie.map(|s| s.to_string()),
		headers: parse_headers(raw_headers),
		session: session.map(|p| p.to_path_buf()),
	};

	// Perform form login if requested
	if let (Some(url), Some(user), Some(pass)) = (login_url, login_user, login_pass) {
		println!("Auth: performing form login to {}", url);

		// Parse extra fields
		let extra_fields: Vec<(String, String)> = login_fields
			.iter()
			.filter_map(|f| {
				let mut parts = f.splitn(2, '=');
				let name = parts.next()?.to_string();
				let value = parts.next()?.to_string();
				Some((name, value))
			})
			.collect();

		let login_config = crate::shared::auth::AuthConfig::FormLogin {
			login_url: url.to_string(),
			username: user.to_string(),
			password: pass.to_string(),
			username_field: login_field_user.to_string(),
			password_field: login_field_pass.to_string(),
			extra_fields,
			success_indicator: None,
		};

		let executor = crate::shared::auth::FormLoginExecutor::new();
		match executor.login_to_context(&login_config).await {
			Ok(login_ctx) => {
				// Merge login cookies into context
				if let Some(cookies) = login_ctx.cookies {
					println!("Auth: login successful, cookies: {}", &cookies[..cookies.len().min(50)]);
					context.cookies = Some(cookies);
				}
			}
			Err(e) => {
				eprintln!("\n{} {}", "Login failed:".red().bold(), e.red());
				return Err(JackSparrowError::ToolExecutionFailed {
					tool: "form-login".to_string(),
					message: e,
				});
			}
		}
	} else if cookie.is_some() {
		println!("Auth: cookies provided");
	}

	let mut engine = ScanEngine::new(config.clone());

	// Pre-scan tool verification
	let warnings = engine.verify_tools();
	if !warnings.is_empty() {
		eprintln!("\n{}", "Tool Warnings:".yellow().bold());
		for w in &warnings {
			eprintln!("  {}", w.yellow());
		}
		eprintln!();
	}

	let results = engine
		.scan(target, checks, &context, concurrency, timeout)
		.await?;

	// Enrich findings with auto-CVSS and specific remediation
	let mut results = results;
	report::enrich_findings(&mut results);

	// Display findings in terminal
	crate::output::display_findings(&results.findings);
	crate::output::display_summary(&results);

	// Determine report format
	let report_format = ReportFormat::from_str(format).unwrap_or(ReportFormat::Json);

	// Determine output path
	let default_name = format!("findings.{}", report_format.extension());
	let output_path = match output {
		Some(path) => path.to_path_buf(),
		None => PathBuf::from(&default_name),
	};

	// Generate and write report
	report::write_report(&results, report_format, &output_path).map_err(|e| {
		JackSparrowError::Io(std::io::Error::other(format!("Failed to write report: {}", e)))
	})?;

	println!(
		"\n{} {}",
		"Report saved to:".green().bold(),
		output_path.display()
	);

	Ok(())
}

/// Execute record command
async fn execute_record(
	output: &std::path::Path,
	browser: &str,
	headless: bool,
) -> Result<(), JackSparrowError> {
	crate::core::recorder::browser::record_session(output, browser, headless).await
}

/// Execute check-tools command
fn execute_check_tools(config: &JackSparrowConfig) -> Result<(), JackSparrowError> {
	println!("\n{}", "Checking installed tools...".bold().cyan());

	let missing = crate::shared::tool_checker::verify_all_tools(&config.tools)?;

	if missing.is_empty() {
		println!("{}", "All tools are installed.".green().bold());
	} else {
		eprintln!("\n{}", "Missing tools:".red().bold());
		for tool in &missing {
			eprintln!("  {} {}", "-".red(), tool.red());
		}
		eprintln!(
			"\n{}",
			"Install missing tools: make install-deps".yellow()
		);
		return Err(JackSparrowError::ToolNotFound {
			tool: missing.join(", "),
		});
	}

	Ok(())
}

/// Execute init-config command
fn execute_init_config(output: &std::path::Path) -> Result<(), JackSparrowError> {
	let config = JackSparrowConfig::default();
	config.to_file(&output.to_path_buf())?;
	println!(
		"\n{} {}",
		"Default configuration saved to:".green().bold(),
		output.display()
	);
	Ok(())
}

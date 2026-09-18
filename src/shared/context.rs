#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

/// Authentication context passed to all scanners.
///
/// Carries cookies, custom headers, and session data so scanners
/// can test authenticated endpoints without hardcoding auth logic.
#[derive(Debug, Clone, Default)]
pub struct ScanContext {
	/// Raw cookie string (e.g. `"PHPSESSID=abc123; security=low"`).
	/// Passed directly to sqlmap `--cookie` and dalfox `--cookies`.
	pub cookies: Option<String>,
	/// Custom HTTP headers as key-value pairs.
	/// Example: `("Authorization", "Bearer eyJ...")`
	pub headers: Vec<(String, String)>,
	/// Optional HAR session file recorded by Playwright.
	pub session: Option<PathBuf>,
}

impl ScanContext {
	/// Build a `HashMap` of headers for reqwest-based scanners.
	pub fn headers_map(&self) -> HashMap<String, String> {
		self.headers
			.iter()
			.map(|(k, v)| (k.clone(), v.clone()))
			.collect()
	}

	/// Return the cookie header value suitable for raw HTTP requests.
	/// If cookies are set, returns `Some(cookie_string)`.
	pub fn cookie_header(&self) -> Option<&str> {
		self.cookies.as_deref()
	}
}

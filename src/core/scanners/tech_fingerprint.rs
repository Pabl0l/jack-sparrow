use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;

/// A detected technology
struct TechMatch {
	name: String,
	version: Option<String>,
	tech_type: TechType,
	evidence: String,
}

#[derive(Debug, Clone, Copy)]
enum TechType {
	Server,
	Language,
	Framework,
	CMS,
	JavaScript,
	CSS,
	Analytics,
	Other,
}

impl std::fmt::Display for TechType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TechType::Server => write!(f, "Server"),
			TechType::Language => write!(f, "Language"),
			TechType::Framework => write!(f, "Framework"),
			TechType::CMS => write!(f, "CMS"),
			TechType::JavaScript => write!(f, "JavaScript"),
			TechType::CSS => write!(f, "CSS"),
			TechType::Analytics => write!(f, "Analytics"),
			TechType::Other => write!(f, "Technology"),
		}
	}
}

pub struct TechFingerprintScanner;

impl TechFingerprintScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self {
		Self
	}

	/// Detect technologies from response headers
	fn detect_from_headers(headers: &reqwest::header::HeaderMap) -> Vec<TechMatch> {
		let mut matches = Vec::new();

		// Server header
		if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
			let server_str = server.to_string();
			let (name, version) = parse_server_version(&server_str);
			matches.push(TechMatch {
				name,
				version,
				tech_type: TechType::Server,
				evidence: format!("Server: {}", server),
			});
		}

		// X-Powered-By
		if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
			let powered_str = powered.to_string();
			let (name, version) = parse_powered_by(&powered_str);
			matches.push(TechMatch {
				name,
				version,
				tech_type: TechType::Language,
				evidence: format!("X-Powered-By: {}", powered),
			});
		}

		// X-AspNet-Version
		if let Some(aspnet) = headers.get("x-aspnet-version").and_then(|v| v.to_str().ok()) {
			matches.push(TechMatch {
				name: "ASP.NET".to_string(),
				version: Some(aspnet.to_string()),
				tech_type: TechType::Framework,
				evidence: format!("X-AspNet-Version: {}", aspnet),
			});
		}

		// X-Drupal-Cache
		if headers.contains_key("x-drupal-cache") {
			matches.push(TechMatch {
				name: "Drupal".to_string(),
				version: None,
				tech_type: TechType::CMS,
				evidence: "X-Drupal-Cache header present".to_string(),
			});
		}

		// X-Generator (WordPress, Drupal, etc.)
		if let Some(generator) = headers.get("x-generator").and_then(|v| v.to_str().ok()) {
			let name = generator.to_string();
			let tech_type = if name.to_lowercase().contains("wordpress") {
				TechType::CMS
			} else if name.to_lowercase().contains("drupal") {
				TechType::CMS
			} else {
				TechType::Other
			};
			matches.push(TechMatch {
				name,
				version: None,
				tech_type,
				evidence: format!("X-Generator: {}", generator),
			});
		}

		// X-Runtime (Ruby on Rails)
		if headers.contains_key("x-runtime") {
			matches.push(TechMatch {
				name: "Ruby on Rails".to_string(),
				version: None,
				tech_type: TechType::Framework,
				evidence: "X-Runtime header present (Rails)".to_string(),
			});
		}

		// X-Version (Express.js)
		if let Some(ver) = headers.get("x-version").and_then(|v| v.to_str().ok()) {
			matches.push(TechMatch {
				name: "Express.js".to_string(),
				version: Some(ver.to_string()),
				tech_type: TechType::Framework,
				evidence: format!("X-Version: {}", ver),
			});
		}

		// CF-RAY (Cloudflare)
		if headers.contains_key("cf-ray") {
			matches.push(TechMatch {
				name: "Cloudflare".to_string(),
				version: None,
				tech_type: TechType::Other,
				evidence: "CF-RAY header present".to_string(),
			});
		}

		// X-Cache / X-Cache-Hits (Varnish, Nginx cache)
		if let Some(cache) = headers.get("x-cache").and_then(|v| v.to_str().ok()) {
			let cache_str = cache.to_string();
			if cache_str.to_lowercase().contains("varnish") {
				matches.push(TechMatch {
					name: "Varnish".to_string(),
					version: None,
					tech_type: TechType::Other,
					evidence: format!("X-Cache: {}", cache),
				});
			}
		}

		// Set-Cookie framework detection
		for (name, value) in headers.iter() {
			if name.as_str() == "set-cookie" {
				let cookie_str = value.to_str().unwrap_or("");
				if cookie_str.contains("PHPSESSID") {
					matches.push(TechMatch {
						name: "PHP".to_string(),
						version: None,
						tech_type: TechType::Language,
						evidence: "PHPSESSID cookie detected".to_string(),
					});
				} else if cookie_str.contains("JSESSIONID") {
					matches.push(TechMatch {
						name: "Java".to_string(),
						version: None,
						tech_type: TechType::Language,
						evidence: "JSESSIONID cookie detected".to_string(),
					});
				} else if cookie_str.contains("ASP.NET_SessionId") {
					matches.push(TechMatch {
						name: "ASP.NET".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "ASP.NET_SessionId cookie detected".to_string(),
					});
				} else if cookie_str.contains("_rails_session") || cookie_str.contains("_session_id") {
					matches.push(TechMatch {
						name: "Ruby on Rails".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "Rails session cookie detected".to_string(),
					});
				} else if cookie_str.contains("laravel_session") {
					matches.push(TechMatch {
						name: "Laravel".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "Laravel session cookie detected".to_string(),
					});
				} else if cookie_str.contains("connect.sid") {
					matches.push(TechMatch {
						name: "Express.js".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "Express connect.sid cookie detected".to_string(),
					});
				} else if cookie_str.contains("csrftoken") || cookie_str.contains("csrfmiddlewaretoken") {
					matches.push(TechMatch {
						name: "Django".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "Django CSRF cookie detected".to_string(),
					});
				} else if cookie_str.contains("XSRF-TOKEN") {
					matches.push(TechMatch {
						name: "Laravel/Angular".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "XSRF-TOKEN cookie detected".to_string(),
					});
				} else if cookie_str.contains("_gitlab_session") {
					matches.push(TechMatch {
						name: "GitLab".to_string(),
						version: None,
						tech_type: TechType::Framework,
						evidence: "GitLab session cookie detected".to_string(),
					});
				}
			}
		}

		matches
	}

	/// Detect technologies from HTML body
	fn detect_from_body(body: &str) -> Vec<TechMatch> {
		let mut matches = Vec::new();
		let body_lower = body.to_lowercase();

		// WordPress
		if body_lower.contains("wp-content") || body_lower.contains("wp-includes") {
			matches.push(TechMatch {
				name: "WordPress".to_string(),
				version: extract_version_from_meta(body, "generator"),
				tech_type: TechType::CMS,
				evidence: "wp-content/wp-includes references found".to_string(),
			});
		}

		// Drupal
		if body_lower.contains("drupal.js") || body_lower.contains("drupal.css") {
			matches.push(TechMatch {
				name: "Drupal".to_string(),
				version: extract_version_from_meta(body, "generator"),
				tech_type: TechType::CMS,
				evidence: "Drupal JS/CSS references found".to_string(),
			});
		}

		// Joomla
		if body_lower.contains("/media/jui/") || body_lower.contains("joomla") {
			matches.push(TechMatch {
				name: "Joomla".to_string(),
				version: None,
				tech_type: TechType::CMS,
				evidence: "Joomla media references found".to_string(),
			});
		}

		// React
		if body_lower.contains("react") || body_lower.contains("__next") || body_lower.contains("_next/static") {
			matches.push(TechMatch {
				name: "React/Next.js".to_string(),
				version: None,
				tech_type: TechType::JavaScript,
				evidence: "React/Next.js references found".to_string(),
			});
		}

		// Vue.js
		if body_lower.contains("vue.js") || body_lower.contains("vue.min.js") || body.contains("data-v-") {
			matches.push(TechMatch {
				name: "Vue.js".to_string(),
				version: None,
				tech_type: TechType::JavaScript,
				evidence: "Vue.js references found".to_string(),
			});
		}

		// Angular
		if body_lower.contains("angular") || body.contains("ng-version") || body.contains("ng-app") {
			matches.push(TechMatch {
				name: "Angular".to_string(),
				version: extract_ng_version(body),
				tech_type: TechType::JavaScript,
				evidence: "Angular references found".to_string(),
			});
		}

		// jQuery
		if let Some(version) = extract_jquery_version(body) {
			matches.push(TechMatch {
				name: "jQuery".to_string(),
				version: Some(version),
				tech_type: TechType::JavaScript,
				evidence: "jQuery script tag found".to_string(),
			});
		}

		// Bootstrap
		if body_lower.contains("bootstrap.min.js") || body_lower.contains("bootstrap.min.css") {
			matches.push(TechMatch {
				name: "Bootstrap".to_string(),
				version: extract_bootstrap_version(body),
				tech_type: TechType::CSS,
				evidence: "Bootstrap references found".to_string(),
			});
		}

		// Tailwind CSS
		if body_lower.contains("tailwind") || body.contains("tw-") {
			matches.push(TechMatch {
				name: "Tailwind CSS".to_string(),
				version: None,
				tech_type: TechType::CSS,
				evidence: "Tailwind CSS references found".to_string(),
			});
		}

		// Google Analytics
		if body_lower.contains("google-analytics.com") || body_lower.contains("googletagmanager.com") || body_lower.contains("gtag(") {
			matches.push(TechMatch {
				name: "Google Analytics".to_string(),
				version: None,
				tech_type: TechType::Analytics,
				evidence: "Google Analytics references found".to_string(),
			});
		}

		// Matomo/Piwik
		if body_lower.contains("matomo") || body_lower.contains("piwik") {
			matches.push(TechMatch {
				name: "Matomo".to_string(),
				version: None,
				tech_type: TechType::Analytics,
				evidence: "Matomo/Piwik references found".to_string(),
			});
		}

		// Meta generator tag
		if let Some(generator) = extract_meta_generator(body) {
			let tech_type = if generator.to_lowercase().contains("wordpress") {
				TechType::CMS
			} else if generator.to_lowercase().contains("drupal") {
				TechType::CMS
			} else if generator.to_lowercase().contains("joomla") {
				TechType::CMS
			} else {
				TechType::Other
			};
			matches.push(TechMatch {
				name: generator,
				version: None,
				tech_type,
				evidence: "Meta generator tag found".to_string(),
			});
		}

		// Laravel Blade
		if body.contains("csrf-token") && body_lower.contains("laravel") {
			matches.push(TechMatch {
				name: "Laravel".to_string(),
				version: None,
				tech_type: TechType::Framework,
				evidence: "Laravel CSRF meta tag found".to_string(),
			});
		}

		// Django
		if body.contains("csrfmiddlewaretoken") {
			matches.push(TechMatch {
				name: "Django".to_string(),
				version: None,
				tech_type: TechType::Framework,
				evidence: "Django CSRF token found".to_string(),
			});
		}

		// Ruby on Rails
		if body.contains("csrf-token") && body.contains("rails") {
			matches.push(TechMatch {
				name: "Ruby on Rails".to_string(),
				version: None,
				tech_type: TechType::Framework,
				evidence: "Rails CSRF meta tag found".to_string(),
			});
		}

		matches
	}

	/// Convert tech matches to findings
	fn to_findings(&self, matches: Vec<TechMatch>, target: &str) -> Vec<Finding> {
		let mut findings = Vec::new();

		for tech in matches {
			let title = match &tech.version {
				Some(v) => format!("{} {} detected", tech.name, v),
				None => format!("{} detected", tech.name),
			};

			let description = format!(
				"{} technology ({}) detected on target. {}",
				tech.tech_type,
				tech.name,
				tech.evidence
			);

			let mut finding = Finding::new(
				VulnerabilityType::TechFingerprint,
				Severity::Info,
				Confidence::Confirmed,
				title,
				target.to_string(),
				"tech-fingerprint".to_string(),
			);
			finding.description = description;
			finding.evidence = Evidence {
				request: None,
				response: Some(tech.evidence),
				payload: None,
				pattern: Some(tech.name),
				context: Some(tech.tech_type.to_string()),
			};
			finding.remediation =
				"Review technology stack for known vulnerabilities and ensure all components are up to date"
					.to_string();

			findings.push(finding);
		}

		findings
	}
}

/// Parse server header to extract name and version
fn parse_server_version(server: &str) -> (String, Option<String>) {
	let parts: Vec<&str> = server.splitn(2, '/').collect();
	let name = parts[0].trim().to_string();
	let version = parts.get(1).map(|v| v.trim().to_string());
	(name, version)
}

/// Parse X-Powered-By header
fn parse_powered_by(value: &str) -> (String, Option<String>) {
	let parts: Vec<&str> = value.splitn(2, '/').collect();
	let name = parts[0].trim().to_string();
	let version = parts.get(1).map(|v| v.trim().to_string());
	(name, version)
}

/// Extract version from meta generator tag
fn extract_version_from_meta(body: &str, tag: &str) -> Option<String> {
	let pattern = format!("content=\"{}[^\"]*?([\\d.]+)\"", tag);
	let re = regex::Regex::new(&pattern).ok()?;
	re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Extract ng-version from Angular
fn extract_ng_version(body: &str) -> Option<String> {
	let re = regex::Regex::new(r#"ng-version="([^"]+)""#).ok()?;
	re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Extract jQuery version from script tags
fn extract_jquery_version(body: &str) -> Option<String> {
	let re = regex::Regex::new(r#"jquery[.-](\d+\.\d+\.\d+)"#).ok()?;
	re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Extract Bootstrap version
fn extract_bootstrap_version(body: &str) -> Option<String> {
	let re = regex::Regex::new(r#"bootstrap[.-](\d+\.\d+\.\d+)"#).ok()?;
	re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Extract meta generator content
fn extract_meta_generator(body: &str) -> Option<String> {
	let re = regex::Regex::new(r#"<meta[^>]*name="generator"[^>]*content="([^"]+)""#).ok()?;
	re.captures(body)
		.and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

#[async_trait]
impl Scanner for TechFingerprintScanner {
	fn scanner_type(&self) -> ScannerType {
		ScannerType::TechFingerprint
	}

	async fn scan(
		&self,
		target: &str,
		config: &JackSparrowConfig,
		context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		// Build client with auth headers
		let mut headers = reqwest::header::HeaderMap::new();
		for (key, value) in &context.headers {
			if let (Ok(name), Ok(val)) = (
				reqwest::header::HeaderName::from_bytes(key.as_bytes()),
				reqwest::header::HeaderValue::from_str(value),
			) {
				headers.insert(name, val);
			}
		}
		if let Some(ref cookies) = context.cookies {
			if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
				headers.insert(reqwest::header::COOKIE, val);
			}
		}

		let client = Client::builder()
			.default_headers(headers)
			.user_agent(&config.general.user_agent)
			.build()
			.map_err(|e| JackSparrowError::ToolExecutionFailed {
				tool: "tech-fingerprint".to_string(),
				message: e.to_string(),
			})?;

		// Send request
		let response = client.get(target).send().await.map_err(|e| {
			JackSparrowError::ToolExecutionFailed {
				tool: "tech-fingerprint".to_string(),
				message: e.to_string(),
			}
		})?;

		let response_headers = response.headers().clone();
		let body = response.text().await.unwrap_or_default();

		// Detect from headers
		let header_matches = Self::detect_from_headers(&response_headers);

		// Detect from body
		let body_matches = Self::detect_from_body(&body);

		// Combine and deduplicate
		let mut all_matches = header_matches;
		all_matches.extend(body_matches);

		// Convert to findings
		let findings = self.to_findings(all_matches, target);

		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_server_version() {
		let (name, version) = parse_server_version("Apache/2.4.41");
		assert_eq!(name, "Apache");
		assert_eq!(version, Some("2.4.41".to_string()));
	}

	#[test]
	fn test_parse_server_no_version() {
		let (name, version) = parse_server_version("nginx");
		assert_eq!(name, "nginx");
		assert!(version.is_none());
	}

	#[test]
	fn test_parse_powered_by() {
		let (name, version) = parse_powered_by("PHP/7.4.3");
		assert_eq!(name, "PHP");
		assert_eq!(version, Some("7.4.3".to_string()));
	}

	#[test]
	fn test_detect_jquery_version() {
		let body = r#"<script src="jquery-3.6.0.min.js"></script>"#;
		let version = extract_jquery_version(body);
		assert_eq!(version, Some("3.6.0".to_string()));
	}

	#[test]
	fn test_detect_angular_version() {
		let body = r#"<app-root ng-version="13.0.0"></app-root>"#;
		let version = extract_ng_version(body);
		assert_eq!(version, Some("13.0.0".to_string()));
	}

	#[test]
	fn test_detect_bootstrap_version() {
		let body = r#"<link rel="stylesheet" href="bootstrap-5.1.0.min.css">"#;
		let version = extract_bootstrap_version(body);
		assert_eq!(version, Some("5.1.0".to_string()));
	}

	#[test]
	fn test_detect_wordpress_from_body() {
		let body = r#"<link href="wp-content/themes/flavor/style.css" rel="stylesheet">"#;
		let matches = TechFingerprintScanner::detect_from_body(body);
		assert!(matches.iter().any(|m| m.name == "WordPress"));
	}

	#[test]
	fn test_detect_react_from_body() {
		let body = r#"<div id="__next"></div><script src="_next/static/chunks/main.js"></script>"#;
		let matches = TechFingerprintScanner::detect_from_body(body);
		assert!(matches.iter().any(|m| m.name == "React/Next.js"));
	}

	#[test]
	fn test_detect_vue_from_body() {
		let body = r#"<div data-v-abc123></div><script src="vue.min.js"></script>"#;
		let matches = TechFingerprintScanner::detect_from_body(body);
		assert!(matches.iter().any(|m| m.name == "Vue.js"));
	}
}

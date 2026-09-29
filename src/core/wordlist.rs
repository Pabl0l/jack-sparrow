#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::shared::error::JackSparrowError;

// CLI integration flags (wire into clap args):
//   --wordlist-subdomain <path>
//   --wordlist-path <path>
//   --wordlist-param <path>
//   --wordlist-password <path>

#[derive(Debug, Clone)]
pub struct WordlistConfig {
	pub subdomain_wordlist: Option<PathBuf>,
	pub path_wordlist: Option<PathBuf>,
	pub param_wordlist: Option<PathBuf>,
	pub password_wordlist: Option<PathBuf>,
}

pub struct WordlistManager {
	config: WordlistConfig,
	cache: HashMap<String, Vec<String>>,
}

impl WordlistManager {
	pub fn new(config: WordlistConfig) -> Self {
		Self {
			config,
			cache: HashMap::new(),
		}
	}

	pub fn load_wordlist(&mut self, path: &Path) -> Result<Vec<String>, JackSparrowError> {
		let key = path.to_string_lossy().to_string();
		if let Some(cached) = self.cache.get(&key) {
			return Ok(cached.clone());
		}
		let content = fs::read_to_string(path).map_err(|e| JackSparrowError::ConfigError {
			message: format!("Failed to read wordlist '{}': {}", path.display(), e),
		})?;
		let entries: Vec<String> = content
			.lines()
			.map(|l| l.trim().to_string())
			.filter(|l| !l.is_empty() && !l.starts_with('#'))
			.collect();
		self.cache.insert(key, entries.clone());
		Ok(entries)
	}

	pub fn subdomain_wordlist(&mut self) -> Result<Vec<String>, JackSparrowError> {
		let custom = match self.config.subdomain_wordlist.clone() {
			Some(p) => self.load_wordlist(&p)?,
			None => vec![],
		};
		Ok(Self::merge_with_defaults(custom, &DEFAULT_SUBDOMAINS))
	}

	pub fn path_wordlist(&mut self) -> Result<Vec<String>, JackSparrowError> {
		let custom = match self.config.path_wordlist.clone() {
			Some(p) => self.load_wordlist(&p)?,
			None => vec![],
		};
		Ok(Self::merge_with_defaults(custom, &DEFAULT_PATHS))
	}

	pub fn param_wordlist(&mut self) -> Result<Vec<String>, JackSparrowError> {
		let custom = match self.config.param_wordlist.clone() {
			Some(p) => self.load_wordlist(&p)?,
			None => vec![],
		};
		Ok(Self::merge_with_defaults(custom, &DEFAULT_PARAMS))
	}

	pub fn password_wordlist(&mut self) -> Result<Vec<String>, JackSparrowError> {
		match self.config.password_wordlist.clone() {
			Some(p) => self.load_wordlist(&p),
			None => Ok(vec![]),
		}
	}

	fn merge_with_defaults(custom: Vec<String>, defaults: &[&str]) -> Vec<String> {
		let mut merged: Vec<String> = custom;
		for d in defaults {
			let entry = d.to_string();
			if !merged.contains(&entry) {
				merged.push(entry);
			}
		}
		merged
	}

	pub fn validate(&self) -> Vec<String> {
		let mut errors = Vec::new();
		let paths: Vec<(&str, &Option<PathBuf>)> = vec![
			("subdomain", &self.config.subdomain_wordlist),
			("path", &self.config.path_wordlist),
			("param", &self.config.param_wordlist),
			("password", &self.config.password_wordlist),
		];
		for (label, opt) in paths {
			if let Some(p) = opt {
				if !p.exists() {
					errors.push(format!("{} wordlist not found: {}", label, p.display()));
				} else if fs::read_to_string(p).is_err() {
					errors.push(format!("{} wordlist not readable: {}", label, p.display()));
				}
			}
		}
		errors
	}
}

const DEFAULT_SUBDOMAINS: &[&str] = &[
	"www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "portal", "webmail",
	"smtp", "pop", "ns1", "ns2", "dns", "vpn", "blog", "shop", "store", "app",
	"beta", "demo", "cdn", "media", "static", "img", "images", "downloads", "files", "docs",
	"wiki", "help", "support", "status", "monitor", "grafana", "kibana", "jenkins", "ci", "git",
	"gitlab", "bitbucket", "jira", "confluence", "proxy", "gateway", "edge", "internal", "intranet", "hr",
];

const DEFAULT_PATHS: &[&str] = &[
	"/admin", "/login", "/api", "/backup", "/.env", "/config", "/debug", "/console",
	"/dashboard", "/panel", "/portal", "/wp-admin", "/wp-login.php", "/xmlrpc.php",
	"/robots.txt", "/sitemap.xml", "/.git", "/.git/config", "/phpinfo.php", "/info.php",
	"/server-status", "/server-info", "/.htaccess", "/.htpasswd", "/cgi-bin", "/shell",
	"/uploads", "/images", "/assets", "/tmp", "/old", "/new", "/temp", "/test",
	"/db", "/database", "/sql", "/phpmyadmin", "/adminer", "/setup", "/install",
	"/register", "/signup", "/forgot", "/reset", "/profile", "/account",
];

const DEFAULT_PARAMS: &[&str] = &[
	"id", "user", "token", "key", "search", "q", "query", "page", "limit", "offset",
	"sort", "order", "filter", "type", "format", "callback", "redirect", "url", "next",
	"file", "path", "dir", "action", "cmd", "command", "exec", "code", "debug", "test",
	"name",
];

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn temp_path(name: &str) -> PathBuf {
		let mut p = std::env::temp_dir();
		p.push(format!("jack_sparrow_wl_test_{}", name));
		p
	}

	#[test]
	fn test_new_wordlist_manager() {
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mgr = WordlistManager::new(cfg);
		assert!(mgr.cache.is_empty());
	}

	#[test]
	fn test_load_wordlist_valid() {
		let path = temp_path("valid.txt");
		fs::write(&path, "alpha\nbeta\n# comment\n\ngamma\n").unwrap();
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let result = mgr.load_wordlist(&path).unwrap();
		assert_eq!(result, vec!["alpha", "beta", "gamma"]);
		let _ = fs::remove_file(&path);
	}

	#[test]
	fn test_load_wordlist_missing() {
		let path = temp_path("nonexistent.txt");
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let result = mgr.load_wordlist(&path);
		assert!(result.is_err());
	}

	#[test]
	fn test_subdomain_defaults() {
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let wl = mgr.subdomain_wordlist().unwrap();
		assert!(wl.contains(&"www".to_string()));
		assert!(wl.contains(&"admin".to_string()));
		assert!(wl.len() >= 50);
	}

	#[test]
	fn test_path_defaults() {
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let wl = mgr.path_wordlist().unwrap();
		assert!(wl.contains(&"/admin".to_string()));
		assert!(wl.contains(&"/.env".to_string()));
		assert!(wl.len() >= 30);
	}

	#[test]
	fn test_param_defaults() {
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let wl = mgr.param_wordlist().unwrap();
		assert!(wl.contains(&"id".to_string()));
		assert!(wl.contains(&"token".to_string()));
		assert!(wl.len() >= 30);
	}

	#[test]
	fn test_merge_with_defaults() {
		let custom = vec!["custom1".to_string(), "www".to_string()];
		let merged = WordlistManager::merge_with_defaults(custom, &["www", "extra"]);
		assert_eq!(merged.len(), 3);
		assert!(merged.contains(&"custom1".to_string()));
		assert!(merged.contains(&"www".to_string()));
		assert!(merged.contains(&"extra".to_string()));
	}

	#[test]
	fn test_validate_all_valid() {
		let path = temp_path("valid_wl.txt");
		fs::write(&path, "a\nb\n").unwrap();
		let cfg = WordlistConfig {
			subdomain_wordlist: Some(path.clone()),
			path_wordlist: Some(path.clone()),
			param_wordlist: Some(path.clone()),
			password_wordlist: Some(path.clone()),
		};
		let mgr = WordlistManager::new(cfg);
		let errors = mgr.validate();
		assert!(errors.is_empty());
		let _ = fs::remove_file(&path);
	}

	#[test]
	fn test_validate_missing_file() {
		let missing = temp_path("missing_wl.txt");
		let cfg = WordlistConfig {
			subdomain_wordlist: Some(missing.clone()),
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mgr = WordlistManager::new(cfg);
		let errors = mgr.validate();
		assert_eq!(errors.len(), 1);
		assert!(errors[0].contains("not found"));
	}

	#[test]
	fn test_cache_works() {
		let path = temp_path("cached_wl.txt");
		fs::write(&path, "x\ny\n").unwrap();
		let cfg = WordlistConfig {
			subdomain_wordlist: None,
			path_wordlist: None,
			param_wordlist: None,
			password_wordlist: None,
		};
		let mut mgr = WordlistManager::new(cfg);
		let first = mgr.load_wordlist(&path).unwrap();
		let second = mgr.load_wordlist(&path).unwrap();
		assert_eq!(first, second);
		assert!(mgr.cache.contains_key(&path.to_string_lossy().to_string()));
		let _ = fs::remove_file(&path);
	}
}

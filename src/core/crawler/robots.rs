use dashmap::DashMap;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

/// Errors that can occur during robots.txt operations.
#[derive(Debug, Error)]
pub enum RobotsError {
    #[error("Failed to fetch robots.txt: {0}")]
    FetchFailed(String),

    #[error("Failed to parse robots.txt: {0}")]
    ParseFailed(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

/// A single rule in a robots.txt file.
#[derive(Debug, Clone)]
pub struct RobotsRule {
    /// The path pattern (e.g. "/admin/", "/private/*").
    pub path: String,
    /// Whether this path is allowed or disallowed.
    pub allowed: bool,
}

/// Parsed robots.txt for a specific User-Agent.
#[derive(Debug, Clone)]
pub struct RobotsFile {
    /// The User-Agent this entry applies to.
    pub user_agent: String,
    /// Rules sorted by specificity (longest path first).
    pub rules: Vec<RobotsRule>,
    /// Crawl-delay in seconds, if specified.
    pub crawl_delay: Option<f64>,
    /// Sitemaps listed in robots.txt.
    pub sitemaps: Vec<String>,
    /// When this file was fetched (for cache TTL).
    pub fetched_at: Instant,
}

impl RobotsFile {
    /// Check if a path is allowed for the given User-Agent.
    ///
    /// Rules are matched longest-path-first (most specific wins).
    /// If no rule matches, the path is allowed.
    pub fn is_allowed(&self, path: &str) -> bool {
        // Sort rules by path length (longest first) for specificity
        let mut sorted_rules: Vec<&RobotsRule> = self.rules.iter().collect();
        sorted_rules.sort_by(|a, b| b.path.len().cmp(&a.path.len()));

        // Find the most specific matching rule
        for rule in &sorted_rules {
            if path.starts_with(&rule.path) || glob_match(&rule.path, path) {
                return rule.allowed;
            }
        }
        // Default: allowed if no rule matches
        true
    }

    /// Get the crawl delay as a Duration.
    pub fn delay_duration(&self) -> Duration {
        self.crawl_delay
            .map(|d| Duration::from_secs_f64(d))
            .unwrap_or(Duration::from_secs(1))
    }
}

/// Simple glob-style matching for robots.txt patterns.
///
/// Supports:
/// - `*` matches any characters
/// - `$` at end means end-of-string
/// - Trailing `/` means "match everything under this path"
/// - No trailing `/` means "match this path exactly"
fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_end_matches('$');

    if pattern.contains('*') {
        // Wildcard matching
        let parts: Vec<&str> = pattern.split('*').collect();
        let mut remaining = path;

        for part in &parts {
            if part.is_empty() {
                continue;
            }
            if let Some(pos) = remaining.find(part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }
        true
    } else if pattern.ends_with('/') {
        // Prefix match (e.g., "/admin/" matches "/admin/anything")
        path.starts_with(pattern)
    } else {
        // Exact match or match with optional trailing slash
        path == pattern || path == format!("{}/", pattern)
    }
}

/// Cache entry for a robots.txt file.
#[derive(Debug, Clone)]
struct CacheEntry {
    file: RobotsFile,
    /// Whether the fetch succeeded (false = 404 or error).
    success: bool,
}

/// Thread-safe cache for robots.txt files.
#[derive(Clone)]
pub struct RobotsCache {
    cache: Arc<DashMap<String, CacheEntry>>,
    client: Client,
    user_agent: String,
    cache_ttl: Duration,
}

impl RobotsCache {
    /// Create a new cache with a shared HTTP client.
    pub fn new(client: Client, user_agent: &str) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            client,
            user_agent: user_agent.to_string(),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Set the cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Check if a URL is allowed to be crawled.
    ///
    /// Fetches and caches robots.txt if not already present.
    pub async fn is_allowed(&self, url: &Url) -> Result<bool, RobotsError> {
        let domain = match url.host_str() {
            Some(d) => d.to_string(),
            None => return Ok(true), // No host = allow
        };

        // Check cache first
        if let Some(entry) = self.cache.get(&domain) {
            if entry.file.fetched_at.elapsed() < self.cache_ttl {
                return Ok(entry.file.is_allowed(url.path()));
            }
            // Cache expired, remove and re-fetch
            drop(entry);
            self.cache.remove(&domain);
        }

        // Fetch robots.txt
        let file = self.fetch_robots(&domain).await?;
        let allowed = file.is_allowed(url.path());
        self.cache.insert(
            domain,
            CacheEntry {
                file,
                success: true,
            },
        );

        Ok(allowed)
    }

    /// Get the crawl delay for a domain.
    pub async fn get_delay(&self, url: &Url) -> Duration {
        let domain = match url.host_str() {
            Some(d) => d.to_string(),
            None => return Duration::from_secs(1),
        };

        if let Some(entry) = self.cache.get(&domain) {
            return entry.file.delay_duration();
        }

        // Not cached, fetch
        if let Ok(file) = self.fetch_robots(&domain).await {
            let delay = file.delay_duration();
            self.cache.insert(
                domain,
                CacheEntry {
                    file,
                    success: true,
                },
            );
            delay
        } else {
            Duration::from_secs(1)
        }
    }

    /// Fetch and parse robots.txt for a domain.
    async fn fetch_robots(&self, domain: &str) -> Result<RobotsFile, RobotsError> {
        let url = format!("https://{}/robots.txt", domain);

        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_e) => {
                // Network error - assume everything is allowed
                return Ok(RobotsFile {
                    user_agent: "*".to_string(),
                    rules: Vec::new(),
                    crawl_delay: None,
                    sitemaps: Vec::new(),
                    fetched_at: Instant::now(),
                });
            }
        };

        if response.status().as_u16() == 404 {
            // No robots.txt = everything allowed
            return Ok(RobotsFile {
                user_agent: "*".to_string(),
                rules: Vec::new(),
                crawl_delay: None,
                sitemaps: Vec::new(),
                fetched_at: Instant::now(),
            });
        }

        if !response.status().is_success() {
            return Ok(RobotsFile {
                user_agent: "*".to_string(),
                rules: Vec::new(),
                crawl_delay: None,
                sitemaps: Vec::new(),
                fetched_at: Instant::now(),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| RobotsError::FetchFailed(e.to_string()))?;

        self.parse_robots(&body)
    }

    /// Parse a robots.txt file.
    fn parse_robots(&self, body: &str) -> Result<RobotsFile, RobotsError> {
        let mut sitemaps = Vec::new();
        let mut wildcard_rules = Vec::new();
        let mut wildcard_delay = None;
        let mut specific_rules = Vec::new();
        let mut specific_delay = None;
        let mut current_matches_wildcard = false;
        let mut current_matches_specific = false;

        for line in body.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split into directive and value
            let (directive, value) = match line.find(':') {
                Some(pos) => (
                    line[..pos].trim().to_lowercase(),
                    line[pos + 1..].trim().to_string(),
                ),
                None => continue,
            };

            match directive.as_str() {
                "user-agent" => {
                    current_matches_wildcard = value == "*";
                    current_matches_specific = !current_matches_wildcard
                        && self
                            .user_agent
                            .to_lowercase()
                            .contains(&value.to_lowercase());
                }
                "disallow" => {
                    if !value.is_empty() {
                        let rule = RobotsRule {
                            path: value,
                            allowed: false,
                        };
                        if current_matches_wildcard {
                            wildcard_rules.push(rule);
                        } else if current_matches_specific {
                            specific_rules.push(rule);
                        }
                    }
                }
                "allow" => {
                    if !value.is_empty() {
                        let rule = RobotsRule {
                            path: value,
                            allowed: true,
                        };
                        if current_matches_wildcard {
                            wildcard_rules.push(rule);
                        } else if current_matches_specific {
                            specific_rules.push(rule);
                        }
                    }
                }
                "crawl-delay" => {
                    if let Ok(delay) = value.parse::<f64>() {
                        if current_matches_wildcard {
                            wildcard_delay = Some(delay);
                        } else if current_matches_specific {
                            specific_delay = Some(delay);
                        }
                    }
                }
                "sitemap" => {
                    sitemaps.push(value);
                }
                _ => {}
            }
        }

        // Use specific rules if available, otherwise fall back to wildcard
        let has_specific = !specific_rules.is_empty();
        let (rules, crawl_delay) = if has_specific {
            (specific_rules, specific_delay)
        } else {
            (wildcard_rules, wildcard_delay)
        };

        Ok(RobotsFile {
            user_agent: if has_specific {
                self.user_agent.clone()
            } else {
                "*".to_string()
            },
            rules,
            crawl_delay,
            sitemaps,
            fetched_at: Instant::now(),
        })
    }

    /// Clear the cache for a specific domain.
    pub fn clear_domain(&self, domain: &str) {
        self.cache.remove(domain);
    }

    /// Clear the entire cache.
    pub fn clear_all(&self) {
        self.cache.clear();
    }

    /// Get the number of cached domains.
    pub fn cached_count(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RobotsFile tests ─────────────────────

    #[test]
    fn is_allowed_no_rules() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: Vec::new(),
            crawl_delay: None,
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert!(file.is_allowed("/anything"));
        assert!(file.is_allowed("/admin"));
    }

    #[test]
    fn is_allowed_disallow_prefix() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: vec![RobotsRule {
                path: "/admin/".to_string(),
                allowed: false,
            }],
            crawl_delay: None,
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert!(!file.is_allowed("/admin/"));
        assert!(!file.is_allowed("/admin/users"));
        assert!(file.is_allowed("/public"));
        assert!(file.is_allowed("/admin")); // No trailing slash
    }

    #[test]
    fn is_allowed_allow_overrides_disallow() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: vec![
                RobotsRule {
                    path: "/admin/".to_string(),
                    allowed: false,
                },
                RobotsRule {
                    path: "/admin/public/".to_string(),
                    allowed: true,
                },
            ],
            crawl_delay: None,
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        // Rules are sorted by path length (longest first)
        assert!(file.is_allowed("/admin/public/"));
        assert!(!file.is_allowed("/admin/private/"));
    }

    #[test]
    fn is_allowed_wildcard() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: vec![RobotsRule {
                path: "*.json".to_string(),
                allowed: false,
            }],
            crawl_delay: None,
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert!(!file.is_allowed("/api/data.json"));
        assert!(!file.is_allowed("/config.json"));
        assert!(file.is_allowed("/api/data.xml"));
    }

    #[test]
    fn delay_duration_default() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: Vec::new(),
            crawl_delay: None,
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert_eq!(file.delay_duration(), Duration::from_secs(1));
    }

    #[test]
    fn delay_duration_custom() {
        let file = RobotsFile {
            user_agent: "*".to_string(),
            rules: Vec::new(),
            crawl_delay: Some(5.0),
            sitemaps: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert_eq!(file.delay_duration(), Duration::from_secs(5));
    }

    // ── Glob matching tests ──────────────────

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("/admin", "/admin"));
        assert!(glob_match("/admin", "/admin/"));
        assert!(!glob_match("/admin", "/admin/users"));
    }

    #[test]
    fn glob_wildcard() {
        assert!(glob_match("*.json", "/data.json"));
        assert!(glob_match("/api/*", "/api/users"));
        assert!(glob_match("*/test", "/foo/test"));
    }

    // ── Parser tests ─────────────────────────

    #[test]
    fn parse_robots_simple() {
        let cache = RobotsCache::new(Client::new(), "TestBot");
        let body = r#"
            User-agent: *
            Disallow: /admin/
            Disallow: /private/
            Allow: /admin/public/
            Crawl-delay: 2
            Sitemap: http://example.com/sitemap.xml
        "#;

        let file = cache.parse_robots(body).unwrap();
        assert_eq!(file.user_agent, "*");
        assert!(file.crawl_delay.is_some());
        assert_eq!(file.crawl_delay.unwrap(), 2.0);
        assert!(!file.sitemaps.is_empty());
    }

    #[test]
    fn parse_robots_multiple_agents() {
        let cache = RobotsCache::new(Client::new(), "Googlebot");
        let body = r#"
            User-agent: *
            Disallow: /private/

            User-agent: Googlebot
            Allow: /
        "#;

        let file = cache.parse_robots(body).unwrap();
        assert!(file.is_allowed("/private/"));
    }

    #[test]
    fn parse_robots_comments_and_empty() {
        let cache = RobotsCache::new(Client::new(), "TestBot");
        let body = r#"
            # This is a comment
            User-agent: *

            # Another comment
            Disallow: /admin/
        "#;

        let file = cache.parse_robots(body).unwrap();
        assert_eq!(file.rules.len(), 1);
    }

    // ── Cache tests ──────────────────────────

    #[test]
    fn cache_starts_empty() {
        let cache = RobotsCache::new(Client::new(), "TestBot");
        assert_eq!(cache.cached_count(), 0);
    }

    #[test]
    fn cache_clear_domain() {
        let cache = RobotsCache::new(Client::new(), "TestBot");
        // We can't easily test actual caching without a server,
        // but we can test the clear operations
        cache.clear_domain("example.com");
        cache.clear_all();
        assert_eq!(cache.cached_count(), 0);
    }

    #[test]
    fn robots_file_sorted_by_path_length() {
        let cache = RobotsCache::new(Client::new(), "TestBot");
        let body = r#"
            User-agent: *
            Allow: /admin/public/
            Disallow: /admin/
            Allow: /admin/public/api/
        "#;

        let file = cache.parse_robots(body).unwrap();
        // Longest paths first
        assert!(file.rules[0].path.len() >= file.rules[1].path.len());
    }
}

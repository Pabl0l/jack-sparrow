use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the crawler engine.
///
/// Controls depth, concurrency, rate limiting, scope, and politeness.
/// All fields have sensible defaults via `CrawlerConfig::default()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerConfig {
    /// Maximum crawl depth from seed URL (0 = seed only, 3 = default).
    pub max_depth: u32,

    /// Maximum number of pages to crawl (0 = unlimited).
    pub max_pages: usize,

    /// Number of concurrent fetch workers.
    pub max_concurrent: usize,

    /// Minimum delay between requests to the same domain (in milliseconds).
    pub delay_ms: u64,

    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,

    /// User-Agent header sent with every request.
    pub user_agent: String,

    /// Whether to fetch and respect robots.txt rules.
    pub respect_robots: bool,

    /// URL schemes to follow (e.g. "http", "https").
    pub allowed_schemes: Vec<String>,

    /// Scope rules that control which URLs are in-scope.
    pub scope: CrawlScope,
}

/// Scope rules for the crawler.
///
/// Determines which discovered URLs should be followed and which should be skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlScope {
    /// Only crawl URLs on the same domain as the seed.
    pub same_domain_only: bool,

    /// URL path patterns to include (glob-style, e.g. "/api/*").
    pub include_patterns: Vec<String>,

    /// URL path patterns to exclude (e.g. "/logout", "*.pdf").
    pub exclude_patterns: Vec<String>,

    /// Maximum page body size in bytes (default: 10 MB).
    pub max_page_size: usize,

    /// Maximum number of redirect hops to follow.
    pub max_redirects: u32,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            max_concurrent: 10,
            delay_ms: 1000,
            timeout_secs: 30,
            user_agent: "JackSparrow/0.2.0".to_string(),
            respect_robots: true,
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            scope: CrawlScope::default(),
        }
    }
}

impl Default for CrawlScope {
    fn default() -> Self {
        Self {
            same_domain_only: true,
            include_patterns: Vec::new(),
            exclude_patterns: vec![
                "/logout".to_string(),
                "/signout".to_string(),
                "*.pdf".to_string(),
                "*.zip".to_string(),
                "*.tar.gz".to_string(),
                "*.mp4".to_string(),
                "*.mp3".to_string(),
                "*.avi".to_string(),
            ],
            max_page_size: 10 * 1024 * 1024, // 10 MB
            max_redirects: 10,
        }
    }
}

impl CrawlerConfig {
    /// Create a config targeting a specific URL with default settings.
    pub fn for_target(_target: &str) -> Self {
        Self::default()
    }

    /// Builder: set max crawl depth.
    pub fn with_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Builder: set max pages.
    pub fn with_max_pages(mut self, max: usize) -> Self {
        self.max_pages = max;
        self
    }

    /// Builder: set concurrency.
    pub fn with_concurrency(mut self, workers: usize) -> Self {
        self.max_concurrent = workers;
        self
    }

    /// Builder: set per-domain delay in milliseconds.
    pub fn with_delay_ms(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// Builder: set request timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Builder: set custom user agent.
    pub fn with_user_agent(mut self, agent: &str) -> Self {
        self.user_agent = agent.to_string();
        self
    }

    /// Builder: enable/disable robots.txt respect.
    pub fn with_respect_robots(mut self, respect: bool) -> Self {
        self.respect_robots = respect;
        self
    }

    /// Builder: set same-domain-only scope.
    pub fn with_same_domain_only(mut self, same: bool) -> Self {
        self.scope.same_domain_only = same;
        self
    }

    /// Builder: add an include pattern.
    pub fn with_include_pattern(mut self, pattern: &str) -> Self {
        self.scope.include_patterns.push(pattern.to_string());
        self
    }

    /// Builder: add an exclude pattern.
    pub fn with_exclude_pattern(mut self, pattern: &str) -> Self {
        self.scope.exclude_patterns.push(pattern.to_string());
        self
    }

    /// Get the request timeout as a Duration.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Get the per-domain delay as a Duration.
    pub fn delay_duration(&self) -> Duration {
        Duration::from_millis(self.delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = CrawlerConfig::default();
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.max_pages, 100);
        assert_eq!(cfg.max_concurrent, 10);
        assert_eq!(cfg.delay_ms, 1000);
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.user_agent, "JackSparrow/0.2.0");
        assert!(cfg.respect_robots);
    }

    #[test]
    fn default_scope_is_restrictive() {
        let scope = CrawlScope::default();
        assert!(scope.same_domain_only);
        assert!(scope.include_patterns.is_empty());
        assert!(!scope.exclude_patterns.is_empty());
        assert_eq!(scope.max_page_size, 10 * 1024 * 1024);
        assert_eq!(scope.max_redirects, 10);
    }

    #[test]
    fn builder_chain_works() {
        let cfg = CrawlerConfig::default()
            .with_depth(5)
            .with_max_pages(500)
            .with_concurrency(20)
            .with_delay_ms(500)
            .with_timeout(60)
            .with_user_agent("TestBot/1.0")
            .with_respect_robots(false)
            .with_same_domain_only(false)
            .with_include_pattern("/api/*")
            .with_exclude_pattern("/admin/*");

        assert_eq!(cfg.max_depth, 5);
        assert_eq!(cfg.max_pages, 500);
        assert_eq!(cfg.max_concurrent, 20);
        assert_eq!(cfg.delay_ms, 500);
        assert_eq!(cfg.timeout_secs, 60);
        assert_eq!(cfg.user_agent, "TestBot/1.0");
        assert!(!cfg.respect_robots);
        assert!(!cfg.scope.same_domain_only);
        assert_eq!(cfg.scope.include_patterns, vec!["/api/*".to_string()]);
        assert!(cfg.scope.exclude_patterns.contains(&"/admin/*".to_string()));
    }

    #[test]
    fn for_target_uses_defaults() {
        let cfg = CrawlerConfig::for_target("http://example.com");
        assert_eq!(cfg.max_depth, 3);
        assert_eq!(cfg.max_pages, 100);
    }

    #[test]
    fn timeout_duration_conversion() {
        let cfg = CrawlerConfig::default().with_timeout(45);
        assert_eq!(cfg.timeout_duration(), Duration::from_secs(45));
    }

    #[test]
    fn delay_duration_conversion() {
        let cfg = CrawlerConfig::default().with_delay_ms(2500);
        assert_eq!(cfg.delay_duration(), Duration::from_millis(2500));
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = CrawlerConfig::default().with_depth(7);
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: CrawlerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_depth, 7);
        assert_eq!(deserialized.user_agent, "JackSparrow/0.2.0");
    }

    #[test]
    fn scope_exclude_defaults_include_common_static() {
        let scope = CrawlScope::default();
        assert!(scope.exclude_patterns.iter().any(|p| p.contains("pdf")));
        assert!(scope.exclude_patterns.iter().any(|p| p.contains("zip")));
        assert!(scope.exclude_patterns.iter().any(|p| p.contains("mp4")));
    }
}

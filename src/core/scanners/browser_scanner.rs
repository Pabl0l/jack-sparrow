use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration for browser-based scanning
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Run browser in headless mode (no visible window)
    pub headless: bool,
    /// Viewport width
    pub viewport_width: u32,
    /// Viewport height
    pub viewport_height: u32,
    /// Navigation timeout in milliseconds
    pub navigation_timeout_ms: u64,
    /// Wait for network idle after navigation
    pub wait_for_network_idle: bool,
    /// Custom user agent
    pub user_agent: Option<String>,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            headless: true,
            viewport_width: 1920,
            viewport_height: 1080,
            navigation_timeout_ms: 30000,
            wait_for_network_idle: true,
            user_agent: None,
        }
    }
}

impl From<&JackSparrowConfig> for BrowserConfig {
    fn from(config: &JackSparrowConfig) -> Self {
        Self {
            headless: true,
            viewport_width: 1920,
            viewport_height: 1080,
            navigation_timeout_ms: config.general.timeout_secs * 1000,
            wait_for_network_idle: true,
            user_agent: Some(config.general.user_agent.clone()),
        }
    }
}

/// Browser page wrapper with context
pub struct BrowserPage {
    /// Page URL
    pub url: String,
    /// Page HTML content
    pub html: String,
    /// Console messages collected during page load
    pub console_messages: Vec<String>,
    /// Network requests made by the page
    pub network_requests: Vec<NetworkRequest>,
    /// Cookies set by the page
    pub cookies: Vec<Cookie>,
}

/// Network request information
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Cookie information
#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
}

/// Trait for browser-based scanners
#[async_trait]
pub trait BrowserScanner: Send + Sync {
    /// Get the scanner name
    fn scanner_name(&self) -> &str;

    /// Initialize the browser
    async fn init(&self, config: &BrowserConfig) -> Result<(), JackSparrowError>;

    /// Navigate to a URL and return page content
    async fn navigate(
        &self,
        url: &str,
        context: &ScanContext,
    ) -> Result<BrowserPage, JackSparrowError>;

    /// Execute JavaScript in the page context
    async fn execute_js(&self, script: &str) -> Result<String, JackSparrowError>;

    /// Take a screenshot
    async fn screenshot(&self, path: &str) -> Result<(), JackSparrowError>;

    /// Close the browser
    async fn close(&self) -> Result<(), JackSparrowError>;
}

/// Shared browser state for multiple scanners
pub struct SharedBrowserState {
    /// Whether browser is initialized
    pub initialized: bool,
    /// Browser configuration
    pub config: BrowserConfig,
    /// Current page URL
    pub current_url: Option<String>,
}

impl SharedBrowserState {
    pub fn new(config: BrowserConfig) -> Self {
        Self {
            initialized: false,
            config,
            current_url: None,
        }
    }
}

/// Browser manager for coordinating multiple browser-based scans
pub struct BrowserManager {
    state: Arc<Mutex<SharedBrowserState>>,
}

impl BrowserManager {
    pub fn new(config: BrowserConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedBrowserState::new(config))),
        }
    }

    /// Check if browser is initialized
    pub async fn is_initialized(&self) -> bool {
        let state = self.state.lock().await;
        state.initialized
    }

    /// Get browser config
    pub async fn config(&self) -> BrowserConfig {
        let state = self.state.lock().await;
        state.config.clone()
    }

    /// Mark browser as initialized
    pub async fn mark_initialized(&self) {
        let mut state = self.state.lock().await;
        state.initialized = true;
    }

    /// Update current URL
    pub async fn set_current_url(&self, url: &str) {
        let mut state = self.state.lock().await;
        state.current_url = Some(url.to_string());
    }

    /// Get current URL
    pub async fn current_url(&self) -> Option<String> {
        let state = self.state.lock().await;
        state.current_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_config_default() {
        let config = BrowserConfig::default();
        assert!(config.headless);
        assert_eq!(config.viewport_width, 1920);
        assert_eq!(config.viewport_height, 1080);
        assert_eq!(config.navigation_timeout_ms, 30000);
        assert!(config.wait_for_network_idle);
    }

    #[test]
    fn test_browser_config_from_jack_sparrow_config() {
        let jack_config = JackSparrowConfig::default();
        let browser_config = BrowserConfig::from(&jack_config);
        assert!(browser_config.headless);
        assert_eq!(browser_config.navigation_timeout_ms, 300000);
        assert_eq!(
            browser_config.user_agent,
            Some("JackSparrow/0.2.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_browser_manager_new() {
        let config = BrowserConfig::default();
        let manager = BrowserManager::new(config);
        assert!(!manager.is_initialized().await);
        assert!(manager.current_url().await.is_none());
    }

    #[tokio::test]
    async fn test_browser_manager_initialized() {
        let config = BrowserConfig::default();
        let manager = BrowserManager::new(config);
        manager.mark_initialized().await;
        assert!(manager.is_initialized().await);
    }

    #[tokio::test]
    async fn test_browser_manager_current_url() {
        let config = BrowserConfig::default();
        let manager = BrowserManager::new(config);
        manager.set_current_url("http://example.com").await;
        assert_eq!(
            manager.current_url().await,
            Some("http://example.com".to_string())
        );
    }

    #[test]
    fn test_network_request_clone() {
        let req = NetworkRequest {
            url: "http://example.com".to_string(),
            method: "GET".to_string(),
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            body: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.url, req.url);
        assert_eq!(cloned.method, req.method);
    }

    #[test]
    fn test_cookie_clone() {
        let cookie = Cookie {
            name: "session".to_string(),
            value: "abc123".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
        };
        let cloned = cookie.clone();
        assert_eq!(cloned.name, cookie.name);
        assert_eq!(cloned.value, cookie.value);
        assert_eq!(cloned.domain, cookie.domain);
    }
}

use crate::core::scanners::browser_scanner::{
	BrowserConfig, BrowserManager, BrowserPage, BrowserScanner,
};
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use async_trait::async_trait;
use playwright_rs::{Playwright, LaunchOptions};

/// Playwright-based browser implementation
pub struct PlaywrightBrowser {
	manager: BrowserManager,
}

impl PlaywrightBrowser {
	pub fn new(config: BrowserConfig) -> Self {
		Self {
			manager: BrowserManager::new(config),
		}
	}

	/// Create a new instance with default config
	pub fn default() -> Self {
		Self::new(BrowserConfig::default())
	}
}

#[async_trait]
impl BrowserScanner for PlaywrightBrowser {
	fn scanner_name(&self) -> &str {
		"playwright"
	}

	async fn init(&self, _config: &BrowserConfig) -> Result<(), JackSparrowError> {
		// Playwright is initialized per-operation via Playwright::launch()
		Ok(())
	}

	async fn navigate(
		&self,
		url: &str,
		_context: &ScanContext,
	) -> Result<BrowserPage, JackSparrowError> {
		// Launch Playwright
		let playwright = Playwright::launch().await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to launch Playwright: {}", e))
		})?;

		// Launch browser
		let config = self.manager.config().await;
		let opts = LaunchOptions::default().headless(config.headless);
		let browser = playwright
			.chromium()
			.launch_with_options(opts)
			.await
			.map_err(|e| {
				JackSparrowError::Playwright(format!("Failed to launch browser: {}", e))
			})?;

		// Create context
		let browser_context = browser.new_context().await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to create context: {}", e))
		})?;

		// Create page
		let page = browser_context.new_page().await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to create page: {}", e))
		})?;

		// Navigate to URL
		page.goto(url, None).await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to navigate to {}: {}", url, e))
		})?;

		// Get page HTML
		let html = page.content().await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to get page content: {}", e))
		})?;

		// Update manager state
		self.manager.set_current_url(url).await;

		// Close browser
		browser.close().await.map_err(|e| {
			JackSparrowError::Playwright(format!("Failed to close browser: {}", e))
		})?;

		Ok(BrowserPage {
			url: url.to_string(),
			html,
			console_messages: Vec::new(),
			network_requests: Vec::new(),
			cookies: Vec::new(),
		})
	}

	async fn execute_js(&self, _script: &str) -> Result<String, JackSparrowError> {
		Err(JackSparrowError::ToolExecutionFailed {
			tool: "playwright".to_string(),
			message: "execute_js requires page context - use navigate first".to_string(),
		})
	}

	async fn screenshot(&self, _path: &str) -> Result<(), JackSparrowError> {
		Err(JackSparrowError::ToolExecutionFailed {
			tool: "playwright".to_string(),
			message: "screenshot requires page context - use navigate first".to_string(),
		})
	}

	async fn close(&self) -> Result<(), JackSparrowError> {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_playwright_browser_new() {
		let config = BrowserConfig::default();
		let browser = PlaywrightBrowser::new(config);
		assert_eq!(browser.scanner_name(), "playwright");
	}

	#[test]
	fn test_playwright_browser_default() {
		let browser = PlaywrightBrowser::default();
		assert_eq!(browser.scanner_name(), "playwright");
	}

	#[tokio::test]
	async fn test_playwright_browser_init() {
		let browser = PlaywrightBrowser::default();
		let config = BrowserConfig::default();
		assert!(browser.init(&config).await.is_ok());
	}

	#[tokio::test]
	async fn test_playwright_browser_execute_js_without_page() {
		let browser = PlaywrightBrowser::default();
		let result = browser.execute_js("return document.title").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_playwright_browser_screenshot_without_page() {
		let browser = PlaywrightBrowser::default();
		let result = browser.screenshot("/tmp/test.png").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_playwright_browser_close() {
		let browser = PlaywrightBrowser::default();
		assert!(browser.close().await.is_ok());
	}
}

use crate::core::crawler::config::CrawlerConfig;
use reqwest::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use reqwest::{Client, StatusCode, Url};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default timeout in milliseconds if not configured.
const DEFAULT_TIMEOUT_MS: u64 = 30000;

/// Errors that can occur during a fetch operation.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Too many redirects (max {max})")]
    TooManyRedirects { max: u32 },

    #[error("Unsupported content type: {content_type}")]
    UnsupportedContentType { content_type: String },

    #[error("Non-HTML response: status {status}")]
    NonHtmlResponse { status: u16 },

    #[error("Redirect loop detected")]
    RedirectLoop,

    #[error("DNS resolution failed for {host}")]
    DnsFailed { host: String },

    #[error("Connection refused by {host}")]
    ConnectionRefused { host: String },

    #[error("SSL/TLS error: {0}")]
    Tls(String),
}

/// Result of a successful fetch.
#[derive(Debug, Clone)]
pub struct FetchedPage {
    /// The final URL after redirects.
    pub url: Url,
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HeaderMap,
    /// The HTML body (only if content-type is HTML).
    pub body: String,
    /// Content-Type header value.
    pub content_type: String,
    /// Chain of redirects followed to reach this page.
    pub redirect_chain: Vec<Url>,
    /// Time taken for the fetch in milliseconds.
    pub fetch_time_ms: u64,
    /// Size of the response body in bytes.
    pub body_size: usize,
}

/// Retry policy for failed fetches.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Base delay between retries (doubles each attempt).
    pub base_delay_ms: u64,
    /// Maximum delay cap (exponential backoff is clamped to this).
    pub max_delay_ms: u64,
    /// Jitter percentage (0-100) to add randomness to delays.
    pub jitter_percent: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 250,
            max_delay_ms: 4000,
            jitter_percent: 20,
        }
    }
}

impl RetryPolicy {
    /// Calculate the delay for a given attempt number (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.base_delay_ms * 2u64.pow(attempt);
        let capped = base.min(self.max_delay_ms);

        // Add jitter
        let jitter_range = capped * self.jitter_percent as u64 / 100;
        let jitter = if jitter_range > 0 {
            // Simple deterministic jitter based on attempt
            (attempt as u64 * 73) % jitter_range
        } else {
            0
        };

        Duration::from_millis(capped + jitter)
    }
}

/// HTTP fetcher with retry logic, connection pooling, and content validation.
#[derive(Clone)]
pub struct Fetcher {
    client: Client,
    retry_policy: RetryPolicy,
}

impl Fetcher {
    /// Create a new fetcher from crawler configuration.
    pub fn from_config(config: &CrawlerConfig) -> Self {
        let client = Client::builder()
            .user_agent(&config.user_agent)
            .timeout(config.timeout_duration())
            .redirect(reqwest::redirect::Policy::limited(
                config.scope.max_redirects as usize,
            ))
            .pool_max_idle_per_host(config.max_concurrent)
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Create a fetcher with a custom retry policy.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Fetch a URL and return the HTML content.
    ///
    /// Retries on transient failures (network errors, 5xx, 429).
    /// Returns `FetchError` for permanent failures (4xx, unsupported content).
    pub async fn fetch(&self, url: &Url) -> Result<FetchedPage, FetchError> {
        let mut last_error = None;

        for attempt in 0..=self.retry_policy.max_retries {
            if attempt > 0 {
                let delay = self.retry_policy.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            match self.fetch_once(url).await {
                Ok(page) => return Ok(page),
                Err(e) => {
                    // Only retry on transient errors
                    if self.is_retryable(&e) {
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(last_error.unwrap_or(FetchError::Timeout {
            timeout_ms: 0,
        }))
    }

    /// Single fetch attempt without retry.
    async fn fetch_once(&self, url: &Url) -> Result<FetchedPage, FetchError> {
        let start = Instant::now();

        let response = match self.client.get(url.clone()).send().await {
            Ok(r) => r,
            Err(e) => {
                if e.is_timeout() {
                    return Err(FetchError::Timeout {
                        timeout_ms: DEFAULT_TIMEOUT_MS,
                    });
                }
                if e.is_redirect() {
                    return Err(FetchError::TooManyRedirects {
                        max: 10,
                    });
                }
                return Err(FetchError::Request(e));
            }
        };

        let status = response.status();
        let headers = response.headers().clone();

        // Check for redirect responses (shouldn't happen with reqwest following, but safety)
        if status.is_redirection() {
            if let Some(location) = headers.get(LOCATION) {
                if let Ok(loc_str) = location.to_str() {
                    if let Ok(_redirect_url) = Url::parse(loc_str) {
                        return Err(FetchError::TooManyRedirects { max: 10 });
                    }
                }
            }
        }

        // Non-success status
        if !status.is_success() {
            // Retryable server errors
            if status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::REQUEST_TIMEOUT
                || (status.is_server_error() && status != StatusCode::NOT_IMPLEMENTED)
            {
                return Err(FetchError::NonHtmlResponse {
                    status: status.as_u16(),
                });
            }
            return Err(FetchError::NonHtmlResponse {
                status: status.as_u16(),
            });
        }

        // Content-Type check
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/html")
            .to_string();

        if !is_html_content(&content_type) {
            return Err(FetchError::UnsupportedContentType {
                content_type,
            });
        }

        // Read body
        let body = response.text().await.map_err(FetchError::Request)?;
        let body_size = body.len();
        let fetch_time_ms = start.elapsed().as_millis() as u64;

        Ok(FetchedPage {
            url: url.clone(),
            status: status.as_u16(),
            headers,
            body,
            content_type,
            redirect_chain: Vec::new(), // TODO: track redirects
            fetch_time_ms,
            body_size,
        })
    }

    /// Determine if an error is transient and should be retried.
    fn is_retryable(&self, error: &FetchError) -> bool {
        match error {
            FetchError::Request(e) => {
                e.is_timeout() || e.is_connect() || e.is_body() || e.is_decode()
            }
            FetchError::Timeout { .. } => true,
            FetchError::TooManyRedirects { .. } => false,
            FetchError::UnsupportedContentType { .. } => false,
            FetchError::NonHtmlResponse { status } => {
                // Retry on 429, 5xx
                *status == 429 || *status >= 500
            }
            FetchError::RedirectLoop => false,
            FetchError::DnsFailed { .. } => false,
            FetchError::ConnectionRefused { .. } => true, // Transient
            FetchError::Tls(_) => false,
        }
    }

    /// Access the underlying reqwest client.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Check if a Content-Type string indicates HTML content.
fn is_html_content(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.contains("text/html")
        || ct.contains("application/xhtml")
        || ct.contains("text/plain") // Some servers return text/plain for HTML
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_default_values() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay_ms, 250);
        assert_eq!(policy.max_delay_ms, 4000);
        assert_eq!(policy.jitter_percent, 20);
    }

    #[test]
    fn delay_increases_exponentially() {
        let policy = RetryPolicy {
            jitter_percent: 0, // No jitter for deterministic test
            ..Default::default()
        };

        let d0 = policy.delay_for_attempt(0);
        let d1 = policy.delay_for_attempt(1);
        let d2 = policy.delay_for_attempt(2);

        assert_eq!(d0, Duration::from_millis(250));
        assert_eq!(d1, Duration::from_millis(500));
        assert_eq!(d2, Duration::from_millis(1000));
    }

    #[test]
    fn delay_is_capped() {
        let policy = RetryPolicy {
            base_delay_ms: 1000,
            max_delay_ms: 3000,
            jitter_percent: 0,
            ..Default::default()
        };

        let d10 = policy.delay_for_attempt(10); // 1000 * 2^10 = 1024000, capped to 3000
        assert_eq!(d10, Duration::from_millis(3000));
    }

    #[test]
    fn delay_has_jitter() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay_ms: 1000,
            max_delay_ms: 10000,
            jitter_percent: 50,
        };

        let d0 = policy.delay_for_attempt(0);
        // Base is 1000, jitter is (0 * 73) % 500 = 0
        assert_eq!(d0, Duration::from_millis(1000));

        let d1 = policy.delay_for_attempt(1);
        // Base is 2000, jitter is (1 * 73) % 1000 = 73
        assert!(d1 >= Duration::from_millis(2000));
        assert!(d1 <= Duration::from_millis(2073));
    }

    #[test]
    fn is_html_content_detects_types() {
        assert!(is_html_content("text/html"));
        assert!(is_html_content("text/html; charset=utf-8"));
        assert!(is_html_content("application/xhtml+xml"));
        assert!(is_html_content("TEXT/HTML"));
        assert!(!is_html_content("application/json"));
        assert!(!is_html_content("image/png"));
        assert!(!is_html_content("text/css"));
    }

    #[test]
    fn fetcher_can_be_created() {
        let config = CrawlerConfig::default();
        let fetcher = Fetcher::from_config(&config);
        // Verify the client was built successfully by checking retry policy
        assert_eq!(fetcher.retry_policy.max_retries, 3);
    }

    #[test]
    fn retryable_errors() {
        let fetcher = Fetcher::from_config(&CrawlerConfig::default());

        assert!(fetcher.is_retryable(&FetchError::Timeout { timeout_ms: 5000 }));
        assert!(fetcher.is_retryable(&FetchError::NonHtmlResponse { status: 429 }));
        assert!(fetcher.is_retryable(&FetchError::NonHtmlResponse { status: 500 }));
        assert!(fetcher.is_retryable(&FetchError::NonHtmlResponse { status: 503 }));
        assert!(!fetcher.is_retryable(&FetchError::NonHtmlResponse { status: 404 }));
        assert!(!fetcher.is_retryable(&FetchError::UnsupportedContentType {
            content_type: "image/png".to_string()
        }));
        assert!(!fetcher.is_retryable(&FetchError::RedirectLoop));
        assert!(!fetcher.is_retryable(&FetchError::TooManyRedirects { max: 10 }));
    }

    #[test]
    fn fetched_page_has_expected_fields() {
        // Test the struct construction (not actual HTTP)
        let page = FetchedPage {
            url: Url::parse("http://example.com").unwrap(),
            status: 200,
            headers: HeaderMap::new(),
            body: "<html></html>".to_string(),
            content_type: "text/html".to_string(),
            redirect_chain: Vec::new(),
            fetch_time_ms: 150,
            body_size: 14,
        };

        assert_eq!(page.status, 200);
        assert_eq!(page.body_size, 14);
        assert!(page.redirect_chain.is_empty());
    }
}

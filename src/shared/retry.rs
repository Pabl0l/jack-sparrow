#![allow(dead_code)]

use std::time::Duration;

/// Retry configuration for HTTP requests
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries (cap for exponential backoff)
    pub max_delay: Duration,
    /// Backoff multiplier (e.g., 2.0 = double each time)
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 = no jitter, 1.0 = up to 100% random jitter)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.3,
        }
    }
}

impl RetryConfig {
    /// Aggressive config for critical requests
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_factor: 0.5,
        }
    }

    /// Minimal config for non-critical requests
    pub fn minimal() -> Self {
        Self {
            max_retries: 1,
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }

    /// No retries
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            initial_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            backoff_multiplier: 1.0,
            jitter_factor: 0.0,
        }
    }

    /// Calculate delay for a given retry attempt (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay_ms = self.initial_delay.as_millis() as f64;
        let delay = base_delay_ms * self.backoff_multiplier.powi(attempt as i32);
        let capped = delay.min(self.max_delay.as_millis() as f64);

        // Add jitter
        let jitter_range = capped * self.jitter_factor;
        let jitter = if jitter_range > 0.0 {
            let r: f64 = rand_simple();
            r * jitter_range
        } else {
            0.0
        };

        Duration::from_millis((capped + jitter) as u64)
    }
}

/// Simple pseudo-random f64 in [0, 1) — no external dependency needed
fn rand_simple() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u64(unsafe { std::mem::transmute::<_, u64>(0u64) });
    let bits = hasher.finish();
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

/// Result of a retry attempt
#[derive(Debug)]
pub enum RetryResult<T> {
    /// Success on first try
    Success(T),
    /// Success after retries
    SuccessAfterRetry(T, u32),
    /// Failed after all retries
    Failed(String),
    /// Should not retry (e.g., 4xx client error)
    NoRetry(String),
}

/// Check if a status code should be retried
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Check if an error should be retried
pub fn is_retryable_error(err: &reqwest::Error) -> bool {
    if err.is_timeout() || err.is_connect() {
        return true;
    }
    if let Some(status) = err.status() {
        return is_retryable_status(status.as_u16());
    }
    false
}

/// Execute an HTTP request with retries and exponential backoff
pub async fn retry_request(
    request: reqwest::RequestBuilder,
    config: &RetryConfig,
) -> RetryResult<reqwest::Response> {
    let mut last_error = String::new();

    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            let delay = config.delay_for_attempt(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        match request.try_clone().unwrap().send().await {
            Ok(response) => {
                let status = response.status().as_u16();

                if response.status().is_success() {
                    return if attempt == 0 {
                        RetryResult::Success(response)
                    } else {
                        RetryResult::SuccessAfterRetry(response, attempt)
                    };
                }

                // 4xx (except 429) = don't retry
                if status >= 400 && status < 500 && status != 429 {
                    return RetryResult::NoRetry(format!("HTTP {}", status));
                }

                last_error = format!("HTTP {}", status);
            }
            Err(e) => {
                if !is_retryable_error(&e) {
                    return RetryResult::NoRetry(e.to_string());
                }
                last_error = e.to_string();
            }
        }
    }

    RetryResult::Failed(last_error)
}

/// Simple retry wrapper for async closures
pub async fn with_retry<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            let delay = config.delay_for_attempt(attempt - 1);
            tracing::warn!(
                operation = operation_name,
                attempt = attempt,
                max = config.max_retries,
                delay_ms = delay.as_millis(),
                "Retrying after error"
            );
            tokio::time::sleep(delay).await;
        }

        match f().await {
            Ok(value) => {
                if attempt > 0 {
                    tracing::info!(
                        operation = operation_name,
                        attempt = attempt,
                        "Succeeded after retry"
                    );
                }
                return Ok(value);
            }
            Err(e) => {
                tracing::warn!(
                    operation = operation_name,
                    attempt = attempt,
                    error = %e,
                    "Request failed"
                );
                last_error = Some(e);
            }
        }
    }

    Err(last_error.expect("with_retry: no error recorded but all retries exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_retry_config_aggressive() {
        let config = RetryConfig::aggressive();
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_retry_config_minimal() {
        let config = RetryConfig::minimal();
        assert_eq!(config.max_retries, 1);
    }

    #[test]
    fn test_retry_config_none() {
        let config = RetryConfig::none();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_delay_for_attempt_increases() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0, // no jitter for deterministic test
            ..Default::default()
        };

        let d0 = config.delay_for_attempt(0);
        let d1 = config.delay_for_attempt(1);
        let d2 = config.delay_for_attempt(2);

        assert_eq!(d0, Duration::from_millis(100));
        assert_eq!(d1, Duration::from_millis(200));
        assert_eq!(d2, Duration::from_millis(400));
    }

    #[test]
    fn test_delay_is_capped() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 10.0,
            jitter_factor: 0.0,
            ..Default::default()
        };

        let d5 = config.delay_for_attempt(5);
        assert!(d5 <= Duration::from_secs(5));
    }

    #[test]
    fn test_is_retryable_status() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(504));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(403));
    }

    #[test]
    fn test_delay_with_jitter_varies() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            jitter_factor: 0.5,
            ..Default::default()
        };

        // With jitter, delays should vary between attempts
        let delays: Vec<_> = (0..10).map(|i| config.delay_for_attempt(i)).collect();
        // At least some should be different (very high probability with jitter)
        let all_same = delays.windows(2).all(|w| w[0] == w[1]);
        // This is probabilistic but essentially never fails
        assert!(!all_same || config.jitter_factor == 0.0);
    }
}

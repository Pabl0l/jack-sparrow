#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Configuration for the adaptive rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Base requests per second per domain
    pub base_rps: f64,
    /// Minimum RPS (when being throttled)
    pub min_rps: f64,
    /// Maximum RPS (when no throttling detected)
    pub max_rps: f64,
    /// How much to reduce RPS on 429 (multiplier)
    pub backoff_multiplier: f64,
    /// How much to increase RPS when no throttling (multiplier)
    pub recovery_multiplier: f64,
    /// Cooldown period after 429 (seconds)
    pub cooldown_secs: u64,
    /// Honeypot detection: if response < this ms, consider it suspicious
    pub honeypot_threshold_ms: u64,
    /// Max requests before forcing a cooldown
    pub burst_limit: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            base_rps: 5.0,
            min_rps: 0.5,
            max_rps: 20.0,
            backoff_multiplier: 0.5,
            recovery_multiplier: 1.1,
            cooldown_secs: 60,
            honeypot_threshold_ms: 10,
            burst_limit: 50,
        }
    }
}

/// Per-domain rate limit state
#[derive(Debug, Clone)]
struct DomainState {
    current_rps: f64,
    last_request: Instant,
    consecutive_429: u32,
    cooldown_until: Option<Instant>,
    request_count: u32,
    suspicious_fast_count: u32,
    total_requests: u32,
}

impl DomainState {
    fn new(base_rps: f64) -> Self {
        Self {
            current_rps: base_rps,
            last_request: Instant::now(),
            consecutive_429: 0,
            cooldown_until: None,
            request_count: 0,
            suspicious_fast_count: 0,
            total_requests: 0,
        }
    }
}

/// Adaptive rate limiter that adjusts per-domain based on server responses
pub struct AdaptiveRateLimiter {
    config: RateLimiterConfig,
    domains: Arc<Mutex<HashMap<String, DomainState>>>,
}

impl AdaptiveRateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            domains: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Extract domain from URL
    fn extract_domain(url: &str) -> String {
        url.split("://")
            .nth(1)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or(url)
            .split(':')
            .next()
            .unwrap_or(url)
            .to_string()
    }

    /// Wait until a request is allowed for the given URL
    pub async fn wait(&self, url: &str) {
        let domain = Self::extract_domain(url);

        loop {
            let wait_duration = {
                let mut domains = self.domains.lock().await;
                let now = Instant::now();

                let state = domains
                    .entry(domain.clone())
                    .or_insert_with(|| DomainState::new(self.config.base_rps));

                // Check if in cooldown
                if let Some(cooldown_end) = state.cooldown_until {
                    if now < cooldown_end {
                        let remaining = cooldown_end.duration_since(now);
                        Some(remaining)
                    } else {
                        state.cooldown_until = None;
                        state.consecutive_429 = 0;
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(wait) = wait_duration {
                tracing::debug!(
                    domain = %domain,
                    wait_ms = wait.as_millis(),
                    "Rate limiter: domain in cooldown"
                );
                tokio::time::sleep(wait).await;
            } else {
                break;
            }
        }

        // Enforce inter-request delay
        {
            let mut domains = self.domains.lock().await;
            let now = Instant::now();
            let state = domains
                .entry(domain.clone())
                .or_insert_with(|| DomainState::new(self.config.base_rps));

            let min_interval = Duration::from_secs_f64(1.0 / state.current_rps);
            let elapsed = now.duration_since(state.last_request);

            if elapsed < min_interval {
                let sleep_time = min_interval - elapsed;
                drop(domains);
                tokio::time::sleep(sleep_time).await;
                let mut domains = self.domains.lock().await;
                if let Some(state) = domains.get_mut(&domain) {
                    state.last_request = Instant::now();
                    state.request_count += 1;
                    state.total_requests += 1;
                }
            } else {
                state.last_request = now;
                state.request_count += 1;
                state.total_requests += 1;
            }
        }
    }

    /// Report the result of a request to adapt the rate
    pub async fn report_result(&self, url: &str, status: Option<u16>, response_time_ms: u64) {
        let domain = Self::extract_domain(url);
        let mut domains = self.domains.lock().await;
        let now = Instant::now();

        let state = domains
            .entry(domain.clone())
            .or_insert_with(|| DomainState::new(self.config.base_rps));

        match status {
            Some(429) => {
                // Rate limited — back off aggressively
                state.consecutive_429 += 1;
                state.current_rps =
                    (state.current_rps * self.config.backoff_multiplier).max(self.config.min_rps);
                state.cooldown_until =
                    Some(now + Duration::from_secs(self.config.cooldown_secs));

                tracing::warn!(
                    domain = %domain,
                    new_rps = state.current_rps,
                    consecutive_429 = state.consecutive_429,
                    "Rate limited (429) — reducing request rate"
                );
            }
            Some(status) if status >= 500 => {
                // Server error — slight backoff
                state.current_rps =
                    (state.current_rps * 0.8).max(self.config.min_rps);
                tracing::warn!(
                    domain = %domain,
                    status = status,
                    new_rps = state.current_rps,
                    "Server error — reducing rate"
                );
            }
            Some(200..=399) => {
                // Success — recover rate slowly
                state.current_rps =
                    (state.current_rps * self.config.recovery_multiplier).min(self.config.max_rps);
                state.consecutive_429 = 0;
            }
            _ => {}
        }

        // Honeypot detection
        if response_time_ms < self.config.honeypot_threshold_ms && response_time_ms > 0 {
            state.suspicious_fast_count += 1;
            if state.suspicious_fast_count >= 3 {
                state.current_rps = self.config.min_rps;
                tracing::warn!(
                    domain = %domain,
                    fast_count = state.suspicious_fast_count,
                    "Possible honeypot detected — minimum rate"
                );
            }
        }

        // Burst limit check
        if state.request_count >= self.config.burst_limit {
            state.cooldown_until =
                Some(now + Duration::from_secs(self.config.cooldown_secs / 2));
            state.request_count = 0;
            tracing::info!(
                domain = %domain,
                "Burst limit reached — short cooldown"
            );
        }
    }

    /// Get current RPS for a domain
    pub async fn get_rps(&self, url: &str) -> f64 {
        let domain = Self::extract_domain(url);
        let domains = self.domains.lock().await;
        domains
            .get(&domain)
            .map(|s| s.current_rps)
            .unwrap_or(self.config.base_rps)
    }

    /// Get stats for all domains
    pub async fn stats(&self) -> HashMap<String, DomainStats> {
        let domains = self.domains.lock().await;
        domains
            .iter()
            .map(|(domain, state)| {
                (
                    domain.clone(),
                    DomainStats {
                        current_rps: state.current_rps,
                        total_requests: state.total_requests,
                        consecutive_429: state.consecutive_429,
                        in_cooldown: state.cooldown_until.is_some(),
                        suspicious_fast_count: state.suspicious_fast_count,
                    },
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct DomainStats {
    pub current_rps: f64,
    pub total_requests: u32,
    pub consecutive_429: u32,
    pub in_cooldown: bool,
    pub suspicious_fast_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            AdaptiveRateLimiter::extract_domain("http://example.com/path"),
            "example.com"
        );
        assert_eq!(
            AdaptiveRateLimiter::extract_domain("https://api.example.com:8080/v1"),
            "api.example.com"
        );
        assert_eq!(
            AdaptiveRateLimiter::extract_domain("https://sub.domain.co.uk"),
            "sub.domain.co.uk"
        );
    }

    #[test]
    fn test_rate_limiter_config_default() {
        let config = RateLimiterConfig::default();
        assert_eq!(config.base_rps, 5.0);
        assert_eq!(config.min_rps, 0.5);
        assert_eq!(config.max_rps, 20.0);
        assert_eq!(config.cooldown_secs, 60);
    }

    #[tokio::test]
    async fn test_rate_limiter_creates_domain_state() {
        let limiter = AdaptiveRateLimiter::with_defaults();
        limiter.wait("http://example.com/test").await;
        let stats = limiter.stats().await;
        assert!(stats.contains_key("example.com"));
    }

    #[tokio::test]
    async fn test_rate_limiter_429_backs_off() {
        let limiter = AdaptiveRateLimiter::with_defaults();
        limiter.wait("http://example.com/test").await;

        let rps_before = limiter.get_rps("http://example.com/test").await;

        // Report 429
        limiter
            .report_result("http://example.com/test", Some(429), 100)
            .await;

        let rps_after = limiter.get_rps("http://example.com/test").await;
        assert!(rps_after < rps_before);
    }

    #[tokio::test]
    async fn test_rate_limiter_success_recovers() {
        let config = RateLimiterConfig {
            base_rps: 5.0,
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::new(config);
        limiter.wait("http://example.com/test").await;

        // Report success
        limiter
            .report_result("http://example.com/test", Some(200), 200)
            .await;

        let stats = limiter.stats().await;
        let domain_stats = stats.get("example.com").unwrap();
        assert!(domain_stats.current_rps >= 5.0);
    }

    #[tokio::test]
    async fn test_rate_limiter_honeypot_detection() {
        let config = RateLimiterConfig {
            honeypot_threshold_ms: 10,
            ..Default::default()
        };
        let min_rps = config.min_rps;
        let limiter = AdaptiveRateLimiter::new(config);

        // 3 suspicious fast responses
        for _ in 0..3 {
            limiter
                .report_result("http://example.com/test", Some(200), 1)
                .await;
        }

        let stats = limiter.stats().await;
        let domain_stats = stats.get("example.com").unwrap();
        assert!(domain_stats.suspicious_fast_count >= 3);
        // RPS should be at minimum
        assert!(domain_stats.current_rps <= min_rps + 0.1);
    }

    #[tokio::test]
    async fn test_rate_limiter_500_backs_off() {
        let limiter = AdaptiveRateLimiter::with_defaults();
        limiter.wait("http://example.com/test").await;

        let rps_before = limiter.get_rps("http://example.com/test").await;

        limiter
            .report_result("http://example.com/test", Some(500), 500)
            .await;

        let rps_after = limiter.get_rps("http://example.com/test").await;
        assert!(rps_after < rps_before);
    }
}

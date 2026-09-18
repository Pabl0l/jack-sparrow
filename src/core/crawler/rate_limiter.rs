use dashmap::DashMap;
use governor::state::{NotKeyed, InMemoryState};
use governor::{Quota, RateLimiter as GovernorLimiter, clock::DefaultClock};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

/// Type alias for the governor rate limiter used internally.
type GovernorRateLimiter = GovernorLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-domain rate limiter using the GCRA (Generic Cell Rate Algorithm).
///
/// Each domain gets its own rate limiter, allowing different crawl speeds
/// for different servers. The default is 1 request per second with burst of 1.
///
/// # Example
/// ```ignore
/// let limiter = DomainRateLimiter::new(Duration::from_millis(1000), 1);
/// limiter.wait("example.com").await;
/// // ... make request ...
/// ```
pub struct DomainRateLimiter {
    /// Map of domain -> rate limiter.
    limiters: DashMap<String, Arc<GovernorRateLimiter>>,
    /// Default delay between requests.
    default_delay: Duration,
    /// Burst size (number of immediate requests allowed).
    burst_size: u32,
}

impl DomainRateLimiter {
    /// Create a new rate limiter with default settings (1 req/sec, burst=1).
    pub fn new(default_delay: Duration, burst_size: u32) -> Self {
        Self {
            limiters: DashMap::new(),
            default_delay,
            burst_size,
        }
    }

    /// Create a rate limiter from milliseconds.
    pub fn from_millis(delay_ms: u64, burst_size: u32) -> Self {
        Self::new(Duration::from_millis(delay_ms), burst_size)
    }

    /// Create a rate limiter with a specific requests-per-second.
    pub fn from_rps(rps: f64) -> Self {
        let delay_ms = if rps > 0.0 { 1000.0 / rps } else { 1000.0 };
        Self::from_millis(delay_ms as u64, 1)
    }

    /// Wait for permission to make a request to the given domain.
    ///
    /// This will block (async) until the rate limit allows the request.
    pub async fn wait(&self, domain: &str) {
        let limiter = self.get_or_create_limiter(domain);
        limiter.until_ready().await;
    }

    /// Try to get permission immediately (non-blocking).
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub fn try_wait(&self, domain: &str) -> bool {
        let limiter = self.get_or_create_limiter(domain);
        limiter.check().is_ok()
    }

    /// Get the delay until the next request is allowed for a domain.
    pub fn next_allowed_in(&self, domain: &str) -> Duration {
        let limiter = self.get_or_create_limiter(domain);
        match limiter.check() {
            Ok(()) => Duration::ZERO,
            Err(_not_until) => {
                // Simplified: return the default delay as an estimate
                self.default_delay
            }
        }
    }

    /// Get or create a rate limiter for a domain.
    fn get_or_create_limiter(&self, domain: &str) -> Arc<GovernorRateLimiter> {
        self.limiters
            .entry(domain.to_string())
            .or_insert_with(|| {
                let quota = if self.default_delay.as_millis() > 0 {
                    Quota::with_period(self.default_delay)
                        .unwrap_or(Quota::per_second(NonZeroU32::new(1).unwrap()))
                        .allow_burst(NonZeroU32::new(self.burst_size).unwrap())
                } else {
                    // If delay is 0, allow unlimited (for testing)
                    Quota::per_second(NonZeroU32::new(u32::MAX).unwrap())
                };

                Arc::new(GovernorLimiter::direct(quota))
            })
            .clone()
    }

    /// Remove the rate limiter for a domain (reset its state).
    pub fn remove(&self, domain: &str) {
        self.limiters.remove(domain);
    }

    /// Clear all rate limiters.
    pub fn clear(&self) {
        self.limiters.clear();
    }

    /// Get the number of tracked domains.
    pub fn domain_count(&self) -> usize {
        self.limiters.len()
    }

    /// Get the default delay.
    pub fn default_delay(&self) -> Duration {
        self.default_delay
    }

    /// Get the burst size.
    pub fn burst_size(&self) -> u32 {
        self.burst_size
    }
}

/// Shared handle for use across async tasks.
#[derive(Clone)]
pub struct RateLimiterHandle {
    inner: Arc<DomainRateLimiter>,
}

impl RateLimiterHandle {
    /// Create a handle from a DomainRateLimiter.
    pub fn new(limiter: DomainRateLimiter) -> Self {
        Self {
            inner: Arc::new(limiter),
        }
    }

    /// Wait for permission to make a request.
    pub async fn wait(&self, domain: &str) {
        self.inner.wait(domain).await;
    }

    /// Try to get permission immediately.
    pub fn try_wait(&self, domain: &str) -> bool {
        self.inner.try_wait(domain)
    }

    /// Get the delay until next allowed request.
    pub fn next_allowed_in(&self, domain: &str) -> Duration {
        self.inner.next_allowed_in(domain)
    }

    /// Remove a domain's limiter.
    pub fn remove(&self, domain: &str) {
        self.inner.remove(domain);
    }

    /// Clear all limiters.
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Get the number of tracked domains.
    pub fn domain_count(&self) -> usize {
        self.inner.domain_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        assert_eq!(limiter.default_delay(), Duration::from_secs(1));
        assert_eq!(limiter.burst_size(), 1);
    }

    #[test]
    fn from_millis_creates_limiter() {
        let limiter = DomainRateLimiter::from_millis(500, 2);
        assert_eq!(limiter.default_delay(), Duration::from_millis(500));
        assert_eq!(limiter.burst_size(), 2);
    }

    #[test]
    fn from_rps_creates_limiter() {
        let limiter = DomainRateLimiter::from_rps(10.0);
        assert_eq!(limiter.default_delay(), Duration::from_millis(100));
    }

    #[test]
    fn from_rps_zero_delay() {
        let limiter = DomainRateLimiter::from_rps(0.0);
        // Should default to 1000ms
        assert_eq!(limiter.default_delay(), Duration::from_millis(1000));
    }

    #[test]
    fn domain_count_starts_at_zero() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        assert_eq!(limiter.domain_count(), 0);
    }

    #[test]
    fn remove_decreases_count() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        limiter.try_wait("example.com");
        assert_eq!(limiter.domain_count(), 1);
        limiter.remove("example.com");
        assert_eq!(limiter.domain_count(), 0);
    }

    #[test]
    fn clear_removes_all() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        limiter.try_wait("a.com");
        limiter.try_wait("b.com");
        assert_eq!(limiter.domain_count(), 2);
        limiter.clear();
        assert_eq!(limiter.domain_count(), 0);
    }

    #[test]
    fn different_domains_independent() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        // First request to each domain should succeed (burst)
        assert!(limiter.try_wait("a.com"));
        assert!(limiter.try_wait("b.com"));
        // Second request to each should fail (rate limited)
        assert!(!limiter.try_wait("a.com"));
        assert!(!limiter.try_wait("b.com"));
    }

    #[test]
    fn burst_allows_multiple_requests() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(10), 3);
        // Should allow 3 immediate requests (burst)
        assert!(limiter.try_wait("example.com"));
        assert!(limiter.try_wait("example.com"));
        assert!(limiter.try_wait("example.com"));
        // 4th should fail
        assert!(!limiter.try_wait("example.com"));
    }

    #[tokio::test]
    async fn wait_blocks_until_available() {
        let limiter = DomainRateLimiter::from_millis(50, 1);
        let start = std::time::Instant::now();

        limiter.wait("example.com").await;
        limiter.wait("example.com").await;

        let elapsed = start.elapsed();
        // Should have waited at least 50ms
        assert!(elapsed >= Duration::from_millis(40)); // Allow some tolerance
    }

    #[test]
    fn handle_works() {
        let limiter = DomainRateLimiter::new(Duration::from_secs(1), 1);
        let handle = RateLimiterHandle::new(limiter);

        assert!(handle.try_wait("example.com"));
        assert_eq!(handle.domain_count(), 1);
        handle.remove("example.com");
        assert_eq!(handle.domain_count(), 0);
    }

    #[test]
    fn zero_delay_allows_unlimited() {
        let limiter = DomainRateLimiter::new(Duration::ZERO, 1);
        // All should succeed
        for _ in 0..100 {
            assert!(limiter.try_wait("example.com"));
        }
    }
}

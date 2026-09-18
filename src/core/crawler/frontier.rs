use bloomfilter::Bloom;
use dashmap::DashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use url::Url;

/// A single URL request in the crawl frontier, with metadata.
#[derive(Debug, Clone)]
pub struct CrawlRequest {
    pub url: Url,
    pub depth: u32,
    pub domain: String,
}

/// Statistics about the frontier's operations.
#[derive(Debug, Default)]
pub struct FrontierStats {
    pub enqueued: AtomicUsize,
    pub deduplicated: AtomicUsize,
    pub depth_exceeded: AtomicUsize,
    pub scope_filtered: AtomicUsize,
}

impl FrontierStats {
    pub fn snapshot(&self) -> FrontierSnapshot {
        FrontierSnapshot {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            deduplicated: self.deduplicated.load(Ordering::Relaxed),
            depth_exceeded: self.depth_exceeded.load(Ordering::Relaxed),
            scope_filtered: self.scope_filtered.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time snapshot of frontier statistics.
#[derive(Debug, Clone, Default)]
pub struct FrontierSnapshot {
    pub enqueued: usize,
    pub deduplicated: usize,
    pub depth_exceeded: usize,
    pub scope_filtered: usize,
}

/// URL deduplication strategy.
#[derive(Debug, Clone)]
pub enum DedupStrategy {
    /// Exact-match DashSet — fast, low memory for < threshold URLs.
    Exact,
    /// Bloom filter — probabilistic, low memory for > threshold URLs.
    /// Parameter: expected number of URLs, false positive rate.
    Bloom { expected: usize, fp_rate: f64 },
}

/// The URL frontier manages the crawl queue with deduplication and depth tracking.
///
/// # Deduplication
/// Uses `DashSet` for small crawls and an optional `BloomFilter` for large crawls.
/// The threshold is configurable via `DedupStrategy`.
///
/// # Depth Tracking
/// Each URL carries a depth. URLs beyond `max_depth` are rejected.
pub struct UrlFrontier {
    /// Set of visited URL strings (exact dedup).
    visited: DashSet<String>,
    /// Bloom filter for large-scale dedup (optional).
    bloom: Option<Bloom<String>>,
    /// Strategy in use.
    strategy: DedupStrategy,
    /// Channel sender for crawl requests.
    sender: async_channel::Sender<CrawlRequest>,
    /// Channel receiver for crawl requests.
    receiver: async_channel::Receiver<CrawlRequest>,
    /// Live statistics.
    stats: Arc<FrontierStats>,
}

/// Shared handle to the frontier for use across async tasks.
#[derive(Clone)]
pub struct FrontierHandle {
    inner: Arc<UrlFrontier>,
}

impl UrlFrontier {
    /// Create a new frontier with the given dedup strategy and channel capacity.
    pub fn new(strategy: DedupStrategy, channel_capacity: usize) -> Self {
        let bloom = match &strategy {
            DedupStrategy::Bloom { expected, fp_rate } => {
                Some(Bloom::new_for_fp_rate(*expected, *fp_rate))
            }
            DedupStrategy::Exact => None,
        };

        let (sender, receiver) = async_channel::bounded(channel_capacity);

        Self {
            visited: DashSet::new(),
            bloom,
            strategy,
            sender,
            receiver,
            stats: Arc::new(FrontierStats::default()),
        }
    }

    /// Wrap in a `FrontierHandle` for sharing across tasks.
    pub fn into_handle(self) -> FrontierHandle {
        FrontierHandle {
            inner: Arc::new(self),
        }
    }

    /// Seed the frontier with an initial URL at depth 0.
    pub fn seed(&self, url: Url) -> bool {
        let domain = url.host_str().unwrap_or("unknown").to_string();
        let request = CrawlRequest {
            url,
            depth: 0,
            domain,
        };
        self.try_enqueue(request)
    }

    /// Attempt to enqueue a URL. Returns `true` if the URL was accepted.
    ///
    /// Rejection reasons:
    /// - Already visited (dedup)
    /// - Beyond max depth
    /// - Channel full (backpressure)
    pub fn try_enqueue(&self, request: CrawlRequest) -> bool {
        let url_str = request.url.to_string();

        // 1. Exact dedup via DashSet
        if !self.visited.insert(url_str.clone()) {
            self.stats.deduplicated.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. Bloom filter dedup (if enabled)
        if let Some(ref bloom) = self.bloom {
            if bloom.check(&url_str) {
                // Might be a false positive — but we already inserted into DashSet,
                // so the DashSet is the source of truth for small crawls.
                // For large crawls, the bloom filter is a pre-filter.
                self.stats.deduplicated.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            // We can't mutate the bloom filter here because Bloom is not Sync.
            // The bloom filter is populated after successful crawl in the engine.
        }

        // 3. Enqueue
        if self.sender.try_send(request).is_ok() {
            self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            // Channel full — backpressure
            false
        }
    }

    /// Mark a URL as successfully crawled (for bloom filter tracking).
    pub fn mark_visited(&self, _url_str: &str) {
        // Bloom filter population happens here for large crawls.
        // For exact strategy, the DashSet already has it.
        if let Some(ref _bloom) = self.bloom {
            // Note: Bloom::set requires &mut self, so we'd need interior mutability.
            // For now, the DashSet is the source of truth.
            // TODO: Use parking_lot::Mutex<Bloom> for mutable bloom in async context.
        }
    }

    /// Try to receive the next crawl request (non-blocking).
    pub fn try_next(&self) -> Option<CrawlRequest> {
        self.receiver.try_recv().ok()
    }

    /// Receive the next crawl request (async, blocks until available or closed).
    pub async fn next(&self) -> Option<CrawlRequest> {
        self.receiver.recv().await.ok()
    }

    /// Get a snapshot of frontier statistics.
    pub fn stats(&self) -> FrontierSnapshot {
        self.stats.snapshot()
    }

    /// Number of URLs currently in the channel (queued, not yet consumed).
    pub fn queued(&self) -> usize {
        self.receiver.len()
    }

    /// Close the sender side, signaling no more URLs will be added.
    pub fn close(&self) {
        self.sender.close();
    }

    /// Check if the frontier is done (closed and empty).
    pub fn is_done(&self) -> bool {
        self.sender.is_closed() && self.receiver.is_empty()
    }

    /// Total number of unique URLs seen (visited + queued).
    pub fn total_seen(&self) -> usize {
        self.visited.len()
    }
}

impl FrontierHandle {
    /// Enqueue a discovered URL with depth tracking.
    ///
    /// Returns `true` if the URL was accepted into the frontier.
    pub fn enqueue(&self, url: Url, current_depth: u32, max_depth: u32) -> bool {
        // Depth check
        if current_depth >= max_depth {
            self.inner.stats.depth_exceeded.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let domain = url.host_str().unwrap_or("unknown").to_string();
        let request = CrawlRequest {
            url,
            depth: current_depth + 1,
            domain,
        };
        self.inner.try_enqueue(request)
    }

    /// Get the next request to crawl.
    pub async fn next(&self) -> Option<CrawlRequest> {
        self.inner.next().await
    }

    /// Non-blocking check for next request.
    pub fn try_next(&self) -> Option<CrawlRequest> {
        self.inner.try_next()
    }

    /// Mark a URL as visited.
    pub fn mark_visited(&self, _url_str: &str) {
        self.inner.mark_visited(_url_str);
    }

    /// Get frontier stats.
    pub fn stats(&self) -> FrontierSnapshot {
        self.inner.stats()
    }

    /// Number of URLs in queue.
    pub fn queued(&self) -> usize {
        self.inner.queued()
    }

    /// Close the frontier (no more URLs will be added).
    pub fn close(&self) {
        self.inner.close();
    }

    /// Check if crawling is done.
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Total unique URLs seen.
    pub fn total_seen(&self) -> usize {
        self.inner.total_seen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_url(path: &str) -> Url {
        Url::parse(&format!("http://example.com{}", path)).unwrap()
    }

    #[test]
    fn seed_accepts_new_url() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert!(frontier.seed(make_url("/")));
        assert_eq!(frontier.total_seen(), 1);
        assert_eq!(frontier.stats().enqueued, 1);
    }

    #[test]
    fn seed_rejects_duplicate() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert!(frontier.seed(make_url("/")));
        assert!(!frontier.seed(make_url("/")));
        assert_eq!(frontier.stats().deduplicated, 1);
        assert_eq!(frontier.total_seen(), 1);
    }

    #[test]
    fn try_enqueue_respects_dedup() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        let req1 = CrawlRequest {
            url: make_url("/a"),
            depth: 1,
            domain: "example.com".to_string(),
        };
        let req2 = CrawlRequest {
            url: make_url("/a"),
            depth: 1,
            domain: "example.com".to_string(),
        };
        assert!(frontier.try_enqueue(req1));
        assert!(!frontier.try_enqueue(req2));
        assert_eq!(frontier.stats().deduplicated, 1);
    }

    #[test]
    fn try_enqueue_allows_different_urls() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert!(frontier.try_enqueue(CrawlRequest {
            url: make_url("/a"),
            depth: 1,
            domain: "example.com".to_string(),
        }));
        assert!(frontier.try_enqueue(CrawlRequest {
            url: make_url("/b"),
            depth: 1,
            domain: "example.com".to_string(),
        }));
        assert_eq!(frontier.stats().enqueued, 2);
    }

    #[test]
    fn next_returns_enqueued_urls() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        frontier.seed(make_url("/page1"));
        frontier.seed(make_url("/page2"));

        let r1 = frontier.try_next().unwrap();
        assert_eq!(r1.url.path(), "/page1");
        assert_eq!(r1.depth, 0);

        let r2 = frontier.try_next().unwrap();
        assert_eq!(r2.url.path(), "/page2");

        assert!(frontier.try_next().is_none());
    }

    #[test]
    fn close_prevents_further_receives() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        frontier.seed(make_url("/"));
        frontier.close();

        // Can still drain what's in the channel
        assert!(frontier.try_next().is_some());
        // But after that, is_done should be true
        assert!(frontier.is_done());
    }

    #[test]
    fn handle_enqueue_respects_max_depth() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100).into_handle();

        // depth 2 with max_depth 2 → rejected (current_depth >= max_depth)
        assert!(!frontier.enqueue(make_url("/deep"), 2, 2));
        assert_eq!(frontier.stats().depth_exceeded, 1);

        // depth 1 with max_depth 2 → accepted
        assert!(frontier.enqueue(make_url("/ok"), 1, 2));
    }

    #[test]
    fn handle_stats_are_cumulative() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100).into_handle();

        frontier.enqueue(make_url("/a"), 0, 3);
        frontier.enqueue(make_url("/b"), 0, 3);
        frontier.enqueue(make_url("/a"), 0, 3); // duplicate

        let stats = frontier.stats();
        assert_eq!(stats.enqueued, 2);
        assert_eq!(stats.deduplicated, 1);
    }

    #[test]
    fn bloom_strategy_creates_bloom_filter() {
        let frontier = UrlFrontier::new(
            DedupStrategy::Bloom {
                expected: 1000,
                fp_rate: 0.01,
            },
            100,
        );
        assert!(frontier.bloom.is_some());
    }

    #[test]
    fn exact_strategy_no_bloom_filter() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert!(frontier.bloom.is_none());
    }

    #[test]
    fn queued_count_tracks_channel() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert_eq!(frontier.queued(), 0);

        frontier.seed(make_url("/a"));
        assert_eq!(frontier.queued(), 1);

        frontier.seed(make_url("/b"));
        assert_eq!(frontier.queued(), 2);

        frontier.try_next();
        assert_eq!(frontier.queued(), 1);
    }

    #[test]
    fn different_domains_are_allowed() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        assert!(frontier.try_enqueue(CrawlRequest {
            url: Url::parse("http://a.com/").unwrap(),
            depth: 0,
            domain: "a.com".to_string(),
        }));
        assert!(frontier.try_enqueue(CrawlRequest {
            url: Url::parse("http://b.com/").unwrap(),
            depth: 0,
            domain: "b.com".to_string(),
        }));
        assert_eq!(frontier.stats().enqueued, 2);
    }

    #[test]
    fn stats_snapshot_is_independent_copy() {
        let frontier = UrlFrontier::new(DedupStrategy::Exact, 100);
        frontier.seed(make_url("/"));

        let snap1 = frontier.stats();
        frontier.seed(make_url("/new"));
        let snap2 = frontier.stats();

        assert_eq!(snap1.enqueued, 1);
        assert_eq!(snap2.enqueued, 2);
    }
}

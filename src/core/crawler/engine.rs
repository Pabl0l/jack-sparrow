use crate::core::crawler::config::CrawlerConfig;
use crate::core::crawler::fetcher::Fetcher;
use crate::core::crawler::frontier::{DedupStrategy, FrontierHandle, UrlFrontier};
use crate::core::crawler::parser::{HtmlParser, ParsedPage};
use crate::core::crawler::rate_limiter::{DomainRateLimiter, RateLimiterHandle};
use crate::core::crawler::robots::RobotsCache;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use url::Url;

/// Statistics from a crawl run.
#[derive(Debug, Clone, Default)]
pub struct CrawlStats {
    pub pages_crawled: usize,
    pub pages_failed: usize,
    pub links_discovered: usize,
    pub forms_found: usize,
    pub scripts_found: usize,
    pub iframes_found: usize,
    pub embeds_found: usize,
    pub event_handlers_found: usize,
    pub depth_reached: u32,
    pub duration_ms: u64,
    pub requests_made: usize,
    pub bytes_downloaded: usize,
}

/// A single crawled page with all extracted data.
#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: Url,
    pub status: u16,
    pub parsed: Option<ParsedPage>,
    pub fetch_time_ms: u64,
    pub body_size: usize,
    pub depth: u32,
}

/// Complete results from a crawl run.
#[derive(Debug, Clone)]
pub struct CrawlResults {
    pub target: Url,
    pub pages: Vec<CrawledPage>,
    pub stats: CrawlStats,
    pub errors: Vec<CrawlError>,
}

/// An error that occurred during crawling.
#[derive(Debug, Clone)]
pub struct CrawlError {
    pub url: Url,
    pub error: String,
    pub depth: u32,
}

/// Events emitted during crawling for progress reporting.
#[derive(Debug, Clone)]
pub enum CrawlEvent {
    PageStarted { url: Url, depth: u32 },
    PageCompleted { url: Url, status: u16, links: usize, forms: usize },
    PageFailed { url: Url, error: String },
    DepthReached { depth: u32 },
    CrawlComplete { stats: CrawlStats },
}

/// The main crawler engine that orchestrates all components.
///
/// # Architecture
///
/// ```text
///                     ┌─────────────────┐
///                     │  CrawlerEngine   │
///                     └────────┬────────┘
///                              │
///         ┌────────────────────┼────────────────────┐
///         │                    │                     │
///    ┌────▼────┐         ┌─────▼─────┐         ┌────▼────┐
///    │ Frontier │         │  Fetcher  │         │ Parser  │
///    │ (URLs)  │         │  (HTTP)   │         │ (HTML)  │
///    └────┬────┘         └─────┬─────┘         └────┬────┘
///         │                    │                     │
///    ┌────▼────┐         ┌─────▼─────┐         ┌────▼────┐
///    │ Robots  │         │   Rate    │         │ Results │
///    │  (txt)  │         │  Limiter  │         │ (output)│
///    └─────────┘         └───────────┘         └─────────┘
/// ```
pub struct CrawlerEngine {
    config: CrawlerConfig,
    frontier: FrontierHandle,
    fetcher: Fetcher,
    parser: HtmlParser,
    robots: RobotsCache,
    limiter: RateLimiterHandle,
    results: Arc<Mutex<Vec<CrawledPage>>>,
    errors: Arc<Mutex<Vec<CrawlError>>>,
    stats: Arc<CrawlStatsInner>,
}

struct CrawlStatsInner {
    pages_crawled: AtomicUsize,
    pages_failed: AtomicUsize,
    links_discovered: AtomicUsize,
    forms_found: AtomicUsize,
    scripts_found: AtomicUsize,
    iframes_found: AtomicUsize,
    embeds_found: AtomicUsize,
    event_handlers_found: AtomicUsize,
    depth_reached: AtomicUsize,
    requests_made: AtomicUsize,
    bytes_downloaded: AtomicUsize,
}

impl Default for CrawlStatsInner {
    fn default() -> Self {
        Self {
            pages_crawled: AtomicUsize::new(0),
            pages_failed: AtomicUsize::new(0),
            links_discovered: AtomicUsize::new(0),
            forms_found: AtomicUsize::new(0),
            scripts_found: AtomicUsize::new(0),
            iframes_found: AtomicUsize::new(0),
            embeds_found: AtomicUsize::new(0),
            event_handlers_found: AtomicUsize::new(0),
            depth_reached: AtomicUsize::new(0),
            requests_made: AtomicUsize::new(0),
            bytes_downloaded: AtomicUsize::new(0),
        }
    }
}

impl CrawlerEngine {
    /// Create a new crawler engine with the given configuration.
    pub fn new(config: CrawlerConfig) -> Self {
        let client = Client::builder()
            .user_agent(&config.user_agent)
            .timeout(config.timeout_duration())
            .redirect(reqwest::redirect::Policy::limited(
                config.scope.max_redirects as usize,
            ))
            .build()
            .expect("failed to build HTTP client");

        let fetcher = Fetcher::from_config(&config);
        let robots = RobotsCache::new(client.clone(), &config.user_agent);
        let limiter = RateLimiterHandle::new(DomainRateLimiter::from_millis(
            config.delay_ms,
            config.max_concurrent as u32,
        ));

        let frontier = UrlFrontier::new(DedupStrategy::Exact, 10_000).into_handle();

        Self {
            config,
            frontier,
            fetcher,
            parser: HtmlParser::new(Url::parse("http://placeholder").unwrap()),
            robots,
            limiter,
            results: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(CrawlStatsInner::default()),
        }
    }

    /// Create a crawler with custom frontier settings.
    pub fn with_frontier_strategy(mut self, strategy: DedupStrategy) -> Self {
        self.frontier = UrlFrontier::new(strategy, 10_000).into_handle();
        self
    }

    /// Start a crawl from the given URL.
    ///
    /// Returns the crawl results after completion.
    pub async fn crawl(&self, target: &Url) -> Result<CrawlResults, CrawlError> {
        self.crawl_with_callback(target, |_| {}).await
    }

    /// Start a crawl with a progress callback.
    pub async fn crawl_with_callback<F>(
        &self,
        target: &Url,
        callback: F,
    ) -> Result<CrawlResults, CrawlError>
    where
        F: Fn(CrawlEvent) + Send + Sync + Clone + 'static,
    {
        let start = Instant::now();

        // Seed the frontier
        self.frontier.enqueue(target.clone(), 0, self.config.max_depth + 1);

        // Spawn workers
        let callback = Arc::new(callback);
        let workers = self.spawn_workers(callback.clone());

        // Wait for all workers to complete
        for worker in workers {
            let _ = worker.await;
        }

        // Close frontier
        self.frontier.close();

        let duration_ms = start.elapsed().as_millis() as u64;

        // Collect results
        let pages = self.results.lock().await.clone();
        let errors = self.errors.lock().await.clone();

        let stats = CrawlStats {
            pages_crawled: self.stats.pages_crawled.load(Ordering::Relaxed),
            pages_failed: self.stats.pages_failed.load(Ordering::Relaxed),
            links_discovered: self.stats.links_discovered.load(Ordering::Relaxed),
            forms_found: self.stats.forms_found.load(Ordering::Relaxed),
            scripts_found: self.stats.scripts_found.load(Ordering::Relaxed),
            iframes_found: self.stats.iframes_found.load(Ordering::Relaxed),
            embeds_found: self.stats.embeds_found.load(Ordering::Relaxed),
            event_handlers_found: self.stats.event_handlers_found.load(Ordering::Relaxed),
            depth_reached: self.stats.depth_reached.load(Ordering::Relaxed) as u32,
            duration_ms,
            requests_made: self.stats.requests_made.load(Ordering::Relaxed),
            bytes_downloaded: self.stats.bytes_downloaded.load(Ordering::Relaxed),
        };

        callback(CrawlEvent::CrawlComplete {
            stats: stats.clone(),
        });

        Ok(CrawlResults {
            target: target.clone(),
            pages,
            stats,
            errors,
        })
    }

    /// Spawn worker tasks for crawling.
    fn spawn_workers<F>(&self, callback: Arc<F>) -> Vec<tokio::task::JoinHandle<()>>
    where
        F: Fn(CrawlEvent) + Send + Sync + Clone + 'static,
    {
        let mut workers = Vec::new();

        for _ in 0..self.config.max_concurrent {
            let frontier = self.frontier.clone();
            let fetcher = self.fetcher.clone();
            let robots = self.robots.clone();
            let limiter = self.limiter.clone();
            let results = self.results.clone();
            let errors = self.errors.clone();
            let stats = self.stats.clone();
            let config = self.config.clone();
            let callback = callback.clone();

            workers.push(tokio::spawn(async move {
                Self::worker_loop(
                    frontier,
                    fetcher,
                    robots,
                    limiter,
                    results,
                    errors,
                    stats,
                    config,
                    callback,
                )
                .await;
            }));
        }

        workers
    }

    /// Main worker loop that processes URLs from the frontier.
    async fn worker_loop(
        frontier: FrontierHandle,
        fetcher: Fetcher,
        robots: RobotsCache,
        limiter: RateLimiterHandle,
        results: Arc<Mutex<Vec<CrawledPage>>>,
        errors: Arc<Mutex<Vec<CrawlError>>>,
        stats: Arc<CrawlStatsInner>,
        config: CrawlerConfig,
        callback: Arc<impl Fn(CrawlEvent) + Send + Sync>,
    ) {
        while let Some(request) = frontier.next().await {
            let url = &request.url;
            let domain = url.host_str().unwrap_or("unknown");

            // Check robots.txt
            if config.respect_robots {
                match robots.is_allowed(url).await {
                    Ok(false) => {
                        // Not allowed by robots.txt
                        continue;
                    }
                    Ok(true) => {}
                    Err(_) => {
                        // Error checking robots.txt, proceed anyway
                    }
                }
            }

            // Wait for rate limit
            limiter.wait(domain).await;

            // Emit start event
            callback(CrawlEvent::PageStarted {
                url: url.clone(),
                depth: request.depth,
            });

            // Fetch the page
            stats.requests_made.fetch_add(1, Ordering::Relaxed);
            match fetcher.fetch(url).await {
                Ok(page) => {
                    // Parse the page
                    let parsed = HtmlParser::new(url.clone()).parse(&page.body);

                    // Update stats
                    stats.pages_crawled.fetch_add(1, Ordering::Relaxed);
                    stats.links_discovered.fetch_add(parsed.links.len(), Ordering::Relaxed);
                    stats.forms_found.fetch_add(parsed.forms.len(), Ordering::Relaxed);
                    stats.scripts_found.fetch_add(parsed.scripts.len(), Ordering::Relaxed);
                    stats.iframes_found.fetch_add(parsed.iframes.len(), Ordering::Relaxed);
                    stats.embeds_found.fetch_add(parsed.embeds.len(), Ordering::Relaxed);
                    stats
                        .event_handlers_found
                        .fetch_add(parsed.event_handlers.len(), Ordering::Relaxed);
                    stats.bytes_downloaded.fetch_add(page.body_size, Ordering::Relaxed);

                    let depth = request.depth;
                    if depth > stats.depth_reached.load(Ordering::Relaxed) as u32 {
                        stats.depth_reached.store(depth as usize, Ordering::Relaxed);
                    }

                    // Enqueue discovered links
                    for link in &parsed.links {
                        frontier.enqueue(link.href.clone(), depth, config.max_depth);
                    }

                    // Store the crawled page
                    let crawled = CrawledPage {
                        url: url.clone(),
                        status: page.status,
                        parsed: Some(parsed.clone()),
                        fetch_time_ms: page.fetch_time_ms,
                        body_size: page.body_size,
                        depth,
                    };

                    results.lock().await.push(crawled);

                    // Emit completion event
                    callback(CrawlEvent::PageCompleted {
                        url: url.clone(),
                        status: page.status,
                        links: parsed.links.len(),
                        forms: parsed.forms.len(),
                    });
                }
                Err(e) => {
                    stats.pages_failed.fetch_add(1, Ordering::Relaxed);

                    let error = CrawlError {
                        url: url.clone(),
                        error: e.to_string(),
                        depth: request.depth,
                    };

                    errors.lock().await.push(error.clone());

                    callback(CrawlEvent::PageFailed {
                        url: url.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    /// Get the current crawl statistics (live, during crawl).
    pub fn live_stats(&self) -> CrawlStats {
        CrawlStats {
            pages_crawled: self.stats.pages_crawled.load(Ordering::Relaxed),
            pages_failed: self.stats.pages_failed.load(Ordering::Relaxed),
            links_discovered: self.stats.links_discovered.load(Ordering::Relaxed),
            forms_found: self.stats.forms_found.load(Ordering::Relaxed),
            scripts_found: self.stats.scripts_found.load(Ordering::Relaxed),
            iframes_found: self.stats.iframes_found.load(Ordering::Relaxed),
            embeds_found: self.stats.embeds_found.load(Ordering::Relaxed),
            event_handlers_found: self.stats.event_handlers_found.load(Ordering::Relaxed),
            depth_reached: self.stats.depth_reached.load(Ordering::Relaxed) as u32,
            duration_ms: 0,
            requests_made: self.stats.requests_made.load(Ordering::Relaxed),
            bytes_downloaded: self.stats.bytes_downloaded.load(Ordering::Relaxed),
        }
    }

    /// Access the frontier handle.
    pub fn frontier(&self) -> &FrontierHandle {
        &self.frontier
    }

    /// Access the configuration.
    pub fn config(&self) -> &CrawlerConfig {
        &self.config
    }
}

// Manual Clone implementation since we can't derive it with Arc<AtomicUsize>
impl Clone for CrawlerEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            frontier: self.frontier.clone(),
            fetcher: Fetcher::from_config(&self.config),
            parser: HtmlParser::new(Url::parse("http://placeholder").unwrap()),
            robots: RobotsCache::new(Client::new(), &self.config.user_agent),
            limiter: self.limiter.clone(),
            results: self.results.clone(),
            errors: self.errors.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stats_are_zero() {
        let stats = CrawlStats::default();
        assert_eq!(stats.pages_crawled, 0);
        assert_eq!(stats.pages_failed, 0);
        assert_eq!(stats.links_discovered, 0);
        assert_eq!(stats.forms_found, 0);
        assert_eq!(stats.duration_ms, 0);
    }

    #[test]
    fn crawled_page_struct() {
        let page = CrawledPage {
            url: Url::parse("http://example.com").unwrap(),
            status: 200,
            parsed: None,
            fetch_time_ms: 100,
            body_size: 1024,
            depth: 1,
        };
        assert_eq!(page.status, 200);
        assert_eq!(page.depth, 1);
        assert_eq!(page.body_size, 1024);
    }

    #[test]
    fn crawl_results_struct() {
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![],
            stats: CrawlStats::default(),
            errors: vec![],
        };
        assert!(results.pages.is_empty());
        assert!(results.errors.is_empty());
    }

    #[test]
    fn crawl_error_struct() {
        let error = CrawlError {
            url: Url::parse("http://example.com").unwrap(),
            error: "timeout".to_string(),
            depth: 2,
        };
        assert_eq!(error.error, "timeout");
        assert_eq!(error.depth, 2);
    }

    #[test]
    fn crawl_events_are_cloneable() {
        let event = CrawlEvent::PageStarted {
            url: Url::parse("http://example.com").unwrap(),
            depth: 1,
        };
        let _cloned = event.clone();
    }

    #[tokio::test]
    async fn engine_creates_with_defaults() {
        let config = CrawlerConfig::default();
        let engine = CrawlerEngine::new(config);
        assert_eq!(engine.config.max_depth, 3);
        assert_eq!(engine.config.max_concurrent, 10);
    }

    #[test]
    fn live_stats_start_at_zero() {
        let config = CrawlerConfig::default();
        let engine = CrawlerEngine::new(config);
        let stats = engine.live_stats();
        assert_eq!(stats.pages_crawled, 0);
        assert_eq!(stats.requests_made, 0);
    }

    #[test]
    fn stats_inner_default() {
        let stats = CrawlStatsInner::default();
        assert_eq!(stats.pages_crawled.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_downloaded.load(Ordering::Relaxed), 0);
    }
}

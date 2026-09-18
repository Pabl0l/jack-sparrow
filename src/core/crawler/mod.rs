//! # Crawler Engine
//!
//! High-performance async web crawler with:
//! - Per-domain rate limiting
//! - robots.txt compliance

#![allow(dead_code, unused_imports)]
//! - Efficient URL deduplication (Bloom filter for large crawls)
//! - Configurable depth and scope
//! - HTML parsing with link/form/script extraction
//! - Security-relevant element extraction (iframes, embeds, event handlers, etc.)
//! - Sitemap generation in multiple formats (XML, JSON, Text, Tree)

pub mod config;
pub mod engine;
pub mod fetcher;
pub mod frontier;
pub mod parser;
pub mod rate_limiter;
pub mod robots;
pub mod sitemap;

pub use config::{CrawlerConfig, CrawlScope};
pub use engine::{CrawlError, CrawlEvent, CrawlResults, CrawlStats, CrawledPage, CrawlerEngine};
pub use fetcher::{FetchedPage, FetchError, Fetcher, RetryPolicy};
pub use frontier::{
    DedupStrategy, FrontierHandle, UrlFrontier,
};
pub use parser::{
    BaseTag, DiscoveredEmbed, DiscoveredForm, DiscoveredIframe, DiscoveredLink,
    DiscoveredLinkTag, DiscoveredMedia, DiscoveredScript, EmbedKind, EventHandler, FormInput,
    HtmlParser, InlineScript, LinkContext, MediaKind, MetaRefresh, Method, ParsedPage,
};
pub use rate_limiter::{DomainRateLimiter, RateLimiterHandle};
pub use robots::{RobotsCache, RobotsError, RobotsFile, RobotsRule};
pub use sitemap::{Sitemap, SitemapEntry, SitemapFormat, SitemapGenerator, SitemapNode};

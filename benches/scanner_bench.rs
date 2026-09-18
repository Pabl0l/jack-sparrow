//! Benchmarks for Jack Sparrow scanners and core components.
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jack_sparrow::core::scanners::crawl_integration::CrawlTargetExtractor;
use jack_sparrow::core::scanners::dom_xss::DomXssScanner;
use jack_sparrow::core::scanners::headers::SecurityHeadersScanner;
use jack_sparrow::core::scanners::tech_fingerprint::TechFingerprintScanner;
use jack_sparrow::shared::config::JackSparrowConfig;
use jack_sparrow::shared::context::ScanContext;

fn bench_dom_xss_analysis(c: &mut Criterion) {
    let config = JackSparrowConfig::default();
    let scanner = DomXssScanner::new(&config);

    let simple_html = r#"
        <html><body>
            <div id="output"></div>
            <script>
                var data = location.hash.substring(1);
                document.getElementById('output').innerHTML = data;
            </script>
        </body></html>
    "#;

    let complex_html = r#"
        <html><body>
            <div id="app"></div>
            <script>
                // Multiple sinks and sources
                var hash = location.hash;
                var search = location.search;
                var referrer = document.referrer;

                document.getElementById('app').innerHTML = hash;
                document.write(search);
                eval(referrer);

                // Indirect flow
                var x = hash;
                var y = x;
                document.getElementById('app').innerHTML = y;
            </script>
            <script src="/external.js"></script>
            <script>console.log("inline")</script>
        </body></html>
    "#;

    c.bench_function("dom_xss_simple_html", |b| {
        b.iter(|| scanner.analyze_html(black_box(simple_html)))
    });

    c.bench_function("dom_xss_complex_html", |b| {
        b.iter(|| scanner.analyze_html(black_box(complex_html)))
    });
}

fn bench_crawl_target_extraction(c: &mut Criterion) {
    use jack_sparrow::core::crawler::engine::{CrawledPage, CrawlResults, CrawlStats};
    use jack_sparrow::core::crawler::parser::{
        DiscoveredForm, FormInput, HtmlParser, Method, ParsedPage,
    };
    use std::collections::HashMap;
    use url::Url;

    let parser = HtmlParser::new(Url::parse("http://example.com").unwrap());
    let html = r#"
        <html>
        <head><title>Test</title></head>
        <body>
            <a href="/page1?q=test">Link1</a>
            <a href="/page2?id=5">Link2</a>
            <form action="/search" method="GET">
                <input type="text" name="query">
                <input type="hidden" name="token" value="abc">
            </form>
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
            <img src="/image.png">
            <script src="/app.js"></script>
            <iframe src="/frame.html"></iframe>
        </body>
        </html>
    "#;
    let parsed = parser.parse(html);

    let crawl_results = CrawlResults {
        target: Url::parse("http://example.com").unwrap(),
        pages: vec![CrawledPage {
            url: Url::parse("http://example.com").unwrap(),
            status: 200,
            parsed: Some(parsed),
            fetch_time_ms: 50,
            body_size: html.len(),
            depth: 0,
        }],
        stats: CrawlStats::default(),
        errors: vec![],
    };

    c.bench_function("crawl_target_extraction", |b| {
        b.iter(|| CrawlTargetExtractor::extract_targets(black_box(&crawl_results)))
    });
}

fn bench_config_defaults(c: &mut Criterion) {
    c.bench_function("config_default_creation", |b| {
        b.iter(|| black_box(JackSparrowConfig::default()))
    });
}

fn bench_scan_context(c: &mut Criterion) {
    c.bench_function("scan_context_creation", |b| {
        b.iter(|| {
            black_box(ScanContext {
                cookies: Some("PHPSESSID=abc123; security=low".to_string()),
                headers: vec![
                    ("Authorization".to_string(), "Bearer token123".to_string()),
                    ("X-Custom".to_string(), "value".to_string()),
                ],
                session: None,
            })
        })
    });
}

fn bench_security_headers_parse(c: &mut Criterion) {
    let config = JackSparrowConfig::default();
    let scanner = SecurityHeadersScanner::new(&config);

    // We can't easily bench the async scan without a server,
    // but we can bench the scanner creation
    c.bench_function("security_headers_scanner_creation", |b| {
        b.iter(|| black_box(SecurityHeadersScanner::new(&config)))
    });
}

criterion_group!(
    benches,
    bench_dom_xss_analysis,
    bench_crawl_target_extraction,
    bench_config_defaults,
    bench_scan_context,
    bench_security_headers_parse,
);
criterion_main!(benches);

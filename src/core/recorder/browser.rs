use super::har::{Har, HarEntryBuilder};
use crate::shared::auth::Cookie;
use crate::shared::error::JackSparrowError;
use playwright_rs::{FulfillOptions, LaunchOptions, Playwright, Route};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Record a browser session to HAR format using Playwright
pub async fn record_session(
    output: &Path,
    browser_type: &str,
    headless: bool,
) -> Result<(), JackSparrowError> {
    println!("Initializing Playwright...");

    let playwright = Playwright::launch()
        .await
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to launch Playwright: {}", e)))?;

    let browser_type_obj = match browser_type {
        "firefox" => playwright.firefox(),
        "webkit" => playwright.webkit(),
        _ => playwright.chromium(),
    };

    println!(
        "Launching {} browser (headless: {})...",
        browser_type, headless
    );

    let opts = LaunchOptions::default().headless(headless);
    let browser = browser_type_obj
        .launch_with_options(opts)
        .await
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to launch browser: {}", e)))?;

    let context = browser
        .new_context()
        .await
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to create context: {}", e)))?;

    let page = context
        .new_page()
        .await
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to create page: {}", e)))?;

    let har = Arc::new(Mutex::new(Har::new()));

    let har_clone = har.clone();
    page.route(
        "**/*",
        Box::new(move |route: Route| {
            let har = har_clone.clone();
            Box::pin(async move {
                let request = route.request();
                let method = request.method().to_string();
                let url = request.url().to_string();

                let headers = request.headers();
                let mut builder = HarEntryBuilder::new(&method, &url);

                for (name, value) in headers.iter() {
                    builder = builder.request_header(name, value);
                }

                let post_data = request.post_data();
                if let Some(ref body) = post_data {
                    builder = builder.request_body(body);
                    if let Some(ct) = headers.get("content-type") {
                        builder = builder.content_type(ct);
                    }
                }

                let start = std::time::Instant::now();
                let response = route.fetch(None).await;
                let duration = start.elapsed().as_secs_f64() * 1000.0;

                match response {
                    Ok(resp) => {
                        let status = resp.status();
                        let resp_headers = resp.headers();

                        builder = builder.status(status).duration_ms(duration);

                        for (name, value) in resp_headers.iter() {
                            builder = builder.response_header(name, value);
                        }

                        let body_bytes = resp.body();
                        let body_text = String::from_utf8_lossy(body_bytes).to_string();
                        builder = builder.response_body(&body_text);

                        for (name, value) in resp_headers.iter() {
                            if name.to_lowercase() == "content-type" {
                                builder = builder.content_type(value);
                            }
                        }

                        let entry = builder.build();
                        har.lock().await.add_entry(entry);

                        let fulfill = FulfillOptions::builder()
                            .status(status)
                            .body(body_bytes.to_vec())
                            .build();
                        route.fulfill(fulfill).await.ok();
                    }
                    Err(_) => {
                        route.continue_(None).await.ok();
                    }
                }

                Ok(())
            })
        }),
    )
    .await
    .map_err(|e| JackSparrowError::Playwright(format!("Failed to set up route: {}", e)))?;

    println!("Navigate to your target URL in the browser.");
    println!("Press Ctrl+C when done recording.");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| JackSparrowError::Playwright(format!("Failed to set Ctrl+C handler: {}", e)))?;

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    println!("\nRecording stopped.");

    let har_data = har.lock().await;
    let json = har_data
        .to_json()
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to serialize HAR: {}", e)))?;

    std::fs::write(output, &json)?;

    let entry_count = har_data.log.entries.as_ref().map(|e| e.len()).unwrap_or(0);
    println!("Saved {} entries to: {}", entry_count, output.display());

    browser
        .close()
        .await
        .map_err(|e| JackSparrowError::Playwright(format!("Failed to close browser: {}", e)))?;

    Ok(())
}

/// Load a HAR file and extract requests for scanning
pub fn load_har_requests(path: &Path) -> Result<Vec<HarRequestInfo>, JackSparrowError> {
    let content = std::fs::read_to_string(path)?;
    let har: Har = serde_json::from_str(&content)?;

    let mut requests = Vec::new();
    if let Some(entries) = har.log.entries {
        for entry in entries {
            requests.push(HarRequestInfo {
                method: entry.request.method,
                url: entry.request.url,
                headers: entry
                    .request
                    .headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
                body: entry.request.postData.map(|pd| pd.text),
                status: entry.response.status,
            });
        }
    }

    Ok(requests)
}

/// Extracted request info from a HAR file
#[derive(Debug, Clone)]
pub struct HarRequestInfo {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub status: u16,
}

/// True when both hostnames identify the same site (dot-prefix and
/// subdomains included: `app.test.com` ↔ `.test.com`).
fn hosts_match(a: &str, b: &str) -> bool {
    let a = a.trim().trim_start_matches('.').to_ascii_lowercase();
    let b = b.trim().trim_start_matches('.').to_ascii_lowercase();
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Merge a HAR `cookies` array into `out`; skips cookies scoped to another
/// domain when the scan target host is known.
fn add_cookie_array(
    cookies: Option<&serde_json::Value>,
    host: Option<&str>,
    out: &mut Vec<(String, String)>,
) {
    let Some(cookies) = cookies.and_then(|c| c.as_array()) else {
        return;
    };
    for cookie in cookies {
        let (Some(name), Some(value)) = (
            cookie.get("name").and_then(|n| n.as_str()),
            cookie.get("value").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if let (Some(h), Some(d)) = (
            host,
            cookie
                .get("domain")
                .and_then(|d| d.as_str())
                .filter(|d| !d.is_empty()),
        ) {
            if !hosts_match(d, h) {
                continue;
            }
        }
        crate::shared::auth::upsert_cookie_pair(out, name, value);
    }
}

/// Load the cookies a recorded session (`sparrow record` → HAR) carries for
/// `host`, ready to be used as a `Cookie` header value.
///
/// Cookies are collected in chronological order — the request cookies of an
/// entry first, then the `Set-Cookie` of its response — so later entries win
/// on name conflicts. Entries for other hosts are skipped (all of them when
/// `host` is `None`, e.g. the target is not a parseable URL).
pub fn load_har_cookies(path: &Path, host: Option<&str>) -> Result<Vec<Cookie>, JackSparrowError> {
    let content = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&content)?;

    let no_entries: Vec<serde_json::Value> = Vec::new();
    let entries = root
        .pointer("/log/entries")
        .and_then(|e| e.as_array())
        .unwrap_or(&no_entries);

    let mut merged: Vec<(String, String)> = Vec::new();

    for entry in entries {
        // Only entries that hit the scan target
        if let Some(h) = host {
            let entry_host = entry
                .pointer("/request/url")
                .and_then(|u| u.as_str())
                .and_then(|u| reqwest::Url::parse(u).ok())
                .and_then(|u| u.host_str().map(str::to_string));
            if let Some(entry_host) = entry_host {
                if !hosts_match(&entry_host, h) {
                    continue;
                }
            }
        }

        // Request-side cookies: the `cookies` array first, then the raw
        // `Cookie` header (some HAR writers only fill the header).
        add_cookie_array(entry.pointer("/request/cookies"), host, &mut merged);
        if let Some(headers) = entry.pointer("/request/headers").and_then(|h| h.as_array()) {
            for header in headers {
                let is_cookie = header
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.eq_ignore_ascii_case("cookie"))
                    .unwrap_or(false);
                if !is_cookie {
                    continue;
                }
                let Some(value) = header.get("value").and_then(|v| v.as_str()) else {
                    continue;
                };
                for cookie in crate::shared::auth::parse_cookie_string(value) {
                    crate::shared::auth::upsert_cookie_pair(
                        &mut merged,
                        &cookie.name,
                        &cookie.value,
                    );
                }
            }
        }
        // Response-side `Set-Cookie`: the freshest state of this entry.
        add_cookie_array(entry.pointer("/response/cookies"), host, &mut merged);
    }

    let domain = host.unwrap_or_default().to_string();
    Ok(merged
        .into_iter()
        .map(|(name, value)| Cookie {
            name,
            value,
            domain: domain.clone(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            expires: None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_har_requests_empty() {
        let har = Har::new();
        let json = har.to_json().unwrap();

        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &json).unwrap();

        let requests = load_har_requests(tmp.path()).unwrap();
        assert!(requests.is_empty());
    }

    #[test]
    fn test_load_har_requests_with_entries() {
        let mut har = Har::new();
        let entry = HarEntryBuilder::new("GET", "http://example.com/api")
            .status(200)
            .request_header("Authorization", "Bearer token123")
            .build();
        har.add_entry(entry);

        let json = har.to_json().unwrap();
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &json).unwrap();

        let requests = load_har_requests(tmp.path()).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, "http://example.com/api");
        assert_eq!(requests[0].status, 200);
        assert_eq!(requests[0].headers.len(), 1);
        assert_eq!(requests[0].headers[0].0, "Authorization");
    }

    fn har_with_entries(entries: serde_json::Value) -> NamedTempFile {
        let json = serde_json::json!({ "log": { "version": "1.2", "creator": { "name": "t", "version": "1" }, "entries": entries } });
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json.to_string()).unwrap();
        tmp
    }

    fn entry(
        url: &str,
        request_cookies: serde_json::Value,
        response_cookies: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "startedDateTime": "2026-10-02T00:00:00Z",
            "time": 1,
            "request": { "method": "GET", "url": url, "cookies": request_cookies,
                         "headers": [] },
            "response": { "status": 200, "cookies": response_cookies, "headers": [],
                          "content": { "size": 0 } }
        })
    }

    #[test]
    fn test_load_har_cookies_filters_by_host_and_overrides() {
        let entries = serde_json::json!([
            // otra app: se ignora
            entry(
                "http://other.local/",
                serde_json::json!([{ "name": "PHPSESSID", "value": "OTHER" }]),
                serde_json::json!([]),
            ),
            // el objetivo: cookie de la petición
            entry(
                "http://localhost:3001/index.php",
                serde_json::json!([
                    { "name": "PHPSESSID", "value": "first" },
                    { "name": "security", "value": "low" }
                ]),
                serde_json::json!([]),
            ),
            // el objetivo: el Set-Cookie de la respuesta gana
            entry(
                "http://localhost:3001/login.php",
                serde_json::json!([]),
                serde_json::json!([{ "name": "PHPSESSID", "value": "fresh" }]),
            ),
        ]);
        let tmp = har_with_entries(entries);

        let cookies = load_har_cookies(tmp.path(), Some("localhost")).unwrap();
        let names: Vec<(&str, &str)> = cookies
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_str()))
            .collect();
        assert_eq!(names, vec![("PHPSESSID", "fresh"), ("security", "low")]);
        assert_eq!(cookies[0].domain, "localhost");
    }

    #[test]
    fn test_load_har_cookies_falls_back_to_cookie_header() {
        let entries = serde_json::json!([{
            "startedDateTime": "2026-10-02T00:00:00Z",
            "time": 1,
            "request": {
                "method": "GET",
                "url": "http://localhost/vulnerabilities/sqli/",
                "cookies": [],
                "headers": [{ "name": "Cookie", "value": "fallback=from-header; other=2" }]
            },
            "response": { "status": 200, "cookies": [], "headers": [],
                          "content": { "size": 0 } }
        }]);
        let tmp = har_with_entries(entries);

        let cookies = load_har_cookies(tmp.path(), Some("localhost")).unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name, "fallback");
        assert_eq!(cookies[0].value, "from-header");
        assert_eq!(cookies[1].name, "other");
    }

    #[test]
    fn test_load_har_cookies_response_wins_over_request_header() {
        let entries = serde_json::json!([{
            "startedDateTime": "2026-10-02T00:00:00Z",
            "time": 1,
            "request": {
                "method": "GET",
                "url": "http://localhost/index.php",
                "cookies": [],
                "headers": [{ "name": "Cookie", "value": "PHPSESSID=stale" }]
            },
            "response": {
                "status": 200,
                "cookies": [{ "name": "PHPSESSID", "value": "fresh", "domain": "localhost" }],
                "headers": [],
                "content": { "size": 0 }
            }
        }]);
        let tmp = har_with_entries(entries);

        let cookies = load_har_cookies(tmp.path(), Some("localhost")).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].value, "fresh");
    }

    #[test]
    fn test_load_har_cookies_no_host_takes_everything() {
        let entries = serde_json::json!([entry(
            "http://anywhere.test/",
            serde_json::json!([{ "name": "sid", "value": "1" }]),
            serde_json::json!([]),
        )]);
        let tmp = har_with_entries(entries);

        let cookies = load_har_cookies(tmp.path(), None).unwrap();
        assert_eq!(cookies.len(), 1);
    }

    #[test]
    fn test_load_har_cookies_missing_file_errors() {
        let err = load_har_cookies(Path::new("no-existe.har"), Some("localhost")).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_hosts_match() {
        assert!(hosts_match("localhost", "localhost"));
        assert!(hosts_match(".dvwa.local", "dvwa.local"));
        assert!(hosts_match("app.test.com", "test.com"));
        assert!(!hosts_match("evil.com", "test.com"));
    }
}

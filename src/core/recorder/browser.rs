use super::har::{Har, HarEntryBuilder};
use crate::shared::error::JackSparrowError;
use playwright_rs::{Playwright, Route, FulfillOptions, LaunchOptions};
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

    let playwright = Playwright::launch().await.map_err(|e| {
        JackSparrowError::Playwright(format!("Failed to launch Playwright: {}", e))
    })?;

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
    .map_err(|e| {
        JackSparrowError::Playwright(format!("Failed to set up route: {}", e))
    })?;

    println!("Navigate to your target URL in the browser.");
    println!("Press Ctrl+C when done recording.");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| {
        JackSparrowError::Playwright(format!("Failed to set Ctrl+C handler: {}", e))
    })?;

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    println!("\nRecording stopped.");

    let har_data = har.lock().await;
    let json = har_data.to_json().map_err(|e| {
        JackSparrowError::Playwright(format!("Failed to serialize HAR: {}", e))
    })?;

    std::fs::write(output, &json)?;

    let entry_count = har_data
        .log
        .entries
        .as_ref()
        .map(|e| e.len())
        .unwrap_or(0);
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
}

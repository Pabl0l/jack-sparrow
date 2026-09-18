#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

/// HAR 1.2 format root structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Har {
    pub log: HarLog,
}

/// HAR log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<HarEntry>>,
}

/// HAR creator info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

/// A single HAR entry (one request/response pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntry {
    pub startedDateTime: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<HarTimings>,
}

/// HAR request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
    #[serde(default)]
    pub headers: Vec<HarNameValuePair>,
    #[serde(default)]
    pub queryString: Vec<HarNameValuePair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postData: Option<HarPostData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headersSize: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bodySize: Option<i64>,
}

/// HAR response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statusText: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
    #[serde(default)]
    pub headers: Vec<HarNameValuePair>,
    pub content: HarContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirectURL: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headersSize: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bodySize: Option<i64>,
}

/// HAR cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarCookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub httpOnly: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sameSite: Option<String>,
}

/// HAR name-value pair (headers, query strings, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValuePair {
    pub name: String,
    pub value: String,
}

/// HAR POST data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarPostData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimeType: Option<String>,
    #[serde(default)]
    pub params: Vec<HarPostDataParam>,
    pub text: String,
}

/// HAR POST data parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarPostDataParam {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fileName: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contentType: Option<String>,
}

/// HAR content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarContent {
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimeType: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// HAR timings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarTimings {
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl: Option<f64>,
}

impl Har {
    /// Create a new empty HAR
    pub fn new() -> Self {
        Self {
            log: HarLog {
                version: "1.2".to_string(),
                creator: HarCreator {
                    name: "Jack Sparrow".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                entries: Some(Vec::new()),
            },
        }
    }

    /// Add an entry
    pub fn add_entry(&mut self, entry: HarEntry) {
        self.log
            .entries
            .as_mut()
            .map(|e| e.push(entry));
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for Har {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating HAR entries
pub struct HarEntryBuilder {
    method: String,
    url: String,
    status: u16,
    request_headers: Vec<HarNameValuePair>,
    response_headers: Vec<HarNameValuePair>,
    request_body: Option<String>,
    response_body: Option<String>,
    content_type: Option<String>,
    started_at: String,
    duration_ms: f64,
}

impl HarEntryBuilder {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            url: url.to_string(),
            status: 0,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            content_type: None,
            started_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: 0.0,
        }
    }

    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    pub fn request_header(mut self, name: &str, value: &str) -> Self {
        self.request_headers.push(HarNameValuePair {
            name: name.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn response_header(mut self, name: &str, value: &str) -> Self {
        self.response_headers.push(HarNameValuePair {
            name: name.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn request_body(mut self, body: &str) -> Self {
        self.request_body = Some(body.to_string());
        self
    }

    pub fn response_body(mut self, body: &str) -> Self {
        self.response_body = Some(body.to_string());
        self
    }

    pub fn content_type(mut self, ct: &str) -> Self {
        self.content_type = Some(ct.to_string());
        self
    }

    pub fn duration_ms(mut self, ms: f64) -> Self {
        self.duration_ms = ms;
        self
    }

    pub fn build(self) -> HarEntry {
        let body_size = self
            .response_body
            .as_ref()
            .map(|b| b.len() as i64)
            .unwrap_or(-1);

        let request_body_size = self
            .request_body
            .as_ref()
            .map(|b| b.len() as i64)
            .unwrap_or(-1);

        HarEntry {
            startedDateTime: self.started_at,
            time: self.duration_ms,
            request: HarRequest {
                method: self.method,
                url: self.url,
                http_version: Some("HTTP/1.1".to_string()),
                cookies: Vec::new(),
                headers: self.request_headers,
                queryString: Vec::new(),
                postData: self.request_body.map(|text| HarPostData {
                    mimeType: self.content_type.clone(),
                    params: Vec::new(),
                    text,
                }),
                headersSize: Some(-1),
                bodySize: Some(request_body_size),
            },
            response: HarResponse {
                status: self.status,
                statusText: Some(status_text(self.status)),
                http_version: Some("HTTP/1.1".to_string()),
                cookies: Vec::new(),
                headers: self.response_headers,
                content: HarContent {
                    size: body_size,
                    mimeType: self.content_type,
                    text: self.response_body,
                    encoding: None,
                },
                redirectURL: None,
                headersSize: Some(-1),
                bodySize: Some(body_size),
            },
            cache: None,
            timings: Some(HarTimings {
                send: 0.0,
                wait: self.duration_ms,
                receive: 0.0,
                blocked: None,
                dns: None,
                connect: None,
                ssl: None,
            }),
        }
    }
}

/// Get human-readable status text
fn status_text(status: u16) -> String {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_har_new() {
        let har = Har::new();
        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.creator.name, "Jack Sparrow");
        assert!(har.log.entries.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_har_entry_builder() {
        let entry = HarEntryBuilder::new("GET", "http://example.com")
            .status(200)
            .request_header("Accept", "text/html")
            .response_header("Content-Type", "text/html")
            .response_body("<html></html>")
            .duration_ms(42.5)
            .build();

        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.request.url, "http://example.com");
        assert_eq!(entry.response.status, 200);
        assert_eq!(entry.time, 42.5);
        assert_eq!(entry.request.headers.len(), 1);
        assert_eq!(entry.response.headers.len(), 1);
        assert_eq!(
            entry.response.content.text,
            Some("<html></html>".to_string())
        );
    }

    #[test]
    fn test_har_json_serialization() {
        let mut har = Har::new();
        let entry = HarEntryBuilder::new("POST", "http://api.test.com/data")
            .status(201)
            .request_body(r#"{"key":"value"}"#)
            .content_type("application/json")
            .build();
        har.add_entry(entry);

        let json = har.to_json().unwrap();
        assert!(json.contains("Jack Sparrow"));
        assert!(json.contains("POST"));
        assert!(json.contains("http://api.test.com/data"));
        assert!(json.contains("201"));
    }
}

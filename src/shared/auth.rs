#![allow(dead_code)]

use crate::shared::context::ScanContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    /// No authentication
    None,
    /// HTTP Basic Auth
    BasicAuth { username: String, password: String },
    /// Bearer token (JWT, API key, etc.)
    BearerToken { token: String },
    /// OAuth 2.0 Client Credentials flow
    OAuth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        scopes: Vec<String>,
    },
    /// OAuth 2.0 Authorization Code flow (for interactive use)
    OAuth2AuthorizationCode {
        auth_url: String,
        token_url: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        scopes: Vec<String>,
    },
    /// Session cookies (from browser export)
    SessionCookies { cookies: Vec<Cookie> },
    /// Custom headers
    CustomHeaders { headers: Vec<(String, String)> },
    /// Form-based login — POST credentials to a login endpoint, extract session cookies.
    FormLogin {
        /// URL of the login form (POST target)
        login_url: String,
        /// Username value
        username: String,
        /// Password value
        password: String,
        /// Form field name for username (default: "username")
        #[serde(default = "default_username_field")]
        username_field: String,
        /// Form field name for password (default: "password")
        #[serde(default = "default_password_field")]
        password_field: String,
        /// Extra form fields to include (e.g., CSRF tokens, hidden fields)
        #[serde(default)]
        extra_fields: Vec<(String, String)>,
        /// String that should appear in response body after successful login
        #[serde(default)]
        success_indicator: Option<String>,
    },
}

fn default_username_field() -> String {
    "username".to_string()
}
fn default_password_field() -> String {
    "password".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expires: Option<String>,
}

/// OAuth 2.0 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(skip)]
    obtained_at: Option<std::time::Instant>,
}

impl OAuthToken {
    pub fn new(response: OAuthTokenResponse) -> Self {
        Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
            refresh_token: response.refresh_token,
            scope: response.scope,
            obtained_at: Some(std::time::Instant::now()),
        }
    }

    /// Check if the token is expired (with 60s buffer)
    pub fn is_expired(&self) -> bool {
        if let Some(expires_in) = self.expires_in {
            if let Some(obtained) = self.obtained_at {
                let elapsed = obtained.elapsed().as_secs();
                return elapsed + 60 >= expires_in;
            }
        }
        false
    }

    /// Get the Authorization header value
    pub fn auth_header(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// OAuth 2.0 Client Credentials manager
pub struct OAuth2Manager {
    config: AuthConfig,
    token: Option<OAuthToken>,
    client: reqwest::Client,
}

impl OAuth2Manager {
    pub fn new(config: AuthConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self {
            config,
            token: None,
            client,
        }
    }

    /// Get a valid access token, refreshing if needed
    pub async fn get_token(&mut self) -> Result<String, String> {
        match &self.config {
            AuthConfig::None => Err("No authentication configured".to_string()),

            AuthConfig::BasicAuth { username, password } => {
                use base64::Engine;
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, password));
                Ok(format!("Basic {}", credentials))
            }

            AuthConfig::BearerToken { token } => Ok(format!("Bearer {}", token)),

            AuthConfig::OAuth2ClientCredentials {
                token_url,
                client_id,
                client_secret,
                scopes,
            } => {
                // Check if we have a valid token
                if let Some(ref token) = self.token {
                    if !token.is_expired() {
                        return Ok(token.auth_header());
                    }
                }

                // Request new token
                let mut params = HashMap::new();
                params.insert("grant_type", "client_credentials");
                params.insert("client_id", client_id.as_str());
                params.insert("client_secret", client_secret.as_str());
                let scope_str;
                if !scopes.is_empty() {
                    scope_str = scopes.join(" ");
                    params.insert("scope", &scope_str);
                }

                let response = self
                    .client
                    .post(token_url)
                    .form(&params)
                    .send()
                    .await
                    .map_err(|e| format!("Token request failed: {}", e))?;

                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(format!("Token request failed ({}): {}", status, body));
                }

                let token_response: OAuthTokenResponse = response
                    .json()
                    .await
                    .map_err(|e| format!("Invalid token response: {}", e))?;

                let token = OAuthToken::new(token_response);
                let auth_header = token.auth_header();
                self.token = Some(token);

                Ok(auth_header)
            }

            AuthConfig::OAuth2AuthorizationCode { .. } => Err(
                "Authorization Code flow requires browser interaction — use record command"
                    .to_string(),
            ),

            AuthConfig::FormLogin { .. } => Err(
                "FormLogin requires FormLoginExecutor — use get_session_cookies() instead"
                    .to_string(),
            ),

            AuthConfig::SessionCookies { cookies } => {
                let cookie_str = cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                Ok(cookie_str)
            }

            AuthConfig::CustomHeaders { headers } => {
                if let Some((_, value)) = headers.first() {
                    Ok(value.clone())
                } else {
                    Err("No custom headers configured".to_string())
                }
            }
        }
    }

    /// Apply authentication to a request builder
    pub async fn apply_auth(
        &mut self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, String> {
        match &self.config {
            AuthConfig::BasicAuth { .. }
            | AuthConfig::BearerToken { .. }
            | AuthConfig::OAuth2ClientCredentials { .. } => {
                let auth_value = self.get_token().await?;
                Ok(request.header("Authorization", auth_value))
            }

            AuthConfig::SessionCookies { cookies } => {
                let cookie_str = cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                Ok(request.header("Cookie", cookie_str))
            }

            AuthConfig::CustomHeaders { headers } => {
                let mut req = request;
                for (key, value) in headers {
                    req = req.header(key.as_str(), value.as_str());
                }
                Ok(req)
            }

            AuthConfig::None => Ok(request),

            AuthConfig::OAuth2AuthorizationCode { .. } => {
                Err("Authorization Code flow not supported in scanner mode".to_string())
            }

            AuthConfig::FormLogin { .. } => Err(
                "FormLogin requires FormLoginExecutor — use get_session_cookies() instead"
                    .to_string(),
            ),
        }
    }

    /// Build a Reqwest client with auth headers pre-configured
    pub async fn build_client(&mut self) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true);

        match &self.config {
            AuthConfig::None => {}

            AuthConfig::SessionCookies { cookies } => {
                let cookie_store = reqwest::cookie::Jar::default();
                for cookie in cookies {
                    let cookie_str = format!(
                        "{}={}; Domain={}; Path={}",
                        cookie.name, cookie.value, cookie.domain, cookie.path
                    );
                    if let Ok(url) = format!("https://{}", cookie.domain).parse() {
                        cookie_store.add_cookie_str(&cookie_str, &url);
                    }
                }
                builder = builder.cookie_provider(std::sync::Arc::new(cookie_store));
            }

            _ => {}
        }

        builder
            .build()
            .map_err(|e| format!("Failed to build client: {}", e))
    }
}

/// Form-based login executor.
///
/// Performs the standard web login flow:
/// 1. GET login page → extract cookies + hidden fields (CSRF tokens)
/// 2. POST credentials → extract session cookies from Set-Cookie
/// 3. Return session cookies for use in ScanContext
pub struct FormLoginExecutor {
    client: reqwest::Client,
}

impl Default for FormLoginExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl FormLoginExecutor {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Execute form login and return session cookies as a cookie string.
    pub async fn login(&self, config: &AuthConfig) -> Result<String, String> {
        let (
            login_url,
            username,
            password,
            username_field,
            password_field,
            extra_fields,
            success_indicator,
        ) = match config {
            AuthConfig::FormLogin {
                login_url,
                username,
                password,
                username_field,
                password_field,
                extra_fields,
                success_indicator,
            } => (
                login_url,
                username,
                password,
                username_field.as_str(),
                password_field.as_str(),
                extra_fields,
                success_indicator.as_deref(),
            ),
            _ => return Err("Not a FormLogin config".to_string()),
        };

        // Phase 1: GET the login page to discover form fields and initial cookies
        let resp = self
            .client
            .get(login_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch login page: {}", e))?;

        let status = resp.status();
        // Keep the GET headers: many stacks (PHP/DVWA) issue the session cookie
        // here, on session start, and never repeat it on the login POST.
        let get_headers = resp.headers().clone();
        let html = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(format!("Login page returned HTTP {}", status));
        }

        // Phase 2: Build form body — start with extra_fields, then add username/password
        let mut form: Vec<(&str, &str)> = Vec::new();

        // Parse hidden fields from HTML (name="..." value="...")
        let hidden_fields = Self::parse_hidden_fields(&html);
        for (name, value) in &hidden_fields {
            // Don't add if already in extra_fields
            if !extra_fields.iter().any(|(k, _)| k == name) {
                form.push((name.as_str(), value.as_str()));
            }
        }

        // Add explicit extra fields
        for (name, value) in extra_fields {
            form.push((name.as_str(), value.as_str()));
        }

        // Add credentials
        form.push((username_field, username.as_str()));
        form.push((password_field, password.as_str()));

        // Phase 3: POST credentials — capture Set-Cookie headers from response
        let resp = self
            .client
            .post(login_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("Login POST failed: {}", e))?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();

        // Phase 4: Validate success
        if let Some(indicator) = success_indicator {
            if !body.contains(indicator) {
                return Err(format!(
                    "Login may have failed: success indicator '{}' not found in response (HTTP {})",
                    indicator, status
                ));
            }
        }

        // Phase 5: Extract cookies from GET (session bootstrap) + POST Set-Cookie.
        // POST wins on name conflicts — it is the freshest state.
        let mut cookie_pairs: Vec<(String, String)> = Vec::new();
        collect_set_cookies(&get_headers, &mut cookie_pairs);
        collect_set_cookies(&resp_headers, &mut cookie_pairs);

        // Check for common auth failure patterns
        let body_lower = body.to_lowercase();
        if body_lower.contains("invalid credentials")
            || body_lower.contains("login failed")
            || body_lower.contains("incorrect password")
            || body_lower.contains("wrong password")
        {
            return Err(
                "Login appears to have failed: detected error message in response".to_string(),
            );
        }

        if cookie_pairs.is_empty() {
            return Err(
                "Login completed but no session cookies were found in response".to_string(),
            );
        }

        // Build cookie string: "name1=value1; name2=value2"
        let cookie_str = cookie_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");

        Ok(cookie_str)
    }

    /// Parse hidden input fields from HTML: <input type="hidden" name="X" value="Y">
    fn parse_hidden_fields(html: &str) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        // Find all <input ...> or <input .../> tags
        for tag in Self::extract_input_tags(html) {
            let tag_lower = tag.to_lowercase();

            // Only process hidden inputs
            if !tag_lower.contains("type=\"hidden\"") && !tag_lower.contains("type='hidden'") {
                continue;
            }

            // Extract name and value attributes
            let name = Self::extract_attr(&tag, "name");
            let value = Self::extract_attr(&tag, "value");

            if let (Some(n), Some(v)) = (name, value) {
                fields.push((n, v));
            }
        }

        fields
    }

    /// Extract all <input ...> tags from HTML.
    fn extract_input_tags(html: &str) -> Vec<String> {
        let mut tags = Vec::new();
        let lower = html.to_lowercase();
        let mut search_from = 0;

        while let Some(pos) = lower[search_from..].find("<input") {
            let abs_start = search_from + pos;
            // Find the closing > or />
            if let Some(end) = html[abs_start..].find('>') {
                let tag = html[abs_start..=abs_start + end].to_string();
                tags.push(tag);
                search_from = abs_start + end + 1;
            } else {
                break;
            }
        }

        tags
    }

    /// Extract an attribute value from an HTML tag string.
    /// Handles both `name="value"` and `name='value'`.
    fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
        let lower = tag.to_lowercase();
        let attr_lower = format!("{}=", attr_name.to_lowercase());

        // Find the attribute
        let pos = lower.find(&attr_lower)?;
        let after_attr = &tag[pos + attr_name.len() + 1..]; // skip "attr="

        // Skip whitespace
        let after_attr = after_attr.trim_start();

        // Get the quote character
        let quote = after_attr.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }

        // Find the closing quote
        let value_start = 1; // skip opening quote
        let value_end = after_attr[value_start..].find(quote)?;
        Some(after_attr[value_start..value_start + value_end].to_string())
    }

    /// Execute login and return a ready-to-use ScanContext.
    pub async fn login_to_context(&self, config: &AuthConfig) -> Result<ScanContext, String> {
        let cookie_str = self.login(config).await?;

        Ok(ScanContext {
            cookies: if cookie_str.is_empty() {
                None
            } else {
                Some(cookie_str)
            },
            headers: Vec::new(),
            session: None,
        })
    }
}

/// Quick helper: perform form login and return cookies as string.
///
/// This is the primary entry point for CLI and test usage.
pub async fn form_login(
    login_url: &str,
    username: &str,
    password: &str,
    username_field: &str,
    password_field: &str,
    extra_fields: &[(String, String)],
    success_indicator: Option<&str>,
) -> Result<String, String> {
    let config = AuthConfig::FormLogin {
        login_url: login_url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        username_field: username_field.to_string(),
        password_field: password_field.to_string(),
        extra_fields: extra_fields.to_vec(),
        success_indicator: success_indicator.map(|s| s.to_string()),
    };

    let executor = FormLoginExecutor::new();
    executor.login(&config).await
}

/// Parse cookies from a cookie string (e.g., "PHPSESSID=abc123; security=low")
pub fn parse_cookie_string(cookie_str: &str) -> Vec<Cookie> {
    cookie_str
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if let Some((name, value)) = part.split_once('=') {
                Some(Cookie {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                    domain: String::new(),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                    expires: None,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Collect `Set-Cookie` headers into `(name, value)` pairs.
/// Later values replace earlier ones with the same name (in place, order kept).
pub fn collect_set_cookies(headers: &reqwest::header::HeaderMap, out: &mut Vec<(String, String)>) {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        if name != "set-cookie" {
            continue;
        }
        let Ok(cookie_val) = value.to_str() else {
            continue;
        };
        // "name=value; Path=/; HttpOnly" → name, value (before the first ';')
        let Some((cookie_name, rest)) = cookie_val.split_once('=') else {
            continue;
        };
        let cookie_name = cookie_name.trim();
        let cookie_value = rest.split(';').next().unwrap_or("").trim();
        if cookie_name.is_empty() {
            continue;
        }
        pairs.push((cookie_name.to_string(), cookie_value.to_string()));
    }
    collect_pairs(&pairs, out);
}

/// Merge two cookie strings. Pairs from `incoming` win on name conflicts,
/// the relative order of `base` is preserved. `None` if nothing remains.
pub fn merge_cookie_strings(base: Option<&str>, incoming: Option<&str>) -> Option<String> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for src in [base, incoming].into_iter().flatten() {
        let pairs: Vec<(String, String)> = parse_cookie_string(src)
            .into_iter()
            .map(|c| (c.name, c.value))
            .collect();
        collect_pairs(&pairs, &mut merged);
    }
    if merged.is_empty() {
        return None;
    }
    Some(
        merged
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Insert or replace a `(name, value)` pair, keeping first-seen order.
pub fn upsert_cookie_pair(out: &mut Vec<(String, String)>, name: &str, value: &str) {
    match out.iter_mut().find(|(n, _)| n == name) {
        Some(slot) => slot.1 = value.to_string(),
        None => out.push((name.to_string(), value.to_string())),
    }
}

/// Push `(name, value)` pairs into `out`, replacing existing names in place.
fn collect_pairs(pairs: &[(String, String)], out: &mut Vec<(String, String)>) {
    for (name, value) in pairs {
        upsert_cookie_pair(out, name, value);
    }
}

/// Render cookies as a `Cookie` header value: `name1=value1; name2=value2`.
pub fn cookies_to_string(cookies: &[Cookie]) -> Option<String> {
    if cookies.is_empty() {
        return None;
    }
    Some(
        cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Parse cookies from a HAR file's cookie array
pub fn parse_har_cookies(cookies: &[serde_json::Value], domain: &str) -> Vec<Cookie> {
    cookies
        .iter()
        .filter_map(|c| {
            let name = c.get("name")?.as_str()?;
            let value = c.get("value")?.as_str()?;
            Some(Cookie {
                name: name.to_string(),
                value: value.to_string(),
                domain: domain.to_string(),
                path: c
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("/")
                    .to_string(),
                secure: c.get("secure").and_then(|s| s.as_bool()).unwrap_or(false),
                http_only: c.get("httpOnly").and_then(|h| h.as_bool()).unwrap_or(false),
                expires: c
                    .get("expires")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_none() {
        let config = AuthConfig::None;
        let manager = OAuth2Manager::new(config);
        assert!(matches!(manager.config, AuthConfig::None));
    }

    #[test]
    fn test_basic_auth() {
        let config = AuthConfig::BasicAuth {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        let mut manager = OAuth2Manager::new(config);
        let token = tokio_test::block_on(manager.get_token()).unwrap();
        assert!(token.starts_with("Basic "));
    }

    #[test]
    fn test_bearer_token() {
        let config = AuthConfig::BearerToken {
            token: "my-jwt-token".to_string(),
        };
        let mut manager = OAuth2Manager::new(config);
        let token = tokio_test::block_on(manager.get_token()).unwrap();
        assert_eq!(token, "Bearer my-jwt-token");
    }

    #[test]
    fn test_session_cookies() {
        let config = AuthConfig::SessionCookies {
            cookies: vec![
                Cookie {
                    name: "PHPSESSID".to_string(),
                    value: "abc123".to_string(),
                    domain: "test.com".to_string(),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                    expires: None,
                },
                Cookie {
                    name: "security".to_string(),
                    value: "low".to_string(),
                    domain: "test.com".to_string(),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                    expires: None,
                },
            ],
        };
        let mut manager = OAuth2Manager::new(config);
        let token = tokio_test::block_on(manager.get_token()).unwrap();
        assert!(token.contains("PHPSESSID=abc123"));
        assert!(token.contains("security=low"));
    }

    #[test]
    fn test_custom_headers() {
        let config = AuthConfig::CustomHeaders {
            headers: vec![
                ("X-API-Key".to_string(), "secret-key".to_string()),
                ("X-Custom".to_string(), "value".to_string()),
            ],
        };
        let mut manager = OAuth2Manager::new(config);
        let token = tokio_test::block_on(manager.get_token()).unwrap();
        assert_eq!(token, "secret-key");
    }

    #[test]
    fn test_parse_cookie_string() {
        let cookies = parse_cookie_string("PHPSESSID=abc123; security=low; lang=en");
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies[0].name, "PHPSESSID");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[1].name, "security");
        assert_eq!(cookies[1].value, "low");
    }

    #[test]
    fn test_parse_empty_cookie_string() {
        let cookies = parse_cookie_string("");
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_oauth_token_expiry() {
        let token = OAuthToken {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            obtained_at: Some(std::time::Instant::now()),
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn test_oauth_token_expired() {
        let token = OAuthToken {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(0), // Already expired
            refresh_token: None,
            scope: None,
            obtained_at: Some(std::time::Instant::now()),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn test_oauth_token_no_expiry() {
        let token = OAuthToken {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            obtained_at: None,
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn test_form_login_config_serialization() {
        let config = AuthConfig::FormLogin {
            login_url: "http://localhost/login".to_string(),
            username: "admin".to_string(),
            password: "pass123".to_string(),
            username_field: "user".to_string(),
            password_field: "pass".to_string(),
            extra_fields: vec![("csrf".to_string(), "token123".to_string())],
            success_indicator: Some("Welcome".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("FormLogin"));
        assert!(json.contains("login_url"));
        assert!(json.contains("admin"));
    }

    #[test]
    fn test_form_login_config_defaults() {
        let json = r#"{"type":"FormLogin","login_url":"http://test.com/login","username":"u","password":"p"}"#;
        let config: AuthConfig = serde_json::from_str(json).unwrap();
        if let AuthConfig::FormLogin {
            username_field,
            password_field,
            ..
        } = config
        {
            assert_eq!(username_field, "username");
            assert_eq!(password_field, "password");
        } else {
            panic!("Expected FormLogin");
        }
    }

    #[test]
    fn test_parse_hidden_fields_basic() {
        let html = r#"
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="hidden" name="_token" value="xyz789">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Login</button>
        </div>
        "#;
        let fields = FormLoginExecutor::parse_hidden_fields(html);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "csrf_token");
        assert_eq!(fields[0].1, "abc123");
        assert_eq!(fields[1].0, "_token");
        assert_eq!(fields[1].1, "xyz789");
    }

    #[test]
    fn test_parse_hidden_fields_empty() {
        let html = "<form><input type='text' name='user'></form>";
        let fields = FormLoginExecutor::parse_hidden_fields(html);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_parse_hidden_fields_single_quotes() {
        let html = r#"<input type='hidden' name='token' value='secret'>"#;
        let fields = FormLoginExecutor::parse_hidden_fields(html);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "token");
        assert_eq!(fields[0].1, "secret");
    }

    #[test]
    fn test_parse_hidden_fields_no_value() {
        let html = r#"<input type="hidden" name="token">"#;
        let fields = FormLoginExecutor::parse_hidden_fields(html);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_form_login_config_from_json_minimal() {
        let json = r#"{"type":"FormLogin","login_url":"http://dvwa/login.php","username":"admin","password":"password"}"#;
        let config: AuthConfig = serde_json::from_str(json).unwrap();
        match config {
            AuthConfig::FormLogin {
                login_url,
                username,
                password,
                extra_fields,
                success_indicator,
                ..
            } => {
                assert_eq!(login_url, "http://dvwa/login.php");
                assert_eq!(username, "admin");
                assert_eq!(password, "password");
                assert!(extra_fields.is_empty());
                assert!(success_indicator.is_none());
            }
            _ => panic!("Expected FormLogin"),
        }
    }

    #[test]
    fn test_collect_set_cookies_merges_get_then_post() {
        let mut get = reqwest::header::HeaderMap::new();
        get.append(
            reqwest::header::SET_COOKIE,
            "PHPSESSID=abc123; Path=/".parse().unwrap(),
        );
        get.append(
            reqwest::header::SET_COOKIE,
            "security=low; Path=/".parse().unwrap(),
        );
        let mut post = reqwest::header::HeaderMap::new();
        post.append(
            reqwest::header::SET_COOKIE,
            "PHPSESSID=zzz; Path=/".parse().unwrap(),
        );

        let mut out: Vec<(String, String)> = Vec::new();
        collect_set_cookies(&get, &mut out);
        collect_set_cookies(&post, &mut out);

        // El POST manda sobre el GET; las cookies nuevas se conservan.
        assert_eq!(
            out,
            vec![
                ("PHPSESSID".to_string(), "zzz".to_string()),
                ("security".to_string(), "low".to_string()),
            ]
        );
    }

    #[test]
    fn test_collect_set_cookies_ignores_garbage() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            "novalue-without-equals".parse().unwrap(),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            "=orphan; Path=/".parse().unwrap(),
        );
        let mut out: Vec<(String, String)> = Vec::new();
        collect_set_cookies(&headers, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn test_merge_cookie_strings_incoming_wins() {
        let merged =
            merge_cookie_strings(Some("PHPSESSID=old; security=low"), Some("PHPSESSID=new"));
        assert_eq!(merged.as_deref(), Some("PHPSESSID=new; security=low"));
    }

    #[test]
    fn test_merge_cookie_strings_empty_cases() {
        assert_eq!(merge_cookie_strings(None, None), None);
        assert_eq!(merge_cookie_strings(Some(""), Some("")), None);
        assert_eq!(
            merge_cookie_strings(None, Some("a=b")),
            Some("a=b".to_string())
        );
        assert_eq!(
            merge_cookie_strings(Some("a=b"), None),
            Some("a=b".to_string())
        );
    }

    #[test]
    fn test_cookies_to_string() {
        let cookies = parse_cookie_string("PHPSESSID=abc; security=low");
        assert_eq!(
            cookies_to_string(&cookies).as_deref(),
            Some("PHPSESSID=abc; security=low")
        );
        assert_eq!(cookies_to_string(&[]), None);
    }

    /// Read one HTTP/1.x request (head + body) from the stream.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<(String, String, String)> {
        use tokio::io::AsyncReadExt;
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let content_length = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < head_end + content_length {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let method = head.split_whitespace().next().unwrap_or("").to_string();
        let end = buf.len().min(head_end + content_length);
        let body = String::from_utf8_lossy(&buf[head_end..end]).to_string();
        Some((method, head, body))
    }

    /// `FormLoginExecutor` debe conservar el `PHPSESSID` emitido en el GET
    /// aunque el POST no repita `Set-Cookie` (típico en PHP/DVWA).
    #[tokio::test]
    async fn test_form_login_keeps_get_session_cookie() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let post_seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let post_seen_task = post_seen.clone();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let Some((method, _head, body)) = read_request(&mut stream).await else {
                    return;
                };
                if method == "GET" {
                    let html = r#"<form action="/login.php"><input type="hidden" name="user_token" value="tok123"><input name="username"><input name="password"></form>"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: PHPSESSID=abc123; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        html.len(),
                        html
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                } else {
                    *post_seen_task.lock().unwrap() = body;
                    let html = "<html>Welcome</html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        html.len(),
                        html
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
                let _ = stream.shutdown().await;
            }
        });

        let config = AuthConfig::FormLogin {
            login_url: format!("http://{addr}/login.php"),
            username: "admin".to_string(),
            password: "password".to_string(),
            username_field: "username".to_string(),
            password_field: "password".to_string(),
            extra_fields: Vec::new(),
            success_indicator: None,
        };

        let executor = FormLoginExecutor::new();
        let login = executor.login(&config);
        let cookies = tokio::time::timeout(std::time::Duration::from_secs(20), login)
            .await
            .expect("login timed out")
            .expect("login should succeed");

        server.await.expect("server task panicked");

        // Cookie de sesión del GET conservada (¡aunque el POST no la repita!)
        assert_eq!(cookies, "PHPSESSID=abc123");

        let seen = post_seen.lock().unwrap().clone();
        assert!(seen.contains("username=admin"), "body: {seen}");
        // El campo oculto de la página se descubrió y se envió
        assert!(seen.contains("user_token=tok123"), "body: {seen}");
    }
}

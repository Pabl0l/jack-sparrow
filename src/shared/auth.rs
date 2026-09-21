#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    /// No authentication
    None,
    /// HTTP Basic Auth
    BasicAuth {
        username: String,
        password: String,
    },
    /// Bearer token (JWT, API key, etc.)
    BearerToken {
        token: String,
    },
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
    SessionCookies {
        cookies: Vec<Cookie>,
    },
    /// Custom headers
    CustomHeaders {
        headers: Vec<(String, String)>,
    },
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

            AuthConfig::OAuth2AuthorizationCode { .. } => {
                Err("Authorization Code flow requires browser interaction — use record command".to_string())
            }

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
            AuthConfig::BasicAuth { .. } | AuthConfig::BearerToken { .. } | AuthConfig::OAuth2ClientCredentials { .. } => {
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
                    let cookie_str = format!("{}={}; Domain={}; Path={}", cookie.name, cookie.value, cookie.domain, cookie.path);
                    if let Ok(url) = format!("https://{}", cookie.domain).parse() {
                        cookie_store.add_cookie_str(&cookie_str, &url);
                    }
                }
                builder = builder.cookie_provider(std::sync::Arc::new(cookie_store));
            }

            _ => {}
        }

        builder.build().map_err(|e| format!("Failed to build client: {}", e))
    }
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

/// Parse cookies from a HAR file's cookie array
pub fn parse_har_cookies(
    cookies: &[serde_json::Value],
    domain: &str,
) -> Vec<Cookie> {
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
                secure: c
                    .get("secure")
                    .and_then(|s| s.as_bool())
                    .unwrap_or(false),
                http_only: c
                    .get("httpOnly")
                    .and_then(|h| h.as_bool())
                    .unwrap_or(false),
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
}

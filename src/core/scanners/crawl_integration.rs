#![allow(dead_code)]

use crate::core::crawler::engine::{CrawlResults, CrawledPage};
use crate::core::crawler::parser::{DiscoveredForm, Method};
use crate::core::scanners::ScannerType;
use url::Url;

/// A target extracted from crawl results for scanning.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    /// The URL to test.
    pub url: Url,
    /// HTTP method to use.
    pub method: Method,
    /// Parameters to test.
    pub params: Vec<ScanParam>,
    /// Source page where this target was found.
    pub source_url: Option<String>,
    /// Type of target.
    pub target_type: TargetType,
    /// Depth in the crawl tree.
    pub depth: u32,
}

/// A parameter to test.
#[derive(Debug, Clone)]
pub struct ScanParam {
    /// Parameter name.
    pub name: String,
    /// Parameter type (query, body, cookie, header).
    pub param_type: ParamType,
    /// Current value (if any).
    pub value: Option<String>,
    /// Whether this is a hidden field.
    pub is_hidden: bool,
}

/// Type of parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    /// URL query parameter (?key=value).
    Query,
    /// Form body parameter (POST data).
    Body,
    /// Hidden form field.
    Hidden,
    /// Path parameter (/users/{id}).
    Path,
}

/// Type of scan target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetType {
    /// A URL with query parameters.
    UrlWithParams,
    /// A form that can be submitted.
    Form,
    /// An API endpoint (JSON/XML).
    ApiEndpoint,
    /// A page with inline scripts.
    PageWithScripts,
    /// A page with iframes.
    PageWithIframes,
    /// A page with embedded content.
    PageWithEmbeds,
}

/// Extracts scan targets from crawl results.
pub struct CrawlTargetExtractor;

impl CrawlTargetExtractor {
    /// Extract all scan targets from crawl results.
    pub fn extract_targets(results: &CrawlResults) -> Vec<ScanTarget> {
        let mut targets = Vec::new();

        for page in &results.pages {
            // Extract URL parameters
            Self::extract_url_params(page, &mut targets);

            // Extract form targets
            if let Some(ref parsed) = page.parsed {
                for form in &parsed.forms {
                    Self::extract_form_target(page, form, &mut targets);
                }

                // Extract pages with inline scripts (for DOM XSS)
                if !parsed.inline_scripts.is_empty() {
                    targets.push(ScanTarget {
                        url: page.url.clone(),
                        method: Method::Get,
                        params: Vec::new(),
                        source_url: Some(page.url.to_string()),
                        target_type: TargetType::PageWithScripts,
                        depth: page.depth,
                    });
                }

                // Extract pages with iframes
                if !parsed.iframes.is_empty() {
                    targets.push(ScanTarget {
                        url: page.url.clone(),
                        method: Method::Get,
                        params: Vec::new(),
                        source_url: Some(page.url.to_string()),
                        target_type: TargetType::PageWithIframes,
                        depth: page.depth,
                    });
                }

                // Extract pages with embeds
                if !parsed.embeds.is_empty() {
                    targets.push(ScanTarget {
                        url: page.url.clone(),
                        method: Method::Get,
                        params: Vec::new(),
                        source_url: Some(page.url.to_string()),
                        target_type: TargetType::PageWithEmbeds,
                        depth: page.depth,
                    });
                }
            }
        }

        targets
    }

    /// Extract URL parameters from a page.
    fn extract_url_params(page: &CrawledPage, targets: &mut Vec<ScanTarget>) {
        if let Some(query) = page.url.query() {
            let params: Vec<ScanParam> = query
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let name = parts.next()?.to_string();
                    let value = parts.next().map(String::from);
                    Some(ScanParam {
                        name,
                        param_type: ParamType::Query,
                        value,
                        is_hidden: false,
                    })
                })
                .collect();

            if !params.is_empty() {
                targets.push(ScanTarget {
                    url: page.url.clone(),
                    method: Method::Get,
                    params,
                    source_url: Some(page.url.to_string()),
                    target_type: TargetType::UrlWithParams,
                    depth: page.depth,
                });
            }
        }
    }

    /// Extract form target from a discovered form.
    fn extract_form_target(
        page: &CrawledPage,
        form: &DiscoveredForm,
        targets: &mut Vec<ScanTarget>,
    ) {
        let params: Vec<ScanParam> = form
            .inputs
            .iter()
            .map(|input| ScanParam {
                name: input.name.clone(),
                param_type: if input.input_type == "hidden" {
                    ParamType::Hidden
                } else {
                    ParamType::Body
                },
                value: input.value.clone(),
                is_hidden: input.input_type == "hidden",
            })
            .collect();

        if !params.is_empty() {
            targets.push(ScanTarget {
                url: form.action.clone(),
                method: form.method.clone(),
                params,
                source_url: Some(page.url.to_string()),
                target_type: TargetType::Form,
                depth: page.depth,
            });
        }
    }

    /// Filter targets for a specific scanner type.
    pub fn targets_for_scanner(targets: &[ScanTarget], scanner: ScannerType) -> Vec<&ScanTarget> {
        match scanner {
            ScannerType::SqlInjection => {
                // SQLi: URLs with params and forms
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::Form
                    })
                    .collect()
            }
            ScannerType::Xss => {
                // XSS: Forms and URLs with params (reflected)
                // DOM XSS: pages with inline scripts
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::Form
                            || t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::PageWithScripts
                    })
                    .collect()
            }
            ScannerType::XssStored => {
                // Stored XSS: Forms that submit data to the server
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::Form
                    })
                    .collect()
            }
            ScannerType::XssDom => {
                // DOM XSS: Pages with inline scripts
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::PageWithScripts
                    })
                    .collect()
            }
            ScannerType::Idor => {
                // IDOR: API endpoints and URLs with IDs
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::ApiEndpoint
                            || t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::Form
                    })
                    .collect()
            }
            ScannerType::Ssrf => {
                // SSRF: URLs with URL parameters
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::Form
                    })
                    .filter(|t| {
                        t.params.iter().any(|p| {
                            let name = p.name.to_lowercase();
                            name.contains("url")
                                || name.contains("link")
                                || name.contains("redirect")
                                || name.contains("callback")
                                || name.contains("webhook")
                                || name.contains("feed")
                                || name.contains("uri")
                        })
                    })
                    .collect()
            }
            ScannerType::SecurityHeaders => {
                // Headers: all pages
                targets
                    .iter()
                    .filter(|t| t.depth == 0) // Only root pages
                    .collect()
            }
            ScannerType::TechFingerprint => {
                // Tech: all pages
                targets
                    .iter()
                    .filter(|t| t.depth == 0) // Only root pages
                    .collect()
            }
            ScannerType::Secrets => {
                // Secrets: all pages
                targets.iter().collect()
            }
            ScannerType::SupplyChain => {
                // Supply chain: pages with scripts
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::PageWithScripts
                            || t.target_type == TargetType::PageWithEmbeds
                    })
                    .collect()
            }
            ScannerType::SubdomainEnum => {
                // Subdomain enum: only root page
                targets
                    .iter()
                    .filter(|t| t.depth == 0)
                    .collect()
            }
            ScannerType::WafDetection => {
                // WAF: only root page
                targets
                    .iter()
                    .filter(|t| t.depth == 0)
                    .collect()
            }
            ScannerType::JwtAnalysis => {
                // JWT: all pages (check cookies/headers)
                targets.iter().collect()
            }
            ScannerType::GraphQLIntrospection => {
                // GraphQL: only root page
                targets
                    .iter()
                    .filter(|t| t.depth == 0)
                    .collect()
            }
            ScannerType::ApiSecurity => {
                // API Security: all pages
                targets.iter().collect()
            }
            ScannerType::CloudMetadata => {
                // Cloud metadata: only root page
                targets
                    .iter()
                    .filter(|t| t.depth == 0)
                    .collect()
            }
            ScannerType::Xxe => {
                // XXE: URLs with params and forms (XML endpoints)
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::Form
                            || t.target_type == TargetType::ApiEndpoint
                    })
                    .collect()
            }
            ScannerType::Ssti => {
                // SSTI: URLs with params and forms
                targets
                    .iter()
                    .filter(|t| {
                        t.target_type == TargetType::UrlWithParams
                            || t.target_type == TargetType::Form
                    })
                    .collect()
            }
        }
    }

    /// Convert scan targets to URL strings for scanners.
    pub fn targets_to_urls(targets: &[&ScanTarget]) -> Vec<String> {
        targets
            .iter()
            .map(|t| {
                if t.params.is_empty() {
                    t.url.to_string()
                } else {
                    let query: Vec<String> = t
                        .params
                        .iter()
                        .filter(|p| p.param_type == ParamType::Query)
                        .map(|p| {
                            format!(
                                "{}={}",
                                p.name,
                                p.value.as_deref().unwrap_or("test")
                            )
                        })
                        .collect();

                    if query.is_empty() {
                        t.url.to_string()
                    } else {
                        format!("{}?{}", t.url.as_str().split('?').next().unwrap_or(""), query.join("&"))
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crawler::engine::CrawlResults;
    use crate::core::crawler::parser::{ParsedPage, DiscoveredForm, FormInput, Method};
    use std::collections::HashMap;

    fn make_form(action: &str, method: Method, inputs: Vec<FormInput>) -> DiscoveredForm {
        DiscoveredForm {
            action: Url::parse(action).unwrap(),
            method,
            inputs,
            enctype: None,
            id: None,
            name: None,
            onsubmit: None,
            looks_like_auth: false,
        }
    }

    fn make_page_with_form(url: &str, form: DiscoveredForm) -> CrawledPage {
        let parsed = ParsedPage {
            url: Url::parse(url).unwrap(),
            title: String::new(),
            links: vec![],
            forms: vec![form],
            scripts: vec![],
            inline_scripts: vec![],
            meta: HashMap::new(),
            images: vec![],
            canonical: None,
            description: None,
            generator: None,
            iframes: vec![],
            embeds: vec![],
            link_tags: vec![],
            base_tag: None,
            meta_refresh: None,
            event_handlers: vec![],
            media: vec![],
            has_noscript: false,
            hidden_inputs: vec![],
            data_attributes_count: 0,
        };

        CrawledPage {
            url: Url::parse(url).unwrap(),
            status: 200,
            parsed: Some(parsed),
            fetch_time_ms: 100,
            body_size: 1024,
            depth: 0,
        }
    }

    fn make_page_with_query(url: &str) -> CrawledPage {
        CrawledPage {
            url: Url::parse(url).unwrap(),
            status: 200,
            parsed: None,
            fetch_time_ms: 100,
            body_size: 1024,
            depth: 0,
        }
    }

    #[test]
    fn extract_url_params() {
        let page = make_page_with_query("http://example.com/search?q=test&page=1");
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].params.len(), 2);
        assert_eq!(targets[0].target_type, TargetType::UrlWithParams);
    }

    #[test]
    fn extract_form_target() {
        let form = make_form(
            "http://example.com/login",
            Method::Post,
            vec![
                FormInput {
                    name: "username".to_string(),
                    input_type: "text".to_string(),
                    value: None,
                    required: true,
                    id: None,
                    maxlength: None,
                },
                FormInput {
                    name: "password".to_string(),
                    input_type: "password".to_string(),
                    value: None,
                    required: true,
                    id: None,
                    maxlength: None,
                },
            ],
        );

        let page = make_page_with_form("http://example.com", form);
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_type, TargetType::Form);
        assert_eq!(targets[0].params.len(), 2);
    }

    #[test]
    fn filter_targets_for_sqli() {
        let form = make_form(
            "http://example.com/search",
            Method::Get,
            vec![FormInput {
                name: "q".to_string(),
                input_type: "text".to_string(),
                value: None,
                required: false,
                id: None,
                maxlength: None,
            }],
        );

        let page = make_page_with_form("http://example.com", form);
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        let sqli_targets = CrawlTargetExtractor::targets_for_scanner(&targets, ScannerType::SqlInjection);
        assert_eq!(sqli_targets.len(), 1);
    }

    #[test]
    fn filter_targets_for_ssrf_only_url_params() {
        let page = make_page_with_query("http://example.com/fetch?url=http://evil.com");
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        let ssrf_targets = CrawlTargetExtractor::targets_for_scanner(&targets, ScannerType::Ssrf);
        assert_eq!(ssrf_targets.len(), 1);
    }

    #[test]
    fn ssrf_filter_ignores_non_url_params() {
        let page = make_page_with_query("http://example.com/search?q=test");
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        let ssrf_targets = CrawlTargetExtractor::targets_for_scanner(&targets, ScannerType::Ssrf);
        assert_eq!(ssrf_targets.len(), 0);
    }

    #[test]
    fn targets_to_urls_converts_correctly() {
        let page = make_page_with_query("http://example.com/search?q=test&page=1");
        let results = CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![page],
            stats: Default::default(),
            errors: vec![],
        };

        let targets = CrawlTargetExtractor::extract_targets(&results);
        let refs: Vec<&ScanTarget> = targets.iter().collect();
        let urls = CrawlTargetExtractor::targets_to_urls(&refs);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("q=test"));
    }
}

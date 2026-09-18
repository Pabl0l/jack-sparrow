use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;

// ─────────────────────────────────────────────
//  Link types
// ─────────────────────────────────────────────

/// Context describing where a link was found in the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkContext {
    Navigation,
    FormAction,
    Script,
    Stylesheet,
    Image,
    Iframe,
    Object,
    Embed,
    Video,
    Audio,
    Source,
    MetaRefresh,
    Other,
}

/// A discovered link with metadata.
#[derive(Debug, Clone)]
pub struct DiscoveredLink {
    pub href: Url,
    pub text: String,
    pub context: LinkContext,
    pub element: String,
}

// ─────────────────────────────────────────────
//  Form types
// ─────────────────────────────────────────────

/// HTTP method for a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl Method {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            _ => Self::Get,
        }
    }
}

/// An input field inside a form.
#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
    pub required: bool,
    pub id: Option<String>,
    pub maxlength: Option<usize>,
}

/// A discovered form with its metadata and inputs.
#[derive(Debug, Clone)]
pub struct DiscoveredForm {
    pub action: Url,
    pub method: Method,
    pub inputs: Vec<FormInput>,
    pub enctype: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub onsubmit: Option<String>,
    pub looks_like_auth: bool,
}

// ─────────────────────────────────────────────
//  Script types
// ─────────────────────────────────────────────

/// A discovered external script.
#[derive(Debug, Clone)]
pub struct DiscoveredScript {
    pub src: Url,
    pub async_load: bool,
    pub defer: bool,
    pub integrity: Option<String>,
    pub crossorigin: Option<String>,
}

/// A discovered inline script.
#[derive(Debug, Clone)]
pub struct InlineScript {
    pub code: String,
    pub line: usize,
}

// ─────────────────────────────────────────────
//  Security-relevant embedded content
// ─────────────────────────────────────────────

/// A discovered `<iframe>`.
#[derive(Debug, Clone)]
pub struct DiscoveredIframe {
    pub src: Option<Url>,
    pub name: Option<String>,
    pub id: Option<String>,
    pub sandbox: Option<String>,
    pub width: Option<String>,
    pub height: Option<String>,
    pub allow_fullscreen: bool,
    pub is_hidden: bool,
}

/// A discovered `<object>`, `<embed>`, or `<applet>`.
#[derive(Debug, Clone)]
pub struct DiscoveredEmbed {
    pub embed_type: EmbedKind,
    pub data: Option<String>,
    pub src: Option<Url>,
    pub type_attr: Option<String>,
    pub width: Option<String>,
    pub height: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedKind {
    Object,
    Embed,
    Applet,
}

/// A discovered `<link>` tag (stylesheets, icons, preconnect, dns-prefetch).
#[derive(Debug, Clone)]
pub struct DiscoveredLinkTag {
    pub rel: String,
    pub href: Option<String>,
    pub crossorigin: Option<String>,
    pub integrity: Option<String>,
}

/// A discovered `<base>` tag.
#[derive(Debug, Clone)]
pub struct BaseTag {
    pub href: Option<String>,
}

/// A discovered `<meta http-equiv="refresh">` redirect.
#[derive(Debug, Clone)]
pub struct MetaRefresh {
    pub url: Option<String>,
    pub delay: u32,
}

/// An element with a JavaScript event handler attribute.
#[derive(Debug, Clone)]
pub struct EventHandler {
    pub element: String,
    pub event: String,
    pub handler: String,
}

/// A discovered media element (video/audio/source).
#[derive(Debug, Clone)]
pub struct DiscoveredMedia {
    pub media_type: MediaKind,
    pub src: Option<String>,
    pub poster: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaKind {
    Video,
    Audio,
    Source,
}

// ─────────────────────────────────────────────
//  Complete parse result
// ─────────────────────────────────────────────

/// Complete parse result for a single HTML page.
#[derive(Debug, Clone)]
pub struct ParsedPage {
    pub url: Url,
    pub title: String,

    // Core
    pub links: Vec<DiscoveredLink>,
    pub forms: Vec<DiscoveredForm>,
    pub scripts: Vec<DiscoveredScript>,
    pub inline_scripts: Vec<InlineScript>,
    pub meta: HashMap<String, String>,
    pub images: Vec<String>,
    pub canonical: Option<String>,
    pub description: Option<String>,
    pub generator: Option<String>,

    // Security-relevant
    pub iframes: Vec<DiscoveredIframe>,
    pub embeds: Vec<DiscoveredEmbed>,
    pub link_tags: Vec<DiscoveredLinkTag>,
    pub base_tag: Option<BaseTag>,
    pub meta_refresh: Option<MetaRefresh>,
    pub event_handlers: Vec<EventHandler>,
    pub media: Vec<DiscoveredMedia>,
    pub has_noscript: bool,

    // Hidden / suspicious
    pub hidden_inputs: Vec<FormInput>,
    pub data_attributes_count: usize,
}

// ─────────────────────────────────────────────
//  Parser
// ─────────────────────────────────────────────

/// HTML parser that extracts links, forms, scripts, and security-relevant elements.
pub struct HtmlParser {
    base_url: Url,
}

impl HtmlParser {
    /// Create a new parser with a base URL for resolving relative links.
    pub fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    /// Parse an HTML string and extract all discoverable elements.
    pub fn parse(&self, html: &str) -> ParsedPage {
        let document = Html::parse_document(html);

        let title = self.extract_title(&document);
        let links = self.extract_links(&document);
        let forms = self.extract_forms(&document);
        let scripts = self.extract_scripts(&document);
        let inline_scripts = self.extract_inline_scripts(html);
        let meta = self.extract_meta(&document);
        let images = self.extract_images(&document);
        let canonical = self.extract_canonical(&document);
        let description = meta.get("description").cloned();
        let generator = meta.get("generator").cloned();

        let iframes = self.extract_iframes(&document);
        let embeds = self.extract_embeds(&document);
        let link_tags = self.extract_link_tags(&document);
        let base_tag = self.extract_base_tag(&document);
        let meta_refresh = self.extract_meta_refresh(&document);
        let event_handlers = self.extract_event_handlers(html);
        let media = self.extract_media(&document);
        let has_noscript = self.detect_noscript(html);

        let hidden_inputs = forms
            .iter()
            .flat_map(|f| f.inputs.iter())
            .filter(|i| i.input_type == "hidden")
            .cloned()
            .collect();

        let data_attributes_count = self.count_data_attributes(html);

        ParsedPage {
            url: self.base_url.clone(),
            title,
            links,
            forms,
            scripts,
            inline_scripts,
            meta,
            images,
            canonical,
            description,
            generator,
            iframes,
            embeds,
            link_tags,
            base_tag,
            meta_refresh,
            event_handlers,
            media,
            has_noscript,
            hidden_inputs,
            data_attributes_count,
        }
    }

    // ── Core extractors ──────────────────────

    fn extract_title(&self, document: &Html) -> String {
        let selector = Selector::parse("title").unwrap();
        document
            .select(&selector)
            .next()
            .map(|el| el.text().collect::<String>().trim().to_string())
            .unwrap_or_default()
    }

    fn extract_links(&self, document: &Html) -> Vec<DiscoveredLink> {
        let selector = Selector::parse("a[href]").unwrap();
        let mut links = Vec::new();

        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(abs_url) = self.base_url.join(href) {
                    if abs_url.scheme() != "http" && abs_url.scheme() != "https" {
                        continue;
                    }
                    let text = element.text().collect::<String>().trim().to_string();
                    links.push(DiscoveredLink {
                        href: abs_url,
                        text,
                        context: LinkContext::Navigation,
                        element: "a".to_string(),
                    });
                }
            }
        }

        links
    }

    fn extract_forms(&self, document: &Html) -> Vec<DiscoveredForm> {
        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input, textarea, select").unwrap();
        let mut forms = Vec::new();

        for form_el in document.select(&form_selector) {
            let action = form_el
                .value()
                .attr("action")
                .and_then(|a| self.base_url.join(a).ok())
                .unwrap_or_else(|| self.base_url.clone());

            let method = form_el
                .value()
                .attr("method")
                .map(Method::from_str)
                .unwrap_or(Method::Get);

            let enctype = form_el.value().attr("enctype").map(String::from);
            let id = form_el.value().attr("id").map(String::from);
            let name = form_el.value().attr("name").map(String::from);
            let onsubmit = form_el.value().attr("onsubmit").map(String::from);

            let mut inputs = Vec::new();
            for input_el in form_el.select(&input_selector) {
                let input_value = input_el.value();
                let input_type = input_value
                    .attr("type")
                    .unwrap_or("text")
                    .to_lowercase();

                if input_type == "submit" || input_type == "button" || input_type == "image" {
                    continue;
                }

                let name = input_value.attr("name").unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }

                inputs.push(FormInput {
                    name,
                    input_type,
                    value: input_value.attr("value").map(String::from),
                    required: input_value.attr("required").is_some(),
                    id: input_value.attr("id").map(String::from),
                    maxlength: input_value
                        .attr("maxlength")
                        .and_then(|v| v.parse().ok()),
                });
            }

            let looks_like_auth = self.detect_auth_form(&inputs, &name, &id);

            forms.push(DiscoveredForm {
                action,
                method,
                inputs,
                enctype,
                id,
                name,
                onsubmit,
                looks_like_auth,
            });
        }

        forms
    }

    fn extract_scripts(&self, document: &Html) -> Vec<DiscoveredScript> {
        let selector = Selector::parse("script[src]").unwrap();
        let mut scripts = Vec::new();

        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Ok(abs_url) = self.base_url.join(src) {
                    scripts.push(DiscoveredScript {
                        src: abs_url,
                        async_load: element.value().attr("async").is_some(),
                        defer: element.value().attr("defer").is_some(),
                        integrity: element.value().attr("integrity").map(String::from),
                        crossorigin: element.value().attr("crossorigin").map(String::from),
                    });
                }
            }
        }

        scripts
    }

    fn extract_inline_scripts(&self, html: &str) -> Vec<InlineScript> {
        let mut scripts = Vec::new();
        let mut in_script = false;
        let mut current_script = String::new();
        let mut line_num = 1;

        for line in html.lines() {
            let lower = line.to_lowercase();

            if !in_script {
                if lower.contains("<script") && !lower.contains("src=") {
                    in_script = true;
                    current_script.clear();
                }
            } else if lower.contains("</script>") {
                let code = current_script.trim().to_string();
                if !code.is_empty() {
                    scripts.push(InlineScript {
                        code,
                        line: line_num,
                    });
                }
                in_script = false;
            } else {
                current_script.push_str(line);
                current_script.push('\n');
            }

            line_num += 1;
        }

        scripts
    }

    fn extract_meta(&self, document: &Html) -> HashMap<String, String> {
        let selector = Selector::parse("meta[name], meta[property]").unwrap();
        let mut meta = HashMap::new();

        for element in document.select(&selector) {
            let key = element
                .value()
                .attr("name")
                .or_else(|| element.value().attr("property"))
                .unwrap_or("")
                .to_lowercase();

            if let Some(content) = element.value().attr("content") {
                if !key.is_empty() {
                    meta.insert(key, content.to_string());
                }
            }
        }

        meta
    }

    fn extract_canonical(&self, document: &Html) -> Option<String> {
        let selector = Selector::parse("link[rel=\"canonical\"]").unwrap();
        document
            .select(&selector)
            .next()
            .and_then(|el| el.value().attr("href").map(String::from))
    }

    fn extract_images(&self, document: &Html) -> Vec<String> {
        let selector = Selector::parse("img[src]").unwrap();
        document
            .select(&selector)
            .filter_map(|el| el.value().attr("src").map(String::from))
            .collect()
    }

    // ── Security-relevant extractors ─────────

    fn extract_iframes(&self, document: &Html) -> Vec<DiscoveredIframe> {
        let selector = Selector::parse("iframe").unwrap();
        document
            .select(&selector)
            .map(|el| {
                let v = el.value();
                let is_hidden = v.attr("style").map(|s| s.to_lowercase()).map_or(false, |s| {
                    s.contains("display:none")
                        || s.contains("display: none")
                        || s.contains("visibility:hidden")
                        || s.contains("visibility: hidden")
                        || s.contains("width:0")
                        || s.contains("height:0")
                }) || v.attr("width") == Some("0")
                    || v.attr("height") == Some("0");

                DiscoveredIframe {
                    src: v
                        .attr("src")
                        .and_then(|s| self.base_url.join(s).ok()),
                    name: v.attr("name").map(String::from),
                    id: v.attr("id").map(String::from),
                    sandbox: v.attr("sandbox").map(String::from),
                    width: v.attr("width").map(String::from),
                    height: v.attr("height").map(String::from),
                    allow_fullscreen: v.attr("allowfullscreen").is_some(),
                    is_hidden,
                }
            })
            .collect()
    }

    fn extract_embeds(&self, document: &Html) -> Vec<DiscoveredEmbed> {
        let mut embeds = Vec::new();

        // <object>
        for el in document.select(&Selector::parse("object").unwrap()) {
            let v = el.value();
            embeds.push(DiscoveredEmbed {
                embed_type: EmbedKind::Object,
                data: v.attr("data").map(String::from),
                src: v.attr("data").and_then(|s| self.base_url.join(s).ok()),
                type_attr: v.attr("type").map(String::from),
                width: v.attr("width").map(String::from),
                height: v.attr("height").map(String::from),
            });
        }

        // <embed>
        for el in document.select(&Selector::parse("embed").unwrap()) {
            let v = el.value();
            embeds.push(DiscoveredEmbed {
                embed_type: EmbedKind::Embed,
                data: v.attr("src").map(String::from),
                src: v.attr("src").and_then(|s| self.base_url.join(s).ok()),
                type_attr: v.attr("type").map(String::from),
                width: v.attr("width").map(String::from),
                height: v.attr("height").map(String::from),
            });
        }

        // <applet>
        for el in document.select(&Selector::parse("applet").unwrap()) {
            let v = el.value();
            embeds.push(DiscoveredEmbed {
                embed_type: EmbedKind::Applet,
                data: v.attr("code").map(String::from),
                src: v.attr("codebase").and_then(|s| self.base_url.join(s).ok()),
                type_attr: None,
                width: v.attr("width").map(String::from),
                height: v.attr("height").map(String::from),
            });
        }

        embeds
    }

    fn extract_link_tags(&self, document: &Html) -> Vec<DiscoveredLinkTag> {
        let selector = Selector::parse("link[rel]").unwrap();
        document
            .select(&selector)
            .map(|el| {
                let v = el.value();
                DiscoveredLinkTag {
                    rel: v.attr("rel").unwrap_or("").to_string(),
                    href: v.attr("href").map(String::from),
                    crossorigin: v.attr("crossorigin").map(String::from),
                    integrity: v.attr("integrity").map(String::from),
                }
            })
            .collect()
    }

    fn extract_base_tag(&self, document: &Html) -> Option<BaseTag> {
        document
            .select(&Selector::parse("base").unwrap())
            .next()
            .map(|el| BaseTag {
                href: el.value().attr("href").map(String::from),
            })
    }

    fn extract_meta_refresh(&self, document: &Html) -> Option<MetaRefresh> {
        let selector = Selector::parse("meta[http-equiv=\"refresh\"]").unwrap();
        document.select(&selector).next().and_then(|el| {
            let content = el.value().attr("content")?;
            let parts: Vec<&str> = content.splitn(2, ';').collect();
            let delay = parts[0].trim().parse::<u32>().unwrap_or(0);
            let url = parts.get(1).and_then(|p| {
                let p = p.trim();
                if p.to_lowercase().starts_with("url=") {
                    Some(p[4..].trim().to_string())
                } else {
                    None
                }
            });
            Some(MetaRefresh { url, delay })
        })
    }

    fn extract_event_handlers(&self, html: &str) -> Vec<EventHandler> {
        let mut handlers = Vec::new();
        let event_attrs = [
            "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
            "onmousemove", "onmouseout", "onkeydown", "onkeypress", "onkeyup",
            "onfocus", "onblur", "onchange", "onsubmit", "onreset", "onselect",
            "onload", "onerror", "onabort", "onresize", "onscroll", "onunload",
            "onbeforeunload", "onhashchange", "onpopstate", "onstorage",
            "oninput", "oninvalid", "ontouchstart", "ontouchend", "ontouchmove",
            "ondrag", "ondragstart", "ondragend", "ondragover", "ondragenter",
            "ondragleave", "ondrop", "oncopy", "oncut", "onpaste",
        ];

        for event in &event_attrs {
            let pattern = format!("{}=", event);
            let mut pos = 0;
            while let Some(idx) = html[pos..].find(&pattern) {
                let abs_idx = pos + idx;
                // Check if it's inside a tag attribute (not inside a string literal)
                // Simple heuristic: look backwards for '<'
                let before = &html[..abs_idx];
                let mut skip = false;
                let mut element = "unknown".to_string();
                if let Some(tag_start) = before.rfind('<') {
                    let between = &html[tag_start..abs_idx];
                    // Count quotes to check if we're inside an attribute value
                    let single_quotes = between.chars().filter(|&c| c == '\'').count();
                    let double_quotes = between.chars().filter(|&c| c == '"').count();
                    if single_quotes % 2 == 1 || double_quotes % 2 == 1 {
                        // Inside a quoted attribute, skip
                        skip = true;
                    }
                    // Extract element name
                    element = before[tag_start..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("unknown")
                        .trim_start_matches('<')
                        .to_string();
                }

                if skip {
                    pos = abs_idx + pattern.len();
                    continue;
                }

                // Extract handler value
                let after_eq = &html[abs_idx + pattern.len()..];
                let handler = if after_eq.starts_with('"') {
                    after_eq[1..].find('"').map(|end| after_eq[1..1 + end].to_string())
                } else if after_eq.starts_with('\'') {
                    after_eq[1..].find('\'').map(|end| after_eq[1..1 + end].to_string())
                } else {
                    after_eq.split_whitespace().next().map(String::from)
                };

                if let Some(handler) = handler {
                    if !handler.is_empty() {
                        handlers.push(EventHandler {
                            element,
                            event: event.to_string(),
                            handler,
                        });
                    }
                }

                pos = abs_idx + pattern.len();
            }
        }

        handlers
    }

    fn extract_media(&self, document: &Html) -> Vec<DiscoveredMedia> {
        let mut media = Vec::new();

        for el in document.select(&Selector::parse("video").unwrap()) {
            let v = el.value();
            media.push(DiscoveredMedia {
                media_type: MediaKind::Video,
                src: v.attr("src").map(String::from),
                poster: v.attr("poster").map(String::from),
                id: v.attr("id").map(String::from),
            });
        }

        for el in document.select(&Selector::parse("audio").unwrap()) {
            let v = el.value();
            media.push(DiscoveredMedia {
                media_type: MediaKind::Audio,
                src: v.attr("src").map(String::from),
                poster: None,
                id: v.attr("id").map(String::from),
            });
        }

        for el in document.select(&Selector::parse("source").unwrap()) {
            let v = el.value();
            media.push(DiscoveredMedia {
                media_type: MediaKind::Source,
                src: v.attr("src").map(String::from),
                poster: None,
                id: None,
            });
        }

        media
    }

    fn detect_noscript(&self, html: &str) -> bool {
        html.to_lowercase().contains("<noscript")
    }

    fn count_data_attributes(&self, html: &str) -> usize {
        html.match_indices("data-").count()
    }

    // ── Heuristics ───────────────────────────

    fn detect_auth_form(
        &self,
        inputs: &[FormInput],
        form_name: &Option<String>,
        form_id: &Option<String>,
    ) -> bool {
        let auth_keywords = [
            "login", "signin", "sign-in", "auth", "password", "register", "signup",
        ];

        if let Some(ref name) = form_name {
            if auth_keywords
                .iter()
                .any(|k| name.to_lowercase().contains(k))
            {
                return true;
            }
        }
        if let Some(ref id) = form_id {
            if auth_keywords
                .iter()
                .any(|k| id.to_lowercase().contains(k))
            {
                return true;
            }
        }

        let has_password = inputs.iter().any(|i| i.input_type == "password");
        let has_username = inputs.iter().any(|i| {
            let name = i.name.to_lowercase();
            name.contains("user")
                || name.contains("email")
                || name.contains("login")
                || name.contains("account")
        });

        has_password || (has_username && inputs.len() <= 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_url() -> Url {
        Url::parse("http://example.com/page").unwrap()
    }

    // ── Core tests ───────────────────────────

    #[test]
    fn parse_extracts_title() {
        let html = r#"<html><head><title>My Page</title></head><body></body></html>"#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.title, "My Page");
    }

    #[test]
    fn parse_extracts_links() {
        let html = r#"
            <html><body>
                <a href="/about">About</a>
                <a href="http://external.com">External</a>
                <a href="mailto:test@example.com">Email</a>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.links.len(), 2);
        assert_eq!(page.links[0].href.path(), "/about");
        assert_eq!(page.links[0].text, "About");
        assert_eq!(page.links[1].href.host_str(), Some("external.com"));
    }

    #[test]
    fn parse_extracts_forms() {
        let html = r#"
            <html><body>
                <form action="/login" method="POST" onsubmit="return validate()">
                    <input type="text" name="username" required>
                    <input type="password" name="password" required>
                    <input type="hidden" name="csrf_token" value="abc123">
                    <input type="submit" value="Login">
                </form>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.forms.len(), 1);
        let form = &page.forms[0];
        assert_eq!(form.action.path(), "/login");
        assert_eq!(form.method, Method::Post);
        assert_eq!(form.inputs.len(), 3);
        assert!(form.looks_like_auth);
        assert_eq!(form.onsubmit.as_deref(), Some("return validate()"));
    }

    #[test]
    fn parse_extracts_scripts() {
        let html = r#"
            <html><head>
                <script src="/app.js" async crossorigin="anonymous"></script>
                <script src="/lib.js" defer integrity="sha256-abc"></script>
            </head><body></body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.scripts.len(), 2);
        assert!(page.scripts[0].async_load);
        assert!(page.scripts[0].crossorigin.as_deref() == Some("anonymous"));
        assert!(page.scripts[1].defer);
        assert!(page.scripts[1].integrity.is_some());
    }

    #[test]
    fn parse_extracts_inline_scripts() {
        let html = r#"
            <html><body>
                <script>
                    var x = 1;
                    console.log(x);
                </script>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.inline_scripts.len(), 1);
        assert!(page.inline_scripts[0].code.contains("var x = 1"));
    }

    #[test]
    fn parse_extracts_meta_tags() {
        let html = r#"
            <html><head>
                <meta name="description" content="A test page">
                <meta name="generator" content="WordPress">
                <meta property="og:title" content="OG Title">
            </head><body></body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.meta.len(), 3);
        assert_eq!(page.description.as_deref(), Some("A test page"));
        assert_eq!(page.generator.as_deref(), Some("WordPress"));
        assert_eq!(page.meta.get("og:title").unwrap(), "OG Title");
    }

    #[test]
    fn parse_extracts_canonical() {
        let html = r#"
            <html><head>
                <link rel="canonical" href="http://example.com/canonical">
            </head><body></body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(
            page.canonical.as_deref(),
            Some("http://example.com/canonical")
        );
    }

    #[test]
    fn parse_extracts_images() {
        let html = r#"
            <html><body>
                <img src="/logo.png" alt="Logo">
                <img src="/banner.jpg">
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.images.len(), 2);
    }

    // ── Iframe tests ─────────────────────────

    #[test]
    fn parse_extracts_iframes() {
        let html = r#"
            <html><body>
                <iframe src="http://evil.com" width="100" height="100"></iframe>
                <iframe style="display:none" src="http://hidden.com"></iframe>
                <iframe sandbox="allow-scripts" src="/safe.html"></iframe>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.iframes.len(), 3);
        assert!(!page.iframes[0].is_hidden);
        assert!(page.iframes[1].is_hidden);
        assert!(page.iframes[2].sandbox.is_some());
    }

    // ── Embed tests ──────────────────────────

    #[test]
    fn parse_extracts_embeds() {
        let html = r#"
            <html><body>
                <object data="/flash.swf" type="application/x-shockwave-flash"></object>
                <embed src="/plugin.swf" type="application/x-shockwave-flash">
                <applet code="Main.class" codebase="/applets/"></applet>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.embeds.len(), 3);
        assert_eq!(page.embeds[0].embed_type, EmbedKind::Object);
        assert_eq!(page.embeds[1].embed_type, EmbedKind::Embed);
        assert_eq!(page.embeds[2].embed_type, EmbedKind::Applet);
    }

    // ── Link tag tests ───────────────────────

    #[test]
    fn parse_extracts_link_tags() {
        let html = r#"
            <html><head>
                <link rel="stylesheet" href="/style.css">
                <link rel="icon" href="/favicon.ico">
                <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
            </head><body></body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert!(page.link_tags.iter().any(|l| l.rel == "stylesheet"));
        assert!(page.link_tags.iter().any(|l| l.rel == "icon"));
        assert!(page
            .link_tags
            .iter()
            .any(|l| l.rel == "preconnect" && l.crossorigin.is_some()));
    }

    // ── Base tag test ────────────────────────

    #[test]
    fn parse_extracts_base_tag() {
        let html = r#"<html><head><base href="http://other.com/"></head><body></body></html>"#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert!(page.base_tag.is_some());
        assert_eq!(
            page.base_tag.unwrap().href.as_deref(),
            Some("http://other.com/")
        );
    }

    // ── Meta refresh test ────────────────────

    #[test]
    fn parse_extracts_meta_refresh() {
        let html = r#"<html><head><meta http-equiv="refresh" content="5;url=http://other.com"></head><body></body></html>"#;
        let page = HtmlParser::new(base_url()).parse(html);
        let refresh = page.meta_refresh.unwrap();
        assert_eq!(refresh.delay, 5);
        assert_eq!(refresh.url.as_deref(), Some("http://other.com"));
    }

    // ── Event handler tests ──────────────────

    #[test]
    fn parse_extracts_event_handlers() {
        let html = r#"
            <html><body>
                <button onclick="alert('xss')">Click</button>
                <img src="x" onerror="alert('error')">
                <input onfocus="steal()" value="test">
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert!(page
            .event_handlers
            .iter()
            .any(|h| h.event == "onclick" && h.handler.contains("alert")));
        assert!(page
            .event_handlers
            .iter()
            .any(|h| h.event == "onerror" && h.handler.contains("alert")));
        assert!(page
            .event_handlers
            .iter()
            .any(|h| h.event == "onfocus" && h.handler.contains("steal")));
    }

    // ── Media tests ──────────────────────────

    #[test]
    fn parse_extracts_media() {
        let html = r#"
            <html><body>
                <video src="/video.mp4" poster="/thumb.jpg"></video>
                <audio src="/audio.mp3"></audio>
                <source src="/movie.webm" type="video/webm">
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.media.len(), 3);
        assert_eq!(page.media[0].media_type, MediaKind::Video);
        assert_eq!(page.media[0].poster.as_deref(), Some("/thumb.jpg"));
        assert_eq!(page.media[1].media_type, MediaKind::Audio);
        assert_eq!(page.media[2].media_type, MediaKind::Source);
    }

    // ── Noscript test ────────────────────────

    #[test]
    fn parse_detects_noscript() {
        let html = r#"<html><body><noscript>Enable JavaScript</noscript></body></html>"#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert!(page.has_noscript);
    }

    #[test]
    fn parse_no_noscript() {
        let html = r#"<html><body></body></html>"#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert!(!page.has_noscript);
    }

    // ── Hidden inputs test ───────────────────

    #[test]
    fn parse_extracts_hidden_inputs() {
        let html = r#"
            <html><body>
                <form action="/submit" method="POST">
                    <input type="hidden" name="token" value="xyz">
                    <input type="hidden" name="user_id" value="1">
                    <input type="text" name="query">
                </form>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.hidden_inputs.len(), 2);
        assert!(page.hidden_inputs.iter().any(|i| i.name == "token"));
        assert!(page.hidden_inputs.iter().any(|i| i.name == "user_id"));
    }

    // ── Data attributes test ─────────────────

    #[test]
    fn parse_counts_data_attributes() {
        let html = r#"
            <html><body>
                <div data-id="1" data-name="test"></div>
                <span data-action="delete"></span>
            </body></html>
        "#;
        let page = HtmlParser::new(base_url()).parse(html);
        assert_eq!(page.data_attributes_count, 3);
    }

    // ── Edge cases ───────────────────────────

    #[test]
    fn parse_empty_html() {
        let page = HtmlParser::new(base_url()).parse("");
        assert!(page.title.is_empty());
        assert!(page.links.is_empty());
        assert!(page.forms.is_empty());
        assert!(page.iframes.is_empty());
        assert!(page.embeds.is_empty());
    }

    #[test]
    fn parse_preserves_base_url() {
        let page = HtmlParser::new(base_url()).parse("<html><body></body></html>");
        assert_eq!(page.url, base_url());
    }

    #[test]
    fn method_from_str() {
        assert_eq!(Method::from_str("GET"), Method::Get);
        assert_eq!(Method::from_str("post"), Method::Post);
        assert_eq!(Method::from_str("PUT"), Method::Put);
        assert_eq!(Method::from_str("DELETE"), Method::Delete);
        assert_eq!(Method::from_str("unknown"), Method::Get);
    }

    #[test]
    fn detect_auth_form_with_password() {
        let parser = HtmlParser::new(base_url());
        let inputs = vec![
            FormInput {
                name: "user".to_string(),
                input_type: "text".to_string(),
                value: None,
                required: true,
                id: None,
                maxlength: None,
            },
            FormInput {
                name: "pass".to_string(),
                input_type: "password".to_string(),
                value: None,
                required: true,
                id: None,
                maxlength: None,
            },
        ];
        assert!(parser.detect_auth_form(&inputs, &None, &None));
    }

    #[test]
    fn detect_auth_form_by_name() {
        let parser = HtmlParser::new(base_url());
        let inputs = vec![];
        assert!(parser.detect_auth_form(
            &inputs,
            &Some("login-form".to_string()),
            &None
        ));
        assert!(parser.detect_auth_form(
            &inputs,
            &None,
            &Some("signin".to_string())
        ));
    }

    #[test]
    fn detect_non_auth_form() {
        let parser = HtmlParser::new(base_url());
        let inputs = vec![FormInput {
            name: "q".to_string(),
            input_type: "text".to_string(),
            value: None,
            required: false,
            id: None,
            maxlength: None,
        }];
        assert!(!parser.detect_auth_form(
            &inputs,
            &Some("search".to_string()),
            &None
        ));
    }
}

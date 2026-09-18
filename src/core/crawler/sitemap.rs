use crate::core::crawler::engine::{CrawlResults, CrawledPage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Output format for the sitemap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitemapFormat {
    /// XML sitemap (standard format).
    Xml,
    /// JSON tree structure.
    Json,
    /// Simple text list of URLs.
    Text,
    /// Hierarchical tree view.
    Tree,
}

/// A node in the sitemap tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitemapNode {
    /// The URL path segment.
    pub name: String,
    /// Full URL.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Depth in the crawl tree.
    pub depth: u32,
    /// Number of forms found on this page.
    pub forms: usize,
    /// Number of links found on this page.
    pub links: usize,
    /// Child nodes.
    pub children: Vec<SitemapNode>,
}

/// Complete sitemap generated from crawl results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sitemap {
    /// The target URL that was crawled.
    pub target: String,
    /// Total pages discovered.
    pub total_pages: usize,
    /// Total forms discovered.
    pub total_forms: usize,
    /// Total links discovered.
    pub total_links: usize,
    /// Maximum depth reached.
    pub max_depth: u32,
    /// Root node of the tree.
    pub root: SitemapNode,
    /// Flat list of all URLs.
    pub urls: Vec<SitemapEntry>,
    /// Statistics by depth.
    pub depth_stats: HashMap<u32, usize>,
}

/// A single entry in the flat URL list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitemapEntry {
    pub url: String,
    pub status: u16,
    pub depth: u32,
    pub forms: usize,
    pub links: usize,
    pub is_auth: bool,
}

/// Sitemap generator that builds tree and flat representations.
pub struct SitemapGenerator;

impl SitemapGenerator {
    /// Generate a sitemap from crawl results.
    pub fn generate(results: &CrawlResults) -> Sitemap {
        let urls: Vec<SitemapEntry> = results
            .pages
            .iter()
            .map(|page| {
                let is_auth = page
                    .parsed
                    .as_ref()
                    .map(|p| p.forms.iter().any(|f| f.looks_like_auth))
                    .unwrap_or(false);

                SitemapEntry {
                    url: page.url.to_string(),
                    status: page.status,
                    depth: page.depth,
                    forms: page
                        .parsed
                        .as_ref()
                        .map(|p| p.forms.len())
                        .unwrap_or(0),
                    links: page
                        .parsed
                        .as_ref()
                        .map(|p| p.links.len())
                        .unwrap_or(0),
                    is_auth,
                }
            })
            .collect();

        let total_forms = urls.iter().map(|e| e.forms).sum();
        let total_links = urls.iter().map(|e| e.links).sum();
        let max_depth = urls.iter().map(|e| e.depth).max().unwrap_or(0);

        let mut depth_stats: HashMap<u32, usize> = HashMap::new();
        for entry in &urls {
            *depth_stats.entry(entry.depth).or_insert(0) += 1;
        }

        let root = Self::build_tree(&results.pages, &results.target.to_string());

        Sitemap {
            target: results.target.to_string(),
            total_pages: results.pages.len(),
            total_forms,
            total_links,
            max_depth,
            root,
            urls,
            depth_stats,
        }
    }

    /// Build a tree structure from crawl results.
    fn build_tree(pages: &[CrawledPage], target: &str) -> SitemapNode {
        let target_url = Url::parse(target).ok();
        let _base_path = target_url
            .as_ref()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut root = SitemapNode {
            name: "/".to_string(),
            url: target.to_string(),
            status: 200,
            depth: 0,
            forms: 0,
            links: 0,
            children: Vec::new(),
        };

        // Sort pages by depth for proper tree construction
        let mut sorted_pages: Vec<&CrawledPage> = pages.iter().collect();
        sorted_pages.sort_by_key(|p| p.depth);

        for page in sorted_pages {
            let path = page.url.path();
            let segments: Vec<&str> = path
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();

            Self::insert_into_tree(&mut root, &segments, page, 0);
        }

        root
    }

    /// Insert a page into the tree at the correct position.
    fn insert_into_tree(
        node: &mut SitemapNode,
        segments: &[&str],
        page: &CrawledPage,
        current_depth: u32,
    ) {
        if segments.is_empty() {
            // This is the node for this page
            node.status = page.status;
            node.depth = page.depth;
            node.forms = page.parsed.as_ref().map(|p| p.forms.len()).unwrap_or(0);
            node.links = page.parsed.as_ref().map(|p| p.links.len()).unwrap_or(0);
            return;
        }

        let segment = segments[0];
        let remaining = &segments[1..];

        // Find or create child node
        let child = node
            .children
            .iter_mut()
            .find(|c| c.name == segment);

        if let Some(child) = child {
            Self::insert_into_tree(child, remaining, page, current_depth + 1);
        } else {
            let mut new_child = SitemapNode {
                name: segment.to_string(),
                url: format!("{}/{}", node.url.trim_end_matches('/'), segment),
                status: 0,
                depth: current_depth + 1,
                forms: 0,
                links: 0,
                children: Vec::new(),
            };
            Self::insert_into_tree(&mut new_child, remaining, page, current_depth + 1);
            node.children.push(new_child);
        }
    }

    /// Format sitemap as XML.
    pub fn to_xml(sitemap: &Sitemap) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<sitemap xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
        xml.push_str(&format!("  <target>{}</target>\n", xml_escape(&sitemap.target)));
        xml.push_str(&format!("  <pages>{}</pages>\n", sitemap.total_pages));
        xml.push_str(&format!("  <forms>{}</forms>\n", sitemap.total_forms));
        xml.push_str(&format!("  <links>{}</links>\n", sitemap.total_links));

        for entry in &sitemap.urls {
            xml.push_str("  <url>\n");
            xml.push_str(&format!("    <loc>{}</loc>\n", xml_escape(&entry.url)));
            xml.push_str(&format!("    <status>{}</status>\n", entry.status));
            xml.push_str(&format!("    <depth>{}</depth>\n", entry.depth));
            if entry.forms > 0 {
                xml.push_str(&format!("    <forms>{}</forms>\n", entry.forms));
            }
            if entry.is_auth {
                xml.push_str("    <auth>true</auth>\n");
            }
            xml.push_str("  </url>\n");
        }

        xml.push_str("</sitemap>\n");
        xml
    }

    /// Format sitemap as JSON.
    pub fn to_json(sitemap: &Sitemap) -> String {
        serde_json::to_string_pretty(sitemap).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format sitemap as a simple text list.
    pub fn to_text(sitemap: &Sitemap) -> String {
        let mut text = format!("Sitemap for: {}\n", sitemap.target);
        text.push_str(&format!(
            "Total: {} pages, {} forms, {} links\n\n",
            sitemap.total_pages, sitemap.total_forms, sitemap.total_links
        ));

        for entry in &sitemap.urls {
            let auth_marker = if entry.is_auth { " [AUTH]" } else { "" };
            let forms_marker = if entry.forms > 0 {
                format!(" ({} forms)", entry.forms)
            } else {
                String::new()
            };
            text.push_str(&format!(
                "{}[{}] {}{}{}\n",
                "  ".repeat(entry.depth as usize),
                entry.status,
                entry.url,
                forms_marker,
                auth_marker
            ));
        }

        text
    }

    /// Format sitemap as a visual tree.
    pub fn to_tree(sitemap: &Sitemap) -> String {
        let mut output = format!("🌐 {}\n", sitemap.target);
        output.push_str(&format!(
            "   {} pages | {} forms | {} links\n\n",
            sitemap.total_pages, sitemap.total_forms, sitemap.total_links
        ));

        Self::render_node(&sitemap.root, &mut output, "", true);
        output
    }

    /// Render a tree node and its children.
    fn render_node(node: &SitemapNode, output: &mut String, prefix: &str, is_last: bool) {
        let connector = if is_last { "└── " } else { "├── " };
        let status = if node.status > 0 {
            format!("[{}]", node.status)
        } else {
            String::new()
        };
        let forms = if node.forms > 0 {
            format!(" ({} forms)", node.forms)
        } else {
            String::new()
        };

        output.push_str(&format!("{}{}{} {}{}\n", prefix, connector, node.name, status, forms));

        let child_prefix = if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        for (i, child) in node.children.iter().enumerate() {
            Self::render_node(child, output, &child_prefix, i == node.children.len() - 1);
        }
    }
}

/// Escape special characters for XML.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crawler::engine::CrawlResults;
    use crate::core::crawler::parser::ParsedPage;

    fn make_page(url: &str, status: u16, depth: u32, forms: usize) -> CrawledPage {
        let parsed = if forms > 0 {
            Some(ParsedPage {
                url: Url::parse(url).unwrap(),
                title: String::new(),
                links: vec![],
                forms: (0..forms)
                    .map(|_| crate::core::crawler::parser::DiscoveredForm {
                        action: Url::parse(url).unwrap(),
                        method: crate::core::crawler::parser::Method::Get,
                        inputs: vec![],
                        enctype: None,
                        id: None,
                        name: None,
                        onsubmit: None,
                        looks_like_auth: false,
                    })
                    .collect(),
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
            })
        } else {
            None
        };

        CrawledPage {
            url: Url::parse(url).unwrap(),
            status,
            parsed,
            fetch_time_ms: 100,
            body_size: 1024,
            depth,
        }
    }

    fn make_results() -> CrawlResults {
        CrawlResults {
            target: Url::parse("http://example.com").unwrap(),
            pages: vec![
                make_page("http://example.com/", 200, 0, 1),
                make_page("http://example.com/about", 200, 1, 0),
                make_page("http://example.com/contact", 200, 1, 1),
                make_page("http://example.com/api/users", 200, 2, 0),
                make_page("http://example.com/api/posts", 200, 2, 0),
            ],
            stats: Default::default(),
            errors: vec![],
        }
    }

    #[test]
    fn generate_sitemap_from_results() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);

        assert_eq!(sitemap.total_pages, 5);
        assert_eq!(sitemap.total_forms, 2);
        assert_eq!(sitemap.max_depth, 2);
    }

    #[test]
    fn sitemap_has_all_urls() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);

        assert_eq!(sitemap.urls.len(), 5);
        assert!(sitemap.urls.iter().any(|u| u.url.contains("/about")));
        assert!(sitemap.urls.iter().any(|u| u.url.contains("/api/users")));
    }

    #[test]
    fn depth_stats_are_correct() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);

        assert_eq!(sitemap.depth_stats.get(&0), Some(&1));
        assert_eq!(sitemap.depth_stats.get(&1), Some(&2));
        assert_eq!(sitemap.depth_stats.get(&2), Some(&2));
    }

    #[test]
    fn to_xml_produces_valid_xml() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);
        let xml = SitemapGenerator::to_xml(&sitemap);

        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<sitemap"));
        assert!(xml.contains("<url>"));
        assert!(xml.contains("</url>"));
        assert!(xml.contains("</sitemap>"));
    }

    #[test]
    fn to_json_produces_valid_json() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);
        let json = SitemapGenerator::to_json(&sitemap);

        assert!(json.contains("total_pages"));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn to_text_lists_urls() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);
        let text = SitemapGenerator::to_text(&sitemap);

        assert!(text.contains("Sitemap for:"));
        assert!(text.contains("http://example.com/about"));
        assert!(text.contains("http://example.com/api/users"));
    }

    #[test]
    fn to_tree_shows_structure() {
        let results = make_results();
        let sitemap = SitemapGenerator::generate(&results);
        let tree = SitemapGenerator::to_tree(&sitemap);

        assert!(tree.contains("example.com"));
        assert!(tree.contains("5 pages"));
    }

    #[test]
    fn auth_detection_in_urls() {
        let mut results = make_results();
        // Add an auth page
        results.pages.push(make_page(
            "http://example.com/login",
            200,
            1,
            1,
        ));
        // Mark the form as auth
        if let Some(ref mut page) = results.pages.last_mut() {
            if let Some(ref mut parsed) = page.parsed {
                if let Some(form) = parsed.forms.first_mut() {
                    form.looks_like_auth = true;
                }
            }
        }

        let sitemap = SitemapGenerator::generate(&results);
        let login_entry = sitemap.urls.iter().find(|u| u.url.contains("/login"));
        assert!(login_entry.unwrap().is_auth);
    }

    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }
}

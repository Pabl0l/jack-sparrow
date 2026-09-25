#![allow(dead_code)]

use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

/// File upload scanner — tests for extension bypass, content-type bypass,
/// double extensions, and null byte injection.
pub struct FileUploadScanner {
    client: Client,
}

/// A test case for file upload bypass.
struct UploadTest {
    /// Original filename to use.
    filename: &'static str,
    /// Content-Type header to send.
    content_type: &'static str,
    /// File content.
    content: &'static [u8],
    /// Description of the bypass technique.
    description: &'static str,
    /// Severity if successful.
    severity: Severity,
}

impl FileUploadScanner {
    pub fn new(config: &JackSparrowConfig) -> Self {
        let timeout = Duration::from_secs(config.general.timeout_secs.min(15));
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        Self { client }
    }

    /// Generate upload bypass test cases.
    fn bypass_tests() -> Vec<UploadTest> {
        vec![
            // Double extension bypass
            UploadTest {
                filename: "shell.php.jpg",
                content_type: "image/jpeg",
                content: b"GIF89a<?php echo 'pwned'; ?>",
                description: "Double extension bypass (.php.jpg)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.php.png",
                content_type: "image/png",
                content: b"\x89PNG\r\n\x1a\n<?php echo 'pwned'; ?>",
                description: "Double extension bypass (.php.png)",
                severity: Severity::High,
            },
            // Content-Type mismatch
            UploadTest {
                filename: "shell.php",
                content_type: "image/jpeg",
                content: b"GIF89a<?php echo 'pwned'; ?>",
                description: "Content-Type mismatch (PHP with JPEG type)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.php",
                content_type: "image/png",
                content: b"\x89PNG\r\n\x1a\n<?php echo 'pwned'; ?>",
                description: "Content-Type mismatch (PHP with PNG type)",
                severity: Severity::High,
            },
            // Null byte injection
            UploadTest {
                filename: "shell.php%00.jpg",
                content_type: "image/jpeg",
                content: b"GIF89a<?php echo 'pwned'; ?>",
                description: "Null byte injection (shell.php%00.jpg)",
                severity: Severity::Critical,
            },
            // Case variation
            UploadTest {
                filename: "shell.pHp",
                content_type: "application/x-php",
                content: b"<?php echo 'pwned'; ?>",
                description: "Case variation (.pHp)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.PhP",
                content_type: "application/x-php",
                content: b"<?php echo 'pwned'; ?>",
                description: "Case variation (.PhP)",
                severity: Severity::High,
            },
            // Alternative PHP extensions
            UploadTest {
                filename: "shell.phtml",
                content_type: "text/html",
                content: b"<?php echo 'pwned'; ?>",
                description: "Alternative extension (.phtml)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.pht",
                content_type: "text/html",
                content: b"<?php echo 'pwned'; ?>",
                description: "Alternative extension (.pht)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.php5",
                content_type: "application/x-php",
                content: b"<?php echo 'pwned'; ?>",
                description: "Alternative extension (.php5)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.shtml",
                content_type: "text/html",
                content: b"<!--#exec cmd=\"id\" -->",
                description: "Server-side include (.shtml)",
                severity: Severity::High,
            },
            // JSP bypass
            UploadTest {
                filename: "shell.jsp",
                content_type: "image/jpeg",
                content: b"GIF89a<% out.println(\"pwned\"); %>",
                description: "Content-Type mismatch (JSP with JPEG type)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.jspx",
                content_type: "image/jpeg",
                content: b"GIF89a<% out.println(\"pwned\"); %>",
                description: "Alternative JSP extension (.jspx)",
                severity: Severity::High,
            },
            // ASP bypass
            UploadTest {
                filename: "shell.asp",
                content_type: "image/jpeg",
                content: b"GIF89a<% Response.Write(\"pwned\") %>",
                description: "Content-Type mismatch (ASP with JPEG type)",
                severity: Severity::High,
            },
            UploadTest {
                filename: "shell.aspx",
                content_type: "image/jpeg",
                content: b"GIF89a<% Response.Write(\"pwned\") %>",
                description: "Content-Type mismatch (ASPX with JPEG type)",
                severity: Severity::High,
            },
            // Polyglot
            UploadTest {
                filename: "polyglot.php",
                content_type: "image/jpeg",
                content: b"\xff\xd8\xff\xe0\x00\x10JFIF<?php echo 'pwned'; ?>",
                description: "Polyglot file (valid JPEG header + PHP)",
                severity: Severity::Critical,
            },
        ]
    }

    /// Detect upload forms in HTML content.
    pub fn detect_upload_forms(html: &str) -> Vec<UploadFormInfo> {
        let mut forms = Vec::new();
        let lower = html.to_lowercase();

        // Look for file input fields
        if lower.contains("type=\"file\"") || lower.contains("type='file'") || lower.contains("type=file") {
            // Extract form action
            let action = Self::extract_form_action(html);

            // Check enctype
            let has_multipart = lower.contains("multipart/form-data");

            // Check for file type restrictions in accept attribute
            let accept = Self::extract_accept_attribute(html);

            forms.push(UploadFormInfo {
                action,
                has_multipart,
                accept,
            });
        }

        forms
    }

    fn extract_form_action(html: &str) -> String {
        let lower = html.to_lowercase();
        if let Some(pos) = lower.find("action=\"") {
            let start = pos + 8;
            if let Some(end) = html[start..].find('"') {
                return html[start..start + end].to_string();
            }
        }
        if let Some(pos) = lower.find("action='") {
            let start = pos + 8;
            if let Some(end) = html[start..].find('\'') {
                return html[start..start + end].to_string();
            }
        }
        "/".to_string()
    }

    fn extract_accept_attribute(html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        if let Some(pos) = lower.find("accept=\"") {
            let start = pos + 8;
            if let Some(end) = html[start..].find('"') {
                return Some(html[start..start + end].to_string());
            }
        }
        None
    }

    /// Test if a file upload endpoint accepts malicious files.
    async fn test_upload(
        &self,
        upload_url: &str,
        test: &UploadTest,
        field_name: &str,
        context: &ScanContext,
    ) -> Result<Option<Finding>, JackSparrowError> {
        let part = reqwest::multipart::Part::bytes(test.content.to_vec())
            .file_name(test.filename.to_string())
            .mime_str(test.content_type)
            .map_err(|e| JackSparrowError::ToolExecutionFailed {
                tool: "file-upload".to_string(),
                message: e.to_string(),
            })?;

        let form = reqwest::multipart::Form::new().part(field_name.to_string(), part);

        let mut req = self.client.post(upload_url).multipart(form);
        for (k, v) in &context.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref cookies) = context.cookies {
            req = req.header("Cookie", cookies.as_str());
        }

        let resp = req.send().await.map_err(|e| JackSparrowError::ToolExecutionFailed {
            tool: "file-upload".to_string(),
            message: e.to_string(),
        })?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // Check if upload was accepted (not rejected)
        let accepted = status == 200
            || status == 201
            || status == 302
            || (status >= 200 && status < 300);

        let rejected = body_lower.contains("denied")
            || body_lower.contains("forbidden")
            || body_lower.contains("not allowed")
            || body_lower.contains("invalid file")
            || body_lower.contains("file type")
            || body_lower.contains("extension not")
            || body_lower.contains("rejected")
            || status == 403
            || status == 415;

        if accepted && !rejected {
            return Ok(Some(Finding {
                id: uuid::Uuid::new_v4(),
                vulnerability_type: VulnerabilityType::FileUpload,
                severity: test.severity.clone(),
                confidence: Confidence::Likely,
                title: format!("File upload bypass: {}", test.description),
                description: format!(
                    "The upload endpoint at {} accepted a file with {}.\n\
                     Filename: {}\n\
                     Content-Type: {}\n\
                     This could allow an attacker to upload and execute arbitrary code.",
                    upload_url, test.description, test.filename, test.content_type
                ),
                url: upload_url.to_string(),
                parameter: Some(field_name.to_string()),
                evidence: Evidence {
                    request: Some(format!(
                        "POST {} (multipart) [file={}; content-type={}]",
                        upload_url, test.filename, test.content_type
                    )),
                    response: Some(format!("Status: {} — Upload accepted", status)),
                    payload: Some(test.filename.to_string()),
                    pattern: Some(test.description.to_string()),
                    context: Some(format!("Content-Type sent: {}", test.content_type)),
                },
                remediation: "1. Validate file extension against an allowlist\n\
                    2. Validate Content-Type from actual file content, not the header\n\
                    3. Rename uploaded files to prevent extension tricks\n\
                    4. Store uploads outside the web root\n\
                    5. Scan uploaded files with antivirus\n\
                    6. Use random filenames to prevent direct access"
                    .to_string(),
                references: vec![
                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload".to_string(),
                    "https://cwe.mitre.org/data/definitions/434.html".to_string(),
                    "https://portswigger.net/web-security/file-upload".to_string(),
                ],
                timestamp: chrono::Utc::now(),
                cvss_score: Some(8.0),
                cwe_id: Some("CWE-434".to_string()),
                tool_source: "file-upload-scanner".to_string(),
            }));
        }

        Ok(None)
    }
}

/// Info about a detected file upload form.
#[derive(Debug, Clone)]
pub struct UploadFormInfo {
    pub action: String,
    pub has_multipart: bool,
    pub accept: Option<String>,
}

#[async_trait]
impl Scanner for FileUploadScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::FileUpload
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        _context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        // Fetch the page to detect upload forms
        let resp = self.client.get(target).send().await.map_err(|e| {
            JackSparrowError::ToolExecutionFailed {
                tool: "file-upload".to_string(),
                message: e.to_string(),
            }
        })?;

        let html = resp.text().await.unwrap_or_default();
        let forms = Self::detect_upload_forms(&html);

        if forms.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let tests = Self::bypass_tests();

        for form in &forms {
            let upload_url = if form.action.starts_with("http") {
                form.action.clone()
            } else if form.action.starts_with('/') {
                let parsed = url::Url::parse(target).map_err(|e| JackSparrowError::InvalidTarget { url: e.to_string() })?;
                let host_part = match parsed.port() {
                    Some(port) => format!("{}:{}", parsed.host_str().unwrap_or(""), port),
                    None => parsed.host_str().unwrap_or("").to_string(),
                };
                format!("{}://{}{}", parsed.scheme(), host_part, form.action)
            } else {
                format!("{}/{}", target.trim_end_matches('/'), form.action)
            };

            // Detect the file input field name (default to "file")
            let field_name = Self::detect_file_field_name(&html).unwrap_or_else(|| "file".to_string());

            for test in &tests {
                if let Some(finding) = self.test_upload(&upload_url, test, &field_name, _context).await? {
                    findings.push(finding);
                    break; // One finding per form is enough
                }
            }
        }

        Ok(findings)
    }
}

impl FileUploadScanner {
    /// Detect the name attribute of the file input field.
    fn detect_file_field_name(html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        // Find type="file" and look for name="..." nearby
        if let Some(pos) = lower.find("type=\"file\"") {
            // Look backwards for name="
            let before = &html[..pos];
            if let Some(name_pos) = before.rfind("name=\"") {
                let start = name_pos + 6;
                if let Some(end) = html[start..].find('"') {
                    return Some(html[start..start + end].to_string());
                }
            }
            // Also look forwards (name might come after type)
            let after = &html[pos..];
            if let Some(name_pos) = after.find("name=\"") {
                let start = pos + name_pos + 6;
                if let Some(end) = html[start..].find('"') {
                    return Some(html[start..start + end].to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bypass_tests_count() {
        let tests = FileUploadScanner::bypass_tests();
        assert!(tests.len() >= 15, "Should have at least 15 bypass tests");
    }

    #[test]
    fn test_detect_upload_forms() {
        let html = r#"
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="avatar" accept="image/*">
                <input type="submit" value="Upload">
            </form>
        "#;
        let forms = FileUploadScanner::detect_upload_forms(html);
        assert_eq!(forms.len(), 1);
        assert!(forms[0].has_multipart);
        assert_eq!(forms[0].action, "/upload");
    }

    #[test]
    fn test_detect_no_upload_form() {
        let html = r#"
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
        "#;
        let forms = FileUploadScanner::detect_upload_forms(html);
        assert!(forms.is_empty());
    }

    #[test]
    fn test_extract_form_action() {
        let html = r#"<form action="/upload-file">"#;
        assert_eq!(FileUploadScanner::extract_form_action(html), "/upload-file");
    }

    #[test]
    fn test_extract_form_action_default() {
        let html = r#"<form method="POST">"#;
        assert_eq!(FileUploadScanner::extract_form_action(html), "/");
    }

    #[test]
    fn test_extract_accept_attribute() {
        let html = r#"<input type="file" name="file" accept="image/*">"#;
        assert_eq!(
            FileUploadScanner::extract_accept_attribute(html),
            Some("image/*".to_string())
        );
    }

    #[test]
    fn test_detect_file_field_name() {
        let html = r#"<input type="file" name="document">"#;
        assert_eq!(
            FileUploadScanner::detect_file_field_name(html),
            Some("document".to_string())
        );
    }

    #[test]
    fn test_detect_file_field_name_default() {
        let html = r#"<input type="file">"#;
        assert!(FileUploadScanner::detect_file_field_name(html).is_none());
    }

    #[test]
    fn test_scanner_type() {
        let scanner = FileUploadScanner::new(&JackSparrowConfig::default());
        assert_eq!(scanner.scanner_type(), ScannerType::FileUpload);
    }

    #[test]
    fn test_bypass_techniques_coverage() {
        let tests = FileUploadScanner::bypass_tests();
        let descriptions: Vec<&str> = tests.iter().map(|t| t.description).collect();

        // Should cover major bypass categories
        assert!(descriptions.iter().any(|d| d.contains("Double extension")));
        assert!(descriptions.iter().any(|d| d.contains("Content-Type mismatch")));
        assert!(descriptions.iter().any(|d| d.contains("Null byte")));
        assert!(descriptions.iter().any(|d| d.contains("Case variation")));
        assert!(descriptions.iter().any(|d| d.contains("Alternative extension")));
        assert!(descriptions.iter().any(|d| d.contains("Polyglot")));
    }

    #[test]
    fn test_severity_mapping() {
        let tests = FileUploadScanner::bypass_tests();
        // Null byte and polyglot should be critical
        let critical: Vec<&str> = tests
            .iter()
            .filter(|t| t.severity == Severity::Critical)
            .map(|t| t.description)
            .collect();
        assert!(!critical.is_empty(), "Should have at least one critical bypass");
    }
}

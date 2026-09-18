use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use serde_json::{json, Value};

/// Standard GraphQL introspection query
const INTROSPECTION_QUERY: &str = r#"{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind }
        }
        type { name kind }
      }
    }
    directives {
      name
      locations
      args {
        name
        type { name kind }
      }
    }
  }
}"#;

/// Sensitive GraphQL field names that indicate high-risk exposure
const SENSITIVE_FIELDS: &[&str] = &[
    "password", "secret", "token", "api_key", "apikey",
    "creditCard", "credit_card", "ssn", "social_security",
    "private_key", "privateKey", "admin", "root",
    "deleteUser", "delete_user", "dropTable", "drop_table",
    "execute", "runQuery", "run_mutation", "eval",
];

/// Dangerous mutation patterns
const DANGEROUS_MUTATIONS: &[&str] = &[
    "delete", "remove", "destroy", "drop", "truncate",
    "update", "modify", "change", "grant", "revoke",
    "execute", "run", "import", "export", "upload",
];

/// Check if a GraphQL type name is a sensitive/internal type
fn is_sensitive_type(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("user") || lower.contains("admin") || lower.contains("auth")
        || lower.contains("session") || lower.contains("token")
        || lower.contains("password") || lower.contains("credential")
        || lower.contains("payment") || lower.contains("billing")
        || lower.contains("internal") || lower.contains("private")
}

/// Analyze GraphQL schema for security issues
fn analyze_schema(schema: &Value) -> Vec<(Severity, String, String, String)> {
    let mut issues = Vec::new();

    if let Some(types) = schema.get("types").and_then(|v| v.as_array()) {
        for type_def in types {
            let type_name = type_def.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let kind = type_def.get("kind").and_then(|v| v.as_str()).unwrap_or("");

            // Skip built-in types
            if type_name.starts_with("__") {
                continue;
            }

            // Check for sensitive types exposed
            if kind == "OBJECT" && is_sensitive_type(type_name) {
                issues.push((
                    Severity::Medium,
                    format!("Sensitive type exposed: {}", type_name),
                    format!(
                        "GraphQL schema exposes the '{}' type, which may leak sensitive data structures.",
                        type_name
                    ),
                    format!(
                        "Restrict introspection access or use schema directives to hide the '{}' type from unauthenticated users.",
                        type_name
                    ),
                ));
            }

            // Check fields for sensitive data
            if let Some(fields) = type_def.get("fields").and_then(|v| v.as_array()) {
                for field in fields {
                    let field_name = field.get("name").and_then(|v| v.as_str()).unwrap_or("");

                    // Check if field name matches sensitive patterns
                    for &sensitive in SENSITIVE_FIELDS {
                        if field_name.to_lowercase().contains(&sensitive.to_lowercase()) {
                            issues.push((
                                Severity::High,
                                format!("Sensitive field exposed: {}.{}", type_name, field_name),
                                format!(
                                    "GraphQL type '{}' exposes field '{}' which may contain sensitive data.",
                                    type_name, field_name
                                ),
                                format!(
                                    "Remove or restrict access to '{}.{}'. Use authorization directives or hide from introspection.",
                                    type_name, field_name
                                ),
                            ));
                        }
                    }

                    // Check arguments for injection risks
                    if let Some(args) = field.get("args").and_then(|v| v.as_array()) {
                        for arg in args {
                            let arg_name = arg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let arg_type = arg.get("type")
                                .and_then(|t| t.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            // String arguments with "query" or "filter" in name
                            // could be vulnerable to injection
                            let lower_name = arg_name.to_lowercase();
                            if (lower_name.contains("query") || lower_name.contains("filter")
                                || lower_name.contains("search") || lower_name.contains("where"))
                                && (arg_type == "String" || arg_type == "ID")
                            {
                                issues.push((
                                    Severity::Medium,
                                    format!(
                                        "Potentially injectable argument: {}.{}({})",
                                        type_name, field_name, arg_name
                                    ),
                                    format!(
                                        "Argument '{}.{}({}: {})' accepts a string that may be used for injection attacks.",
                                        type_name, field_name, arg_name, arg_type
                                    ),
                                    format!(
                                        "Validate and sanitize the '{}' argument. Use input types with strict validation.",
                                        arg_name
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for dangerous mutations
    if let Some(types) = schema.get("types").and_then(|v| v.as_array()) {
        for type_def in types {
            let type_name = type_def.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if type_name.to_lowercase() == "mutation" {
                if let Some(fields) = type_def.get("fields").and_then(|v| v.as_array()) {
                    for field in fields {
                        let field_name = field.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        for &dangerous in DANGEROUS_MUTATIONS {
                            if field_name.to_lowercase().contains(dangerous) {
                                issues.push((
                                    Severity::Medium,
                                    format!("Dangerous mutation: {}", field_name),
                                    format!(
                                        "GraphQL mutation '{}' may perform destructive or privileged operations.",
                                        field_name
                                    ),
                                    format!(
                                        "Ensure '{}' mutation has proper authorization checks and input validation.",
                                        field_name
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for subscriptions (potential DoS vector)
    if let Some(types) = schema.get("types").and_then(|v| v.as_array()) {
        for type_def in types {
            let type_name = type_def.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if type_name.to_lowercase() == "subscription" {
                if let Some(fields) = type_def.get("fields").and_then(|v| v.as_array()) {
                    if !fields.is_empty() {
                        issues.push((
                            Severity::Low,
                            "GraphQL subscriptions enabled".to_string(),
                            "The schema exposes subscription types, which can be used for real-time event streaming and may be abused for DoS.".to_string(),
                            "Ensure subscriptions are rate-limited and require authentication.".to_string(),
                        ));
                    }
                }
            }
        }
    }

    issues
}

/// GraphQL Introspection Scanner
///
/// Detects:
/// 1. Whether GraphQL introspection is enabled (information disclosure)
/// 2. Sensitive types/fields exposed via schema
/// 3. Dangerous mutations
/// 4. Injectable arguments
/// 5. Subscription exposure
pub struct GraphQLIntrospectionScanner;

impl GraphQLIntrospectionScanner {
    pub fn new(_config: &JackSparrowConfig) -> Self {
        Self
    }

    /// Try common GraphQL endpoint paths
    fn graphql_endpoints(base_url: &str) -> Vec<String> {
        let paths = ["/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
                     "/api/graphql", "/gql", "/query", "/playground", "/altair"];
        let mut endpoints = Vec::new();
        let base = base_url.trim_end_matches('/');
        for path in &paths {
            endpoints.push(format!("{}{}", base, path));
        }
        endpoints
    }
}

#[async_trait]
impl Scanner for GraphQLIntrospectionScanner {
    fn scanner_type(&self) -> ScannerType {
        ScannerType::GraphQLIntrospection
    }

    async fn scan(
        &self,
        target: &str,
        _config: &JackSparrowConfig,
        context: &ScanContext,
    ) -> Result<Vec<Finding>, JackSparrowError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .build()?;

        let mut all_findings = Vec::new();

        // Try the base URL first, then common GraphQL paths
        let mut endpoints = vec![target.to_string()];
        endpoints.extend(Self::graphql_endpoints(target));

        for endpoint in &endpoints {
            // Skip if we already found introspection on a prior endpoint
            if all_findings.iter().any(|f: &Finding| {
                f.title.contains("Introspection enabled") && f.url == *endpoint
            }) {
                continue;
            }

            // Try POST with introspection query
            let body = json!({
                "query": INTROSPECTION_QUERY,
            });

            let mut request = client.post(endpoint)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&body);

            // Add custom headers
            for (key, value) in &context.headers {
                request = request.header(key.as_str(), value.as_str());
            }

            // Add cookies
            if let Some(ref cookies) = context.cookies {
                request = request.header("Cookie", cookies.as_str());
            }

            let response = match request.send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let _status = response.status();
            let content_type = response.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !content_type.contains("json") {
                continue;
            }

            let body_text: String = match response.text().await {
                Ok(t) => t,
                Err(_) => continue,
            };

            let json: Value = match serde_json::from_str(&body_text) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Check if introspection returned data
            if let Some(data) = json.get("data") {
                if let Some(schema) = data.get("__schema") {
                    // Introspection is enabled!
                    let type_count = schema.get("types")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);

                    let directive_count = schema.get("directives")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);

                    let mut finding = Finding::new(
                        VulnerabilityType::GraphQLIntrospection,
                        Severity::Medium,
                        Confidence::Confirmed,
                        "GraphQL introspection enabled".to_string(),
                        endpoint.to_string(),
                        "graphql-introspection-scanner".to_string(),
                    );
                    finding.description = format!(
                        "GraphQL introspection is enabled at {}. The schema exposes {} types and {} directives. \
                         This reveals the full API structure to any client.",
                        endpoint, type_count, directive_count
                    );
                    finding.evidence = Evidence {
                        request: Some(format!("POST {} HTTP/1.1\nContent-Type: application/json\n\n{}", endpoint, INTROSPECTION_QUERY)),
                        response: Some(format!("{}...", &body_text[..body_text.len().min(500)])),
                        payload: Some(INTROSPECTION_QUERY.to_string()),
                        pattern: Some("__schema".to_string()),
                        context: Some(format!("{} types, {} directives", type_count, directive_count)),
                    };
                    finding.remediation = "Disable GraphQL introspection in production. \
                        If needed, restrict it to authenticated/admin users. \
                        Consider using persisted queries or schema stitching."
                        .to_string();
                    finding.references = vec![
                        "https://graphql.org/learn/introspection/".to_string(),
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html".to_string(),
                        "https://portswigger.net/web-security/graphql".to_string(),
                    ];
                    finding.cvss_score = Some(5.3);
                    finding.cwe_id = Some("CWE-200".to_string());
                    all_findings.push(finding);

                    // Now analyze the schema for deeper issues
                    let schema_issues = analyze_schema(schema);
                    for (severity, title, description, remediation) in schema_issues {
                        let confidence = match &severity {
                            Severity::Critical | Severity::High => Confidence::Confirmed,
                            Severity::Medium => Confidence::Likely,
                            _ => Confidence::Possible,
                        };
                        let mut finding = Finding::new(
                            VulnerabilityType::GraphQLIntrospection,
                            severity.clone(),
                            confidence,
                            title,
                            endpoint.to_string(),
                            "graphql-introspection-scanner".to_string(),
                        );
                        finding.description = description;
                        finding.remediation = remediation;
                        finding.evidence = Evidence {
                            request: Some(format!("POST {} (introspection)", endpoint)),
                            response: None,
                            payload: Some(INTROSPECTION_QUERY.to_string()),
                            pattern: None,
                            context: None,
                        };
                        finding.references = vec![
                            "https://graphql.org/learn/introspection/".to_string(),
                            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html".to_string(),
                        ];
                        finding.cvss_score = match severity {
                            Severity::Critical => Some(9.0),
                            Severity::High => Some(7.5),
                            Severity::Medium => Some(5.0),
                            Severity::Low => Some(2.5),
                            Severity::Info => Some(0.0),
                        };
                        finding.cwe_id = Some("CWE-200".to_string());
                        all_findings.push(finding);
                    }

                    // Found working endpoint, no need to try others
                    break;
                }
            }

            // Check for error messages that reveal GraphQL is present
            if let Some(errors) = json.get("errors") {
                if let Some(first_error) = errors.get(0) {
                    let msg = first_error.get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // GraphQL error messages often reveal introspection is disabled
                    if msg.contains("introspection") || msg.contains("__schema") {
                        let mut finding = Finding::new(
                            VulnerabilityType::GraphQLIntrospection,
                            Severity::Info,
                            Confidence::Likely,
                            "GraphQL endpoint found (introspection disabled)".to_string(),
                            endpoint.to_string(),
                            "graphql-introspection-scanner".to_string(),
                        );
                        finding.description = format!(
                            "A GraphQL endpoint exists at {} but introspection is disabled. \
                             Error: {}",
                            endpoint, msg
                        );
                        finding.evidence = Evidence {
                            request: Some(format!("POST {}", endpoint)),
                            response: Some(body_text[..body_text.len().min(300)].to_string()),
                            payload: Some(INTROSPECTION_QUERY.to_string()),
                            pattern: Some(msg.to_string()),
                            context: None,
                        };
                        finding.remediation = "Introspection is disabled, which is good. \
                            Ensure all error messages are generic and don't leak schema info."
                            .to_string();
                        finding.cvss_score = Some(0.0);
                        all_findings.push(finding);
                    }
                }
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_schema_no_issues() {
        let schema = json!({
            "types": [
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "hello", "args": [], "type": {"name": "String", "kind": "SCALAR"}}
                ]}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        // __Schema is skipped, Query.hello is not sensitive
        assert!(issues.is_empty(), "Should have no issues, got: {:?}", issues);
    }

    #[test]
    fn test_analyze_schema_sensitive_type() {
        let schema = json!({
            "types": [
                {"name": "User", "kind": "OBJECT", "fields": [
                    {"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR"}},
                    {"name": "email", "args": [], "type": {"name": "String", "kind": "SCALAR"}}
                ]},
                {"name": "Query", "kind": "OBJECT", "fields": []}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(!issues.is_empty(), "Should detect sensitive User type");
        assert!(issues.iter().any(|(_, t, _, _)| t.contains("User")));
    }

    #[test]
    fn test_analyze_schema_sensitive_field() {
        let schema = json!({
            "types": [
                {"name": "User", "kind": "OBJECT", "fields": [
                    {"name": "password", "args": [], "type": {"name": "String", "kind": "SCALAR"}},
                    {"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR"}}
                ]},
                {"name": "Query", "kind": "OBJECT", "fields": []}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(issues.iter().any(|(_, t, _, _)| t.contains("password")));
    }

    #[test]
    fn test_analyze_schema_injectable_argument() {
        let schema = json!({
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {
                        "name": "search",
                        "args": [
                            {"name": "query", "type": {"name": "String", "kind": "SCALAR"}}
                        ],
                        "type": {"name": "String", "kind": "SCALAR"}
                    }
                ]}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(issues.iter().any(|(_, t, _, _)| t.contains("injectable")));
    }

    #[test]
    fn test_analyze_schema_dangerous_mutation() {
        let schema = json!({
            "types": [
                {"name": "Mutation", "kind": "OBJECT", "fields": [
                    {"name": "deleteUser", "args": [], "type": {"name": "Boolean", "kind": "SCALAR"}},
                    {"name": "createUser", "args": [], "type": {"name": "User", "kind": "OBJECT"}}
                ]},
                {"name": "Query", "kind": "OBJECT", "fields": []}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(issues.iter().any(|(_, t, _, _)| t.contains("deleteUser")));
    }

    #[test]
    fn test_analyze_schema_subscriptions() {
        let schema = json!({
            "types": [
                {"name": "Subscription", "kind": "OBJECT", "fields": [
                    {"name": "onMessage", "args": [], "type": {"name": "Message", "kind": "OBJECT"}}
                ]},
                {"name": "Query", "kind": "OBJECT", "fields": []}
            ],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(issues.iter().any(|(_, t, _, _)| t.contains("subscription")));
    }

    #[test]
    fn test_is_sensitive_type() {
        assert!(is_sensitive_type("User"));
        assert!(is_sensitive_type("AdminUser"));
        assert!(is_sensitive_type("AuthSession"));
        assert!(is_sensitive_type("PaymentInfo"));
        assert!(is_sensitive_type("InternalConfig"));
        assert!(!is_sensitive_type("Product"));
        assert!(!is_sensitive_type("Category"));
    }

    #[test]
    fn test_graphql_endpoints() {
        let endpoints = GraphQLIntrospectionScanner::graphql_endpoints("https://example.com");
        assert!(endpoints.contains(&"https://example.com/graphql".to_string()));
        assert!(endpoints.contains(&"https://example.com/graphiql".to_string()));
        assert!(endpoints.contains(&"https://example.com/v1/graphql".to_string()));
    }

    #[test]
    fn test_analyze_schema_empty() {
        let schema = json!({
            "types": [],
            "directives": []
        });
        let issues = analyze_schema(&schema);
        assert!(issues.is_empty());
    }
}

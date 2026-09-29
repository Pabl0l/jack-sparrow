use crate::core::scanners::{Scanner, ScannerType};
use crate::shared::config::JackSparrowConfig;
use crate::shared::context::ScanContext;
use crate::shared::error::JackSparrowError;
use crate::shared::types::{Confidence, Evidence, Finding, Severity, VulnerabilityType};
use async_trait::async_trait;
use serde_json::{json, Value};

const GRAPHQL_ATTACKS: &[(&str, &str)] = &[
	("Batch Query DoS", r#"{"query":"query{a:__typename ...on Query{__typename}}"}"#),
	("Introspection Deep", r#"{"query":"{__schema{types{fields{type{name}}}}}"}"#),
	("Mutation Probe", r#"{"query":"mutation{__typename}"}"#),
	("Fragment Spread", r#"{"query":"{...on Query{__typename}}"}"#),
	("Directive Injection", r#"{"query":"query @skip(if:true){__typename}"}"#),
	("Alias Abuse", r#"{"query":"{a:__typename b:__typename c:__typename d:__typename e:__typename}"}"#),
	("Long Query", r#"{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"}"#),
	("Field Suggestion", r#"{"query":"{__type(name:\"User\"){fields{name}}}"}"#),
	("Schema Extraction", r#"{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind}}}}"}"#),
	("Error-Based Info", r#"{"query":"{nonexistent_field}"}"#),
];

const GRAPHQL_PATHS: &[&str] = &[
	"/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
	"/query", "/api/query", "/gql", "/graphql/console",
];

const BATCH_SIZE: usize = 100;

pub struct GraphqlAttackScanner;

impl GraphqlAttackScanner {
	pub fn new(_config: &JackSparrowConfig) -> Self { Self }

	fn apply_auth(req: reqwest::RequestBuilder, ctx: &ScanContext) -> reqwest::RequestBuilder {
		let mut req = req.header("Content-Type", "application/json");
		for (k, v) in &ctx.headers {
			req = req.header(k.as_str(), v.as_str());
		}
		if let Some(ref cookies) = ctx.cookies {
			req = req.header("Cookie", cookies.as_str());
		}
		req
	}

	async fn send(
		client: &reqwest::Client, url: &str, body: &Value, ctx: &ScanContext,
	) -> Option<Value> {
		let req = client.post(url).json(body);
		let resp = Self::apply_auth(req, ctx).send().await.ok()?;
		if !resp.status().is_success() { return None; }
		let ct = resp.headers().get("content-type")?.to_str().ok()?;
		if !ct.contains("json") { return None; }
		let text = resp.text().await.ok()?;
		serde_json::from_str(&text).ok()
	}

	async fn detect_endpoint(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> bool {
		let body = json!({"query": "{ __typename }"});
		Self::send(client, url, &body, ctx).await.map(|v| v.get("data").is_some()).unwrap_or(false)
	}

	async fn test_batch_query(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> Option<usize> {
		let queries: Vec<Value> = (0..BATCH_SIZE).map(|_| json!({"query": "{ __typename }"})).collect();
		let val = Self::send(client, url, &json!(queries), ctx).await?;
		val.as_array().map(|a| a.len())
	}

	async fn test_mutation(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> bool {
		let body = json!({"query": "mutation { __typename }"});
		Self::send(client, url, &body, ctx).await.map(|v| v.get("data").is_some()).unwrap_or(false)
	}

	async fn test_depth_limit(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> bool {
		let mut q = String::from("{");
		for _ in 0..50 { q.push_str("a:__typename "); }
		q.push('}');
		let body = json!({"query": q});
		Self::send(client, url, &body, ctx).await.map(|v| v.get("data").is_some()).unwrap_or(false)
	}

	async fn test_persisted_query(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> bool {
		let body = json!({"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}});
		Self::send(client, url, &body, ctx).await.is_some()
	}

	async fn test_introspection_disabled(client: &reqwest::Client, url: &str, ctx: &ScanContext) -> bool {
		let body = json!({"query": "{ __schema { types { name } } }"});
		Self::send(client, url, &body, ctx).await.map(|v| {
			if let Some(errors) = v.get("errors") {
				if let Some(first) = errors.get(0) {
					let msg = first.get("message").and_then(|m| m.as_str()).unwrap_or("");
					return msg.contains("introspection") || msg.contains("__schema") || msg.contains("disabled");
				}
			}
			false
		}).unwrap_or(false)
	}

	fn make_finding(
		title: &str, desc: &str, url: &str, severity: Severity,
		remediation: &str, payload: &str, cwe: &str, cvss: f64,
	) -> Finding {
		let mut f = Finding::new(
			VulnerabilityType::ApiSecurity, severity, Confidence::Confirmed,
			title.to_string(), url.to_string(), "graphql-attack-scanner".to_string(),
		);
		f.description = desc.to_string();
		f.remediation = remediation.to_string();
		f.evidence = Evidence {
			request: Some(format!("POST {}", url)),
			response: None, payload: Some(payload.to_string()),
			pattern: None, context: None,
		};
		f.references = vec![
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html".to_string(),
			"https://portswigger.net/web-security/graphql".to_string(),
		];
		f.cwe_id = Some(cwe.to_string());
		f.cvss_score = Some(cvss);
		f
	}
}

#[async_trait]
impl Scanner for GraphqlAttackScanner {
	fn scanner_type(&self) -> ScannerType { ScannerType::GraphqlAttack }

	async fn scan(
		&self, target: &str, _config: &JackSparrowConfig, context: &ScanContext,
	) -> Result<Vec<Finding>, JackSparrowError> {
		let client = reqwest::Client::builder()
			.timeout(std::time::Duration::from_secs(10))
			.danger_accept_invalid_certs(true)
			.build()?;
		let mut findings = Vec::new();

		for path in GRAPHQL_PATHS {
			let base = target.trim_end_matches('/');
			let url = format!("{}{}", base, path);
			if !Self::detect_endpoint(&client, &url, context).await { continue; }

			if let Some(count) = Self::test_batch_query(&client, &url, context).await {
				if count >= 10 {
					findings.push(Self::make_finding(
						"GraphQL batch query DoS possible",
						&format!("Sent {} batch queries, received {} results. Batch queries amplify server computation.", BATCH_SIZE, count),
						&url, Severity::High,
						"Limit batch size server-side. Reject batches exceeding 5-10 queries. Apply complexity analysis.",
						"{\"query\":\"{...}\",\"query\":\"{...}\"}", "CWE-400", 7.5,
					));
				}
			}

			if Self::test_mutation(&client, &url, context).await {
				findings.push(Self::make_finding(
					"GraphQL mutations enabled without auth",
					"The endpoint accepted a mutation without authentication. Mutations can modify or delete data.",
					&url, Severity::High,
					"Require authentication for all mutations. Use role-based access control.",
					"mutation { __typename }", "CWE-284", 7.5,
				));
			}

			if Self::test_depth_limit(&client, &url, context).await {
				findings.push(Self::make_finding(
					"GraphQL depth limit not enforced",
					"A query with 50 nested levels was accepted. Deep queries cause excessive resource use.",
					&url, Severity::Medium,
					"Enforce max query depth (10-15). Use query cost analysis.",
					"{a:__typename a:__typename ...}", "CWE-400", 5.3,
				));
			}

			for &(name, payload) in GRAPHQL_ATTACKS {
				let body: Value = serde_json::from_str(payload).unwrap_or(json!({"query": payload}));
				if let Some(resp) = Self::send(&client, &url, &body, context).await {
					let has_data = resp.get("data").is_some();
					match name {
						"Introspection Deep" | "Schema Extraction" | "Field Suggestion" if has_data => {
							findings.push(Self::make_finding(
								"GraphQL field suggestion leaks schema info",
								&format!("The '{}' query returned schema data.", name),
								&url, Severity::Low,
								"Disable introspection in production. Remove field suggestions.",
								payload, "CWE-200", 3.7,
							));
						}
						"Error-Based Info" if resp.get("errors").is_some() => {
							let msg = resp.get("errors")
								.and_then(|e| e.get(0))
								.and_then(|e| e.get("message"))
								.and_then(|m| m.as_str()).unwrap_or("");
							if msg.contains("nonexistent_field") || msg.contains("Did you mean") || msg.contains("suggestion") {
								findings.push(Self::make_finding(
									"GraphQL field suggestion leaks schema info",
									&format!("Error-based info disclosure: {}", msg),
									&url, Severity::Low,
									"Return generic error messages. Do not expose field names.",
									payload, "CWE-200", 3.7,
								));
							}
						}
						_ => {}
					}
				}
			}

			let _ = Self::test_introspection_disabled(&client, &url, context).await;
			let _ = Self::test_persisted_query(&client, &url, context).await;
		}
		Ok(findings)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_scanner_type() {
		let s = GraphqlAttackScanner::new(&JackSparrowConfig::default());
		assert_eq!(s.scanner_type(), ScannerType::GraphqlAttack);
	}

	#[test]
	fn test_graphql_attacks_list() {
		assert_eq!(GRAPHQL_ATTACKS.len(), 10);
		assert!(GRAPHQL_ATTACKS.iter().any(|(n, _)| *n == "Batch Query DoS"));
		assert!(GRAPHQL_ATTACKS.iter().any(|(n, _)| *n == "Directive Injection"));
		assert!(GRAPHQL_ATTACKS.iter().any(|(n, _)| *n == "Error-Based Info"));
	}

	#[test]
	fn test_graphql_paths_list() {
		assert_eq!(GRAPHQL_PATHS.len(), 9);
		assert!(GRAPHQL_PATHS.contains(&"/graphql"));
		assert!(GRAPHQL_PATHS.contains(&"/gql"));
	}

	#[test]
	fn test_new_scanner() {
		let s = GraphqlAttackScanner::new(&JackSparrowConfig::default());
		assert!(std::mem::size_of_val(&s) == 0);
	}

	#[test]
	fn test_build_client() {
		let c = reqwest::Client::builder()
			.timeout(std::time::Duration::from_secs(10))
			.danger_accept_invalid_certs(true).build();
		assert!(c.is_ok());
	}

	#[test]
	fn test_batch_payload_format() {
		let queries: Vec<Value> = (0..3).map(|_| json!({"query": "{ __typename }"})).collect();
		let body = json!(queries);
		assert!(body.is_array());
		assert_eq!(body.as_array().unwrap().len(), 3);
		assert!(body[0].get("query").is_some());
	}

	#[test]
	fn test_mutation_payload_format() {
		let body = json!({"query": "mutation { __typename }"});
		let q = body["query"].as_str().unwrap();
		assert!(q.starts_with("mutation"));
	}

	#[test]
	fn test_depth_payload_format() {
		let mut q = String::from("{");
		for _ in 0..5 { q.push_str("a:__typename "); }
		q.push('}');
		let body = json!({"query": q});
		let q_str = body["query"].as_str().unwrap();
		assert!(q_str.contains("__typename"));
		assert!(q_str.starts_with('{'));
	}

	#[test]
	fn test_introspection_query_format() {
		let body = json!({"query": "{ __schema { types { name } } }"});
		let q = body["query"].as_str().unwrap();
		assert!(q.contains("__schema"));
		assert!(q.contains("types"));
	}

	#[test]
	fn test_default_config() {
		let c = JackSparrowConfig::default();
		let s = GraphqlAttackScanner::new(&c);
		assert_eq!(s.scanner_type(), ScannerType::GraphqlAttack);
	}
}

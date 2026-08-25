//! Router middleware completion tests.
//!
//! The fork supports one in-process middleware shape: one public model routed
//! across multiple configured upstreams. These tests keep the seam strict:
//! router middleware chooses ordered candidates, while `AciService` still owns
//! upstream verification, forwarding, and receipt finalization.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;

use async_trait::async_trait;
use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header::CONTENT_TYPE, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};
use futures_util::{stream, StreamExt};
use private_ai_gateway::aci::receipt::{UpstreamVerifiedEvent, VerificationResult};
use private_ai_gateway::aci::upstream::{
    UpstreamBackend, UpstreamError, UpstreamRequest, UpstreamResponse,
};
use private_ai_gateway::aggregator::service::{
    AciService, AciServiceConfig, FixedClock, InMemoryReceiptStore, UpstreamVerificationRequest,
    UpstreamVerifier,
};
use private_ai_gateway::aggregator::upstream_config::{
    UpstreamConfig, UpstreamConfigManager, UpstreamProvider, UpstreamRuntimeOptions,
    UpstreamVerifierMode,
};
use private_ai_gateway::middleware::errors::Surface;
use private_ai_gateway::middleware::request_transform::Endpoint;
use private_ai_gateway::middleware::{CompletionInput, Middleware, MiddlewareConfig};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use common::{event_from_request, StaticKeyProvider, StubQuoter};

#[derive(Default)]
struct CapturedCalls {
    bodies: Mutex<Vec<Value>>,
    headers: Mutex<Vec<HashMap<String, String>>>,
}

struct MockUpstream {
    status: u16,
    body: Vec<u8>,
}

#[async_trait]
impl UpstreamBackend for MockUpstream {
    fn name(&self) -> &str {
        "mock-upstream"
    }

    fn url_origin(&self) -> Option<&str> {
        Some("https://mock-upstream.example")
    }

    async fn forward(&self, _req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Ok(UpstreamResponse {
            status_code: self.status,
            body: self.body.clone(),
            headers,
            served_instance_id: None,
        })
    }
}

struct FailVerifier;

#[async_trait]
impl UpstreamVerifier for FailVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        let mut event = event_from_request(&request, VerificationResult::Failed);
        event.reason = Some("fixture verification failed".to_string());
        event
    }
}

fn temp_config_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "private-ai-gateway-{name}-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn runtime_options() -> UpstreamRuntimeOptions {
    UpstreamRuntimeOptions {
        verifier_mode: UpstreamVerifierMode::None,
        accepted_workload_ids: Vec::new(),
        accepted_image_digests: Vec::new(),
        accepted_dstack_kms_root_public_keys: Vec::new(),
        pccs_url: None,
        verifier_cache_seconds: 300,
        connect_timeout_seconds: 10,
        read_timeout_seconds: 600,
        verifier_request_timeout_seconds: 60,
    }
}

fn upstream_config(
    name: &str,
    base_url: &str,
    public_model: &str,
    upstream_model: &str,
) -> UpstreamConfig {
    UpstreamConfig {
        name: name.to_string(),
        enabled: true,
        provider: UpstreamProvider::OpenAiCompatible,
        base_url: base_url.to_string(),
        path: None,
        models: BTreeMap::from([(public_model.to_string(), upstream_model.to_string())]),
        bearer_token: None,
        accepted_workload_ids: None,
        accepted_image_digests: None,
        accepted_dstack_kms_root_public_keys: None,
        pccs_url: None,
        verifier_cache_seconds: None,
        connect_timeout_seconds: None,
        read_timeout_seconds: None,
        verifier_request_timeout_seconds: None,
        verification_refresh_seconds: None,
        session_refresh_seconds: None,
        chutes_e2ee_api_base: None,
        chutes_chute_ids: None,
        chutes_e2ee_discovery_rounds: None,
        chutes_e2ee_discovery_interval_seconds: None,
    }
}

fn upstream_manager(config: Vec<UpstreamConfig>) -> Arc<UpstreamConfigManager> {
    let path = temp_config_path("middleware-upstreams");
    let manager = UpstreamConfigManager::load(&path, runtime_options()).unwrap();
    manager.replace(config).unwrap();
    Arc::new(manager)
}

fn service_from_manager(manager: &Arc<UpstreamConfigManager>) -> Arc<AciService> {
    Arc::new(
        AciService::new_with_upstream_verifier(
            Arc::new(StaticKeyProvider::default()),
            Arc::new(StubQuoter::default()),
            manager.backend(),
            manager.verifier(),
            Arc::new(InMemoryReceiptStore::default()),
            AciServiceConfig::for_test("private-ai-gateway"),
            Arc::new(FixedClock(1_700_000_000)),
        )
        .unwrap(),
    )
}

fn service_failing_verify() -> Arc<AciService> {
    Arc::new(
        AciService::new_with_upstream_verifier(
            Arc::new(StaticKeyProvider::default()),
            Arc::new(StubQuoter::default()),
            Arc::new(MockUpstream {
                status: 200,
                body: br#"{"id":"chat-ok","object":"chat.completion","choices":[]}"#.to_vec(),
            }),
            Arc::new(FailVerifier),
            Arc::new(InMemoryReceiptStore::default()),
            AciServiceConfig::for_test("private-ai-gateway"),
            Arc::new(FixedClock(1_700_000_000)),
        )
        .unwrap(),
    )
}

async fn spawn_openai_upstream(
    id: &'static str,
    status: u16,
    body: Value,
    calls: Arc<CapturedCalls>,
) -> String {
    let response_body = Arc::new(body);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap, raw: Bytes| {
            let response_body = response_body.clone();
            let calls = calls.clone();
            async move {
                let parsed = serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null);
                calls.bodies.lock().unwrap().push(parsed);
                calls
                    .headers
                    .lock()
                    .unwrap()
                    .push(capture_headers(&headers));
                let status = StatusCode::from_u16(status).unwrap();
                let mut body = (*response_body).clone();
                if let Some(obj) = body.as_object_mut() {
                    obj.entry("id".to_string()).or_insert_with(|| json!(id));
                }
                (status, Json(body)).into_response()
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_sse_text_upstream(
    body_text: &'static str,
    calls: Arc<CapturedCalls>,
) -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap, raw: Bytes| {
            let calls = calls.clone();
            async move {
                let parsed = serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null);
                calls.bodies.lock().unwrap().push(parsed);
                calls
                    .headers
                    .lock()
                    .unwrap()
                    .push(capture_headers(&headers));
                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "text/event-stream")],
                    body_text,
                )
                    .into_response()
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_openai_streaming_upstream(id: &'static str, calls: Arc<CapturedCalls>) -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap, raw: Bytes| {
            let calls = calls.clone();
            async move {
                let parsed = serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null);
                calls.bodies.lock().unwrap().push(parsed);
                calls
                    .headers
                    .lock()
                    .unwrap()
                    .push(capture_headers(&headers));
                let first = format!(
                    "data: {{\"id\":\"{id}\",\"object\":\"chat.completion.chunk\",\
                     \"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"hi\"}}}}]}}\n\n"
                );
                let chunks = stream::once(async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<Bytes, std::io::Error>(Bytes::from(first))
                })
                .chain(stream::once(async {
                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: [DONE]\n\n"))
                }));
                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "text/event-stream")],
                    Body::from_stream(chunks),
                )
                    .into_response()
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn capture_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect()
}

fn middleware(manager: Arc<UpstreamConfigManager>, config: MiddlewareConfig) -> Middleware {
    Middleware::new(&config, manager).unwrap()
}

fn chat_input(model: &str, content: &str) -> CompletionInput {
    let params = json!({
        "model": model,
        "messages": [{ "role": "user", "content": content }]
    });
    CompletionInput {
        endpoint: Endpoint::ChatComplete,
        endpoint_path: "/v1/chat/completions",
        surface: Surface::Openai,
        received_body: serde_json::to_vec(&params).unwrap(),
        params,
        requester: None,
        e2ee: None,
        upstream_required: true,
        request_id: "req-1".to_string(),
        user_model: Some(model.to_string()),
        user_tier: None,
        stream: false,
    }
}

fn web_search_chat_input(model: &str, content: &str) -> CompletionInput {
    let mut input = chat_input(model, content);
    input.params["web_search"] = json!(true);
    input.received_body = serde_json::to_vec(&input.params).unwrap();
    input
}

async fn response_parts(response: axum::response::Response) -> (u16, axum::http::HeaderMap, Value) {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

fn route_running(snapshot: &Value, route_id: &str) -> u64 {
    snapshot["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["route_id"] == json!(route_id))
        .unwrap_or_else(|| panic!("route {route_id} not found in snapshot: {snapshot}"))["running"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn catalog_derives_single_public_model() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls).await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream, "gpt-test", "up-a"),
        upstream_config("gpu-b", &upstream, "gpt-test", "up-b"),
    ]);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, _, body) = response_parts(mw.handle_catalog("/v1/models").await).await;

    assert_eq!(status, 200);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["id"], json!("gpt-test"));
}

#[tokio::test]
async fn multiple_public_models_are_all_listed() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls).await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream, "gpt-a", "up-a"),
        upstream_config("gpu-b", &upstream, "gpt-b", "up-b"),
    ]);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, _, body) = response_parts(mw.handle_catalog("/v1/models").await).await;

    assert_eq!(status, 200);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["gpt-a", "gpt-b"]);
}

#[tokio::test]
async fn configured_public_model_is_primary_not_a_filter() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls).await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream, "gpt-a", "up-a"),
        upstream_config("gpu-b", &upstream, "gpt-b", "up-b"),
    ]);
    let mw = middleware(
        manager,
        MiddlewareConfig {
            public_model: Some("gpt-b".to_string()),
            ..Default::default()
        },
    );

    // Every servable model stays discoverable; the primary is among them.
    let (status, _, body) = response_parts(mw.handle_catalog("/v1/models").await).await;
    assert_eq!(status, 200);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["gpt-a", "gpt-b"]);
}

#[tokio::test]
async fn second_model_routes_to_its_own_upstream() {
    // Two DIFFERENT public models on two upstreams: a request for the
    // non-primary model must reach the upstream serving it, with the
    // public name rewritten to that upstream's model id.
    let calls_a = Arc::new(CapturedCalls::default());
    let calls_b = Arc::new(CapturedCalls::default());
    let upstream_a = spawn_openai_upstream(
        "chat-a",
        200,
        json!({"object":"chat.completion","model":"up-a","choices":[]}),
        calls_a.clone(),
    )
    .await;
    let upstream_b = spawn_openai_upstream(
        "chat-b",
        200,
        json!({"object":"chat.completion","model":"up-b","choices":[]}),
        calls_b.clone(),
    )
    .await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream_a, "gpt-a", "up-a"),
        upstream_config("gpu-b", &upstream_b, "glm-5.2", "zai-org/GLM-5.2-FP8"),
    ]);
    let service = service_from_manager(&manager);
    let mw = middleware(
        manager,
        MiddlewareConfig {
            public_model: Some("gpt-a".to_string()),
            ..Default::default()
        },
    );

    let (status, headers, body) = response_parts(
        mw.handle_completion(&service, chat_input("glm-5.2", "hello there"))
            .await,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], json!("chat-b"));
    assert!(headers.get("x-receipt-id").is_some());
    assert_eq!(calls_a.bodies.lock().unwrap().len(), 0);
    assert_eq!(calls_b.bodies.lock().unwrap().len(), 1);
    assert_eq!(
        calls_b.bodies.lock().unwrap()[0]["model"],
        json!("zai-org/GLM-5.2-FP8"),
        "public model must be rewritten to the upstream model id"
    );
}

#[tokio::test]
async fn wrong_model_returns_model_not_found_without_forwarding() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls.clone()).await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, _, body) = response_parts(
        mw.handle_completion(&service, chat_input("wrong-model", "hello"))
            .await,
    )
    .await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], json!("model_not_found"));
    assert!(calls.bodies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn forwarding_uses_selected_route_and_finalizes_receipt() {
    let calls_a = Arc::new(CapturedCalls::default());
    let calls_b = Arc::new(CapturedCalls::default());
    let upstream_a = spawn_openai_upstream(
        "chat-a",
        200,
        json!({"object":"chat.completion","model":"up-a","choices":[]}),
        calls_a.clone(),
    )
    .await;
    let upstream_b = spawn_openai_upstream(
        "chat-b",
        200,
        json!({"object":"chat.completion","model":"up-b","choices":[]}),
        calls_b.clone(),
    )
    .await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream_a, "gpt-test", "up-a"),
        upstream_config("gpu-b", &upstream_b, "gpt-test", "up-b"),
    ]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, headers, body) = response_parts(
        mw.handle_completion(&service, chat_input("gpt-test", "stable prefix one"))
            .await,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], json!("chat-a"));
    assert!(headers.get("x-receipt-id").is_some());
    assert_eq!(calls_a.bodies.lock().unwrap().len(), 1);
    assert_eq!(calls_b.bodies.lock().unwrap().len(), 0);
    assert_eq!(
        calls_a.bodies.lock().unwrap()[0]["model"],
        json!("up-a"),
        "selected route must rewrite the public model to its upstream model"
    );
}

#[tokio::test]
async fn disabled_upstream_is_visible_but_not_routed() {
    let calls_disabled = Arc::new(CapturedCalls::default());
    let calls_active = Arc::new(CapturedCalls::default());
    let disabled_url = spawn_openai_upstream(
        "chat-disabled",
        200,
        json!({"object":"chat.completion","model":"up-disabled","choices":[]}),
        calls_disabled.clone(),
    )
    .await;
    let active_url = spawn_openai_upstream(
        "chat-active",
        200,
        json!({"object":"chat.completion","model":"up-active","choices":[]}),
        calls_active.clone(),
    )
    .await;
    let mut disabled = upstream_config("gpu-a", &disabled_url, "gpt-test", "up-disabled");
    disabled.enabled = false;
    let manager = upstream_manager(vec![
        disabled,
        upstream_config("gpu-b", &active_url, "gpt-test", "up-active"),
    ]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, _, body) = response_parts(
        mw.handle_completion(&service, chat_input("gpt-test", "hello"))
            .await,
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(body["id"], json!("chat-active"));
    assert_eq!(calls_disabled.bodies.lock().unwrap().len(), 0);
    assert_eq!(calls_active.bodies.lock().unwrap().len(), 1);

    let snapshot = mw.admin_snapshot().unwrap();
    let disabled_route = snapshot["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["route_id"] == json!("gpu-a:gpt-test"))
        .unwrap();
    assert_eq!(disabled_route["enabled"], json!(false));
}

#[tokio::test]
async fn untrusted_user_tier_header_is_not_forwarded_by_default() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream(
        "chat-a",
        200,
        json!({"object":"chat.completion","model":"up-a","choices":[]}),
        calls.clone(),
    )
    .await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());
    let mut input = chat_input("gpt-test", "hello");
    input.user_tier = Some("premium".to_string());

    let (status, _, _) = response_parts(mw.handle_completion(&service, input).await).await;

    assert_eq!(status, 200);
    let headers = calls.headers.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert!(
        !headers[0].contains_key("x-user-tier"),
        "untrusted public x-user-tier must not reach PIG"
    );
}

#[tokio::test]
async fn trusted_user_tier_header_is_forwarded_when_enabled() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream(
        "chat-a",
        200,
        json!({"object":"chat.completion","model":"up-a","choices":[]}),
        calls.clone(),
    )
    .await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let service = service_from_manager(&manager);
    let mw = middleware(
        manager,
        MiddlewareConfig {
            trusted_user_tier_header: true,
            ..Default::default()
        },
    );
    let mut input = chat_input("gpt-test", "hello");
    input.user_tier = Some("premium".to_string());

    let (status, _, _) = response_parts(mw.handle_completion(&service, input).await).await;

    assert_eq!(status, 200);
    let headers = calls.headers.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(
        headers[0].get("x-user-tier").map(String::as_str),
        Some("premium")
    );
}

#[tokio::test]
async fn cache_aware_selection_keeps_similar_prefix_on_same_route() {
    let calls_a = Arc::new(CapturedCalls::default());
    let calls_b = Arc::new(CapturedCalls::default());
    let upstream_a = spawn_openai_upstream(
        "chat-a",
        200,
        json!({"object":"chat.completion","model":"up-a","choices":[]}),
        calls_a.clone(),
    )
    .await;
    let upstream_b = spawn_openai_upstream(
        "chat-b",
        200,
        json!({"object":"chat.completion","model":"up-b","choices":[]}),
        calls_b.clone(),
    )
    .await;
    let manager = upstream_manager(vec![
        upstream_config("gpu-a", &upstream_a, "gpt-test", "up-a"),
        upstream_config("gpu-b", &upstream_b, "gpt-test", "up-b"),
    ]);
    let service = service_from_manager(&manager);
    let mw = middleware(
        manager,
        MiddlewareConfig {
            cache_threshold: 0.25,
            ..Default::default()
        },
    );

    let (first_status, _, first_body) = response_parts(
        mw.handle_completion(&service, chat_input("gpt-test", "shared prefix aaa"))
            .await,
    )
    .await;
    let (second_status, _, second_body) = response_parts(
        mw.handle_completion(&service, chat_input("gpt-test", "shared prefix bbb"))
            .await,
    )
    .await;

    assert_eq!(first_status, 200);
    assert_eq!(second_status, 200);
    assert_eq!(first_body["id"], json!("chat-a"));
    assert_eq!(second_body["id"], json!("chat-a"));
    assert_eq!(calls_a.bodies.lock().unwrap().len(), 2);
    assert_eq!(calls_b.bodies.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn streaming_running_count_stays_until_body_is_consumed() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_streaming_upstream("chat-stream", calls).await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());
    let mut input = chat_input("gpt-test", "streaming request");
    input.stream = true;
    input.params["stream"] = json!(true);
    input.received_body = serde_json::to_vec(&input.params).unwrap();

    let response = mw.handle_completion(&service, input).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        route_running(&mw.admin_snapshot().unwrap(), "gpu-a:gpt-test"),
        1
    );

    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    assert_eq!(
        route_running(&mw.admin_snapshot().unwrap(), "gpu-a:gpt-test"),
        0
    );
}

#[tokio::test]
async fn upstream_verification_failure_fails_closed_before_forwarding() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls.clone()).await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let mw = middleware(manager, MiddlewareConfig::default());

    let (status, _, body) = response_parts(
        mw.handle_completion(&service_failing_verify(), chat_input("gpt-test", "hello"))
            .await,
    )
    .await;

    assert_eq!(status, 503);
    assert_eq!(body["error"]["type"], json!("service_unavailable"));
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("fixture verification failed"));
    assert!(calls.bodies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn image_fetch_5xx_becomes_client_400() {
    let url = "https://halleonard.example/wl/02116757-wl.jpg";
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream(
        "bad-image",
        500,
        json!({
            "error": {
                "message": format!("403, message='Forbidden', url='{url}'"),
                "type": "InternalServerError",
                "code": 500
            }
        }),
        calls,
    )
    .await;
    let manager = upstream_manager(vec![upstream_config(
        "gpu-a", &upstream, "gpt-test", "up-a",
    )]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default());
    let mut input = chat_input("gpt-test", "describe");
    input.params = json!({
        "model": "gpt-test",
        "messages": [{
            "role": "user",
            "content": [
                { "type": "text", "text": "describe" },
                { "type": "image_url", "image_url": { "url": url } }
            ]
        }]
    });
    input.received_body = serde_json::to_vec(&input.params).unwrap();

    let (status, _, body) = response_parts(mw.handle_completion(&service, input).await).await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], json!("invalid_request_error"));
    assert!(body["error"]["message"].as_str().unwrap().contains(url));
}

#[tokio::test]
async fn web_search_flag_aggregates_upstream_stream_and_discloses_queries() {
    // A non-streaming client opts in with web_search:true. The gateway must
    // send the upstream a STREAMING request carrying the search tool (and no
    // flag), then fold the SSE reply into one JSON that lists every query.
    const SSE: &str = concat!(
        "data: {\"id\":\"cmpl-ws\",\"model\":\"up-a\",\"created\":7,\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"web_context_search\",\"arguments\":\"{\\\"query\\\": \\\"tokyo population 2026\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"nearai_tool_result\":{\"name\":\"web_context_search\",\"output\":\"[1] ...\"}}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"About 37 million.\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":4,\"total_tokens\":13}}\n\n",
        "data: [DONE]\n\n",
    );
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_sse_text_upstream(SSE, calls.clone()).await;
    let manager = upstream_manager(vec![upstream_config("gpu-a", &upstream, "gpt-test", "up-a")]);
    let service = service_from_manager(&manager);
    let mw = middleware(
        manager,
        MiddlewareConfig {
            web_search_enabled: true,
            ..Default::default()
        },
    );

    let (status, headers, body) = response_parts(
        mw.handle_completion(&service, web_search_chat_input("gpt-test", "tokyo?"))
            .await,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(headers.get("x-receipt-id").is_some());
    // Aggregated single JSON, not SSE:
    assert_eq!(body["object"], json!("chat.completion"));
    assert_eq!(
        body["choices"][0]["message"]["content"],
        json!("About 37 million.")
    );
    assert_eq!(body["usage"]["total_tokens"], json!(13));
    // The disclosure — exactly what left the enclave:
    assert_eq!(body["web_searches"][0]["query"], json!("tokyo population 2026"));

    // The upstream request was reshaped: tool present, stream forced, flag gone.
    let sent = &calls.bodies.lock().unwrap()[0];
    assert_eq!(sent["stream"], json!(true));
    assert!(sent.get("web_search").is_none());
    let tool_types: Vec<&str> = sent["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["type"].as_str())
        .collect();
    assert!(tool_types.contains(&"web_context_search"));
    // …and the model is told in-band that search is already on, so it never
    // asks the user to enable it.
    let enabled_note = sent["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| {
            m["role"] == json!("system")
                && m["content"]
                    .as_str()
                    .is_some_and(|c| c.contains("Web search is ENABLED"))
        });
    assert!(enabled_note, "missing enabled note: {sent}");
}

#[tokio::test]
async fn web_search_flag_is_refused_when_operator_disabled() {
    let calls = Arc::new(CapturedCalls::default());
    let upstream = spawn_openai_upstream("up-a", 200, json!({}), calls.clone()).await;
    let manager = upstream_manager(vec![upstream_config("gpu-a", &upstream, "gpt-test", "up-a")]);
    let service = service_from_manager(&manager);
    let mw = middleware(manager, MiddlewareConfig::default()); // web_search_enabled: false

    let (status, _, body) = response_parts(
        mw.handle_completion(&service, web_search_chat_input("gpt-test", "hello"))
            .await,
    )
    .await;

    assert_eq!(status, 400);
    assert_eq!(body["error"]["type"], json!("web_search_disabled"));
    assert!(calls.bodies.lock().unwrap().is_empty(), "must not reach the upstream");
}

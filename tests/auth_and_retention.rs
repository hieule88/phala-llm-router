//! Coverage for the new authn/authz layer on receipts
//! and the ACI headers stamped on every response.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod common;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use private_ai_gateway::aci::types::ServiceCapabilities;
use private_ai_gateway::aci::upstream::{
    UpstreamBackend, UpstreamError, UpstreamRequest, UpstreamResponse,
};
use private_ai_gateway::aci::verifier::PreverifiedUpstreamVerifier;
use private_ai_gateway::aggregator::service::{
    AciService, AciServiceConfig, FixedClock, InMemoryReceiptStore,
};
use private_ai_gateway::aggregator::upstream_config::{
    UpstreamConfigManager, UpstreamRuntimeOptions, UpstreamVerifierMode,
};
use private_ai_gateway::http::{build_router, build_router_with_admin_and_api};
use serde_json::Value;
use tower::ServiceExt;

use common::{StaticKeyProvider, StubQuoter};

const CHAT_REQUEST: &[u8] =
    br#"{"model":"aci-model","messages":[{"role":"user","content":"hello"}]}"#;
const CHAT_RESPONSE: &[u8] = br#"{"id":"chat-auth-1","object":"chat.completion","choices":[]}"#;

struct StubUpstream;

#[async_trait]
impl UpstreamBackend for StubUpstream {
    fn name(&self) -> &str {
        "stub-upstream"
    }
    fn url_origin(&self) -> Option<&str> {
        Some("https://stub-upstream.example")
    }
    async fn forward(&self, _req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Ok(UpstreamResponse {
            status_code: 200,
            body: CHAT_RESPONSE.to_vec(),
            headers,
            served_instance_id: None,
        })
    }
}

struct Harness {
    service: Arc<AciService>,
    router: axum::Router,
    clock: Arc<TestClock>,
}

struct TestClock {
    inner: Mutex<u64>,
}

impl TestClock {
    fn new(t0: u64) -> Self {
        Self {
            inner: Mutex::new(t0),
        }
    }
    fn advance(&self, by: u64) {
        let mut guard = self.inner.lock().unwrap();
        *guard += by;
    }
}

impl private_ai_gateway::aggregator::service::Clock for TestClock {
    fn now_secs(&self) -> u64 {
        *self.inner.lock().unwrap()
    }
}

fn harness() -> Harness {
    harness_with_ttl(3600)
}

/// Like [`harness`], but the router is built with an `api_token` so
/// `enforce_api` gates the inference surface. Chat still hits
/// [`StubUpstream`] through the service; the temp upstream-config manager
/// only backs the admin/catalog routes.
fn harness_with_api_token(api_token: &str) -> Harness {
    let mut h = harness_with_ttl(3600);
    let path = std::env::temp_dir().join(format!(
        "auth-retention-upstreams-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let manager = Arc::new(
        UpstreamConfigManager::load(
            &path,
            UpstreamRuntimeOptions {
                verifier_mode: UpstreamVerifierMode::Preverified,
                accepted_workload_ids: vec![],
                accepted_image_digests: vec![],
                accepted_dstack_kms_root_public_keys: vec![],
                pccs_url: None,
                verifier_cache_seconds: 300,
                connect_timeout_seconds: 10,
                read_timeout_seconds: 600,
                verifier_request_timeout_seconds: 60,
            },
        )
        .unwrap(),
    );
    h.router = build_router_with_admin_and_api(
        h.service.clone(),
        manager,
        None,
        Some(api_token.to_string()),
    );
    h
}

fn harness_with_ttl(receipt_ttl_seconds: u64) -> Harness {
    let keys = Arc::new(StaticKeyProvider::default());
    let quoter = Arc::new(StubQuoter::default());
    let upstream = Arc::new(StubUpstream);
    let verifier = Arc::new(PreverifiedUpstreamVerifier::new("test-verifier/v1"));
    let mut cfg = AciServiceConfig::for_test("auth-and-retention");
    cfg.service_capabilities = ServiceCapabilities {
        supported_e2ee_versions: vec![],
    };
    cfg.receipt_ttl_seconds = receipt_ttl_seconds;
    let clock = Arc::new(TestClock::new(1_700_000_000));
    let service = Arc::new(
        AciService::new_with_upstream_verifier(
            keys,
            quoter,
            upstream,
            verifier,
            Arc::new(InMemoryReceiptStore::default()),
            cfg,
            clock.clone(),
        )
        .unwrap(),
    );
    Harness {
        router: build_router(service.clone()),
        service,
        clock,
    }
}

async fn call(router: &axum::Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

// ---------- Receipt auth ----------

#[tokio::test]
async fn anonymous_receipt_is_publicly_retrievable() {
    let h = harness();
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rid = headers.get("x-receipt-id").unwrap().to_str().unwrap();

    // No Authorization on the lookup; should succeed because the
    // receipt has no recorded owner.
    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["receipt"]["receipt_id"], rid);
    assert_eq!(json(&body)["receipt"]["chat_id"], "chat-auth-1");
    assert!(json(&body)["signature"].is_string());
}

#[tokio::test]
async fn owned_receipt_lookup_unauthenticated_returns_401() {
    let h = harness();
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", "Bearer requester-a")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let _rid = headers.get("x-receipt-id").unwrap().to_str().unwrap();

    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["error"]["type"], "unauthorized");
}

#[tokio::test]
async fn owned_receipt_lookup_wrong_bearer_returns_403() {
    let h = harness();
    let (_, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", "Bearer requester-a")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    let _rid = headers.get("x-receipt-id").unwrap().to_str().unwrap();

    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .header("authorization", "Bearer requester-b")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json(&body)["error"]["type"], "redaction_required");
}

#[tokio::test]
async fn owned_receipt_lookup_with_matching_bearer_returns_receipt() {
    let h = harness();
    let (_, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", "Bearer requester-a")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    let rid = headers.get("x-receipt-id").unwrap().to_str().unwrap();

    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .header("authorization", "Bearer requester-a")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["receipt"]["receipt_id"], rid);
}

// ---------- Service token on x-gateway-token (multiplexing front) ----------

/// A multiplexing front (the Edge) authenticates with `x-gateway-token` and
/// keeps `Authorization` for the END USER's bearer — the receipt must be
/// owned by that user bearer, not by the service token.
#[tokio::test]
async fn x_gateway_token_authenticates_and_bearer_owns_the_receipt() {
    let h = harness_with_api_token("api-secret");

    // No credentials at all → the api gate rejects.
    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["error"]["type"], "unauthorized");

    // Wrong x-gateway-token + a tenant bearer → falls through to the bearer
    // check, which does not match the api token either.
    let (status, _, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("x-gateway-token", "wrong-secret")
            .header("authorization", "Bearer tenant-a")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Correct x-gateway-token + tenant bearer → served, receipt owned by tenant.
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("x-gateway-token", "api-secret")
            .header("authorization", "Bearer tenant-a")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rid = headers
        .get("x-receipt-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // The tenant that chatted can fetch its receipt.
    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri(format!("/v1/aci/receipts/{rid}"))
            .header("authorization", "Bearer tenant-a")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["receipt_id"], rid.as_str());

    // Another tenant cannot.
    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri(format!("/v1/aci/receipts/{rid}"))
            .header("authorization", "Bearer tenant-b")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json(&body)["error"]["type"], "redaction_required");

    // Neither can the service token itself (it is NOT the owner).
    let (status, _, _) = call(
        &h.router,
        Request::builder()
            .uri(format!("/v1/aci/receipts/{rid}"))
            .header("authorization", "Bearer api-secret")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Anonymous lookup of an owned receipt still 401s.
    let (status, _, _) = call(
        &h.router,
        Request::builder()
            .uri(format!("/v1/aci/receipts/{rid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Classic single-tenant callers (token on Authorization) keep working
/// unchanged after the x-gateway-token addition.
#[tokio::test]
async fn api_token_on_authorization_still_authenticates() {
    let h = harness_with_api_token("api-secret");
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", "Bearer api-secret")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("x-receipt-id").is_some());
}

// ---------- Receipt TTL ----------

#[tokio::test]
async fn receipt_expires_after_store_ttl() {
    let h = harness_with_ttl(30);
    let (_, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    let rid = headers.get("x-receipt-id").unwrap().to_str().unwrap();

    let (status, _, _) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    h.clock.advance(31);

    let (status, _, body) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/chat-auth-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"]["type"], "not_found");
    assert!(h.service.get_receipt_by_receipt_id(rid).is_none());
}

// ---------- X-ACI headers everywhere ----------

#[tokio::test]
async fn aci_headers_present_on_success_responses() {
    let h = harness();
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .uri("/v1/attestation/report")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-aci-version").unwrap(), "aci/1");
    assert_eq!(
        headers.get("x-aci-identity").unwrap(),
        h.service.workload_id()
    );
    assert_eq!(
        headers.get("x-aci-keyset-digest").unwrap(),
        h.service.workload_keyset_digest()
    );
}

#[tokio::test]
async fn aci_headers_present_on_not_found_error() {
    let h = harness();
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .uri("/v1/signature/nope")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        headers.get("x-aci-identity").unwrap(),
        h.service.workload_id()
    );
    assert_eq!(
        headers.get("x-aci-keyset-digest").unwrap(),
        h.service.workload_keyset_digest()
    );
}

#[tokio::test]
async fn aci_headers_present_on_bad_request_error() {
    let h = harness();
    let (status, headers, _) = call(
        &h.router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from("not json".as_bytes().to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        headers.get("x-aci-identity").unwrap(),
        h.service.workload_id()
    );
}

// ---------- StaticUpstreamVerifier ----------

#[tokio::test]
async fn static_verifier_failed_with_required_blocks_forwarding() {
    use private_ai_gateway::aci::verifier::StaticUpstreamVerifier;
    let keys = Arc::new(StaticKeyProvider::default());
    let quoter = Arc::new(StubQuoter::default());
    let upstream = Arc::new(StubUpstream);
    let verifier = Arc::new(StaticUpstreamVerifier::failed(
        "test-verifier/v1",
        "deliberate failure",
    ));
    let mut cfg = AciServiceConfig::for_test("static-failed");
    cfg.service_capabilities = ServiceCapabilities::default();
    let svc = Arc::new(
        AciService::new_with_upstream_verifier(
            keys,
            quoter,
            upstream,
            verifier,
            Arc::new(InMemoryReceiptStore::default()),
            cfg,
            Arc::new(FixedClock(1_700_000_000)),
        )
        .unwrap(),
    );
    let router = build_router(svc);
    let (status, _, body) = call(
        &router,
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(CHAT_REQUEST.to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(&body)["error"]["type"], "upstream_verification_failed");
}

//! Completion forwarding for the single-model router middleware.
//!
//! The router chooses ordered candidates. `AciService` still validates the
//! route, verifies the upstream, enforces channel binding, forwards the request,
//! and finalizes receipts/E2EE.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{Stream, StreamExt};
use serde_json::Value;

use crate::aci::upstream::UpstreamError;
use crate::aggregator::service::{
    AciService, ChatCompletionRequest, E2eeRequestContext, E2eeResponseInfo, ForwardCandidate,
    GatewayRequestContext, MiddlewareForwardResult, MiddlewareReceiptJournal, ReceiptOwner,
    ServiceError, ServiceResponseStream,
};

use super::config::MiddlewareConfig;
use super::errors::{self, Surface};
use super::request_transform::{build_candidates, inject_default_system_prompt, Endpoint};
use super::router::RouteInFlight;
use super::sse::KeepAliveStream;
use super::stream_transform::SseTransformStream;
use super::types::{ProviderFormat, RouteCandidate};
use super::{response_transform, stream_transform, web_search};

/// Everything the completion path needs, computed by the HTTP handler after E2EE
/// termination and JSON normalization.
pub struct CompletionInput {
    pub endpoint: Endpoint,
    pub endpoint_path: &'static str,
    pub surface: Surface,
    /// Normalized request body used for routing + transforms.
    pub params: Value,
    /// Exact cleartext bytes the service observed (recorded into the receipt).
    pub received_body: Vec<u8>,
    pub requester: Option<ReceiptOwner>,
    pub e2ee: Option<E2eeRequestContext>,
    pub upstream_required: bool,
    pub request_id: String,
    pub user_model: Option<String>,
    pub user_tier: Option<String>,
    pub stream: bool,
}

const MAX_LOG_DETAIL_CHARS: usize = 240;

#[derive(Clone, Copy)]
struct OutcomeCtx<'a> {
    request_id: &'a str,
    model: &'a str,
    started: Instant,
}

fn should_log_failure(status: u16) -> bool {
    status != 429
}

fn sanitize_log_value(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max_chars)
        .collect()
}

fn detail_snippet_bytes(raw: &[u8]) -> String {
    let capped = &raw[..raw.len().min(4 * MAX_LOG_DETAIL_CHARS)];
    String::from_utf8_lossy(capped)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_LOG_DETAIL_CHARS)
        .collect()
}

fn detail_snippet_text(raw: &str) -> String {
    sanitize_log_value(raw, MAX_LOG_DETAIL_CHARS)
}

fn debug_gated_detail(detail: &str) -> &str {
    if tracing::enabled!(target: "request_outcome", tracing::Level::DEBUG) {
        detail
    } else {
        ""
    }
}

fn log_generated_outcome(
    ctx: OutcomeCtx<'_>,
    phase: &'static str,
    status: u16,
    upstream_status: u16,
    route: &str,
    attempt: u32,
    detail: &str,
) {
    if !should_log_failure(status) {
        return;
    }
    tracing::info!(
        target: "request_outcome",
        request_id = %ctx.request_id,
        model = %sanitize_log_value(ctx.model, 128),
        route = %sanitize_log_value(route, 128),
        attempt,
        status,
        upstream_status,
        phase,
        duration_ms = ctx.started.elapsed().as_millis() as u64,
        detail = %debug_gated_detail(detail),
        "request outcome"
    );
}

fn log_failed_attempts(ctx: OutcomeCtx<'_>, attempts: &[(String, u16)], is_streaming: bool) {
    for (index, (route, status)) in attempts.iter().enumerate() {
        if !should_log_failure(*status) {
            continue;
        }
        tracing::info!(
            target: "request_outcome",
            request_id = %ctx.request_id,
            model = %sanitize_log_value(ctx.model, 128),
            route = %sanitize_log_value(route, 128),
            attempt = index as u32,
            status = *status,
            upstream_status = *status,
            phase = "attempt_failed",
            is_streaming,
            duration_ms = ctx.started.elapsed().as_millis() as u64,
            "middleware candidate failed"
        );
    }
}

pub(super) async fn run(
    service: &AciService,
    config: &MiddlewareConfig,
    input: CompletionInput,
    candidates: Vec<RouteCandidate>,
    mut route_in_flight: Option<RouteInFlight>,
) -> Response {
    let started = Instant::now();
    let CompletionInput {
        endpoint,
        endpoint_path,
        surface,
        mut params,
        received_body,
        requester,
        e2ee,
        upstream_required,
        request_id,
        user_model,
        user_tier,
        stream,
    } = input;

    // Operator default system prompt (cutoff disclosure / no-fabrication
    // policy). Chat-shaped endpoints only; the receipt's request.received
    // hash was already fixed to the client's exact bytes upstream of here.
    if matches!(endpoint, Endpoint::ChatComplete | Endpoint::Messages) {
        if let Some(prompt) = config.default_system_prompt.as_deref() {
            inject_default_system_prompt(&mut params, prompt);
        }
    }

    // Per-request web search opt-in (web_search.rs). The flag is stripped
    // unconditionally; whether it takes effect is the operator's call.
    let mut aggregate_web_search = false;
    let mut web_search_rejected = false;
    if matches!(endpoint, Endpoint::ChatComplete) && web_search::take_request_flag(&mut params) {
        if config.web_search_enabled {
            web_search::prepare_upstream_params(&mut params);
            // A streaming client sees the search activity in its own stream;
            // a buffered client needs the stream folded back into one JSON.
            aggregate_web_search = !stream;
        } else {
            web_search_rejected = true;
        }
    }

    let model = params.get("model").and_then(Value::as_str);
    let outcome_ctx = OutcomeCtx {
        request_id: &request_id,
        model: model.unwrap_or(""),
        started,
    };
    if web_search_rejected {
        let message = "web search is not enabled on this gateway";
        log_generated_outcome(outcome_ctx, "web_search", 400, 0, "", 0, message);
        let body = errors::envelope_bytes(surface, "web_search_disabled", message, Some(&request_id));
        return finalize_generated(surface, service, endpoint_path, 400, body, &[], e2ee);
    }
    if candidates.is_empty() {
        let message = format!("no route available for model {}", model.unwrap_or("(none)"));
        log_generated_outcome(outcome_ctx, "routing", 400, 0, "", 0, &message);
        let body = errors::envelope_bytes(surface, "model_not_found", &message, Some(&request_id));
        return finalize_generated(surface, service, endpoint_path, 400, body, &[], e2ee);
    }

    let shaped = match build_candidates(&params, endpoint, &candidates) {
        Ok(shaped) => shaped,
        Err(err) => {
            let message = format!("failed to shape provider request: {err}");
            log_generated_outcome(outcome_ctx, "shaping", 500, 0, "", 0, &message);
            let body = errors::envelope_bytes(
                surface,
                errors::error_type(surface, 500),
                &message,
                Some(&request_id),
            );
            return finalize_generated(surface, service, endpoint_path, 500, body, &[], e2ee);
        }
    };
    let forward_candidates: Vec<ForwardCandidate> = shaped
        .into_iter()
        .map(|(route_id, body)| ForwardCandidate {
            route_id,
            body: serde_json::to_vec(&body).unwrap_or_default(),
        })
        .collect();

    let context = GatewayRequestContext {
        request_id: request_id.clone(),
        user_model,
        target_route_id: None,
        user_tier,
    };

    let journal = MiddlewareReceiptJournal::default();
    let result = service
        .forward_chat_completion_for_middleware(
            ChatCompletionRequest {
                context,
                endpoint_path,
                received_body: &received_body,
                forwarded_body: None,
                upstream_required: Some(upstream_required),
                upstream_verification_event: None,
                requester: requester.clone(),
                e2ee: e2ee.clone(),
            },
            forward_candidates,
            stream,
            journal.clone(),
        )
        .await;

    match result {
        Ok(MiddlewareForwardResult::Forwarded(forward)) => {
            if let Some(in_flight) = route_in_flight.as_mut() {
                in_flight.retarget(&forward.selected_route);
            }
            let upstream_status = forward.upstream_status;
            let selected_format = candidates
                .iter()
                .find(|c| c.route_id == forward.selected_route)
                .or_else(|| candidates.first())
                .map(|c| c.format)
                .unwrap_or(ProviderFormat::Openai);

            let (client_status, final_body) = if (200..300).contains(&upstream_status) {
                let parsed: Option<Value> = if aggregate_web_search {
                    // The upstream replied with an SSE stream (we forced
                    // stream:true for the search tool); fold it back into one
                    // chat.completion carrying the `web_searches` disclosure.
                    web_search::aggregate_stream(&forward.upstream_body)
                } else {
                    serde_json::from_slice(&forward.upstream_body).ok()
                };
                let upstream_json: Value = match parsed {
                    Some(value) => value,
                    None => {
                        let message = "upstream returned a malformed success body";
                        log_generated_outcome(
                            outcome_ctx,
                            "buffered_transform",
                            502,
                            upstream_status,
                            &forward.selected_route,
                            forward.failed_attempts.len() as u32,
                            message,
                        );
                        let body = errors::envelope_bytes(
                            surface,
                            errors::error_type(surface, 502),
                            message,
                            Some(&request_id),
                        );
                        return finalize_generated(
                            surface,
                            service,
                            endpoint_path,
                            502,
                            body,
                            &[],
                            e2ee,
                        );
                    }
                };
                let transformed = response_transform::transform_response(
                    selected_format,
                    endpoint,
                    upstream_json,
                );
                (
                    upstream_status,
                    serde_json::to_vec(&transformed).unwrap_or_default(),
                )
            } else {
                errors::normalize_upstream_error_parts(
                    surface,
                    upstream_status,
                    &forward.upstream_body,
                    &received_body,
                    Some(&request_id),
                )
            };
            if client_status >= 400 {
                log_failed_attempts(outcome_ctx, &forward.failed_attempts, false);
                let detail = detail_snippet_bytes(&forward.upstream_body);
                log_generated_outcome(
                    outcome_ctx,
                    "buffered_upstream",
                    client_status,
                    upstream_status,
                    &forward.selected_route,
                    forward.failed_attempts.len() as u32,
                    &detail,
                );
            }

            match service.finalize_middleware_receipt(
                forward.receipt,
                &final_body,
                Some("application/json"),
                requester,
                e2ee,
            ) {
                Ok(finalized) => {
                    let status =
                        StatusCode::from_u16(client_status).unwrap_or(StatusCode::BAD_GATEWAY);
                    let mut headers =
                        response_headers(&forward.upstream_headers, "application/json");
                    insert_header(&mut headers, "x-receipt-id", &finalized.receipt.receipt_id);
                    apply_e2ee_headers(&mut headers, finalized.e2ee.as_ref());
                    (status, headers, finalized.wire_body).into_response()
                }
                Err(err) => {
                    let status = forward_error_status(&err);
                    let detail = detail_snippet_text(&err.to_string());
                    log_generated_outcome(
                        outcome_ctx,
                        "finalize_buffered",
                        status,
                        upstream_status,
                        &forward.selected_route,
                        forward.failed_attempts.len() as u32,
                        &detail,
                    );
                    service_error_response(surface, endpoint_path, service, &request_id, err, None)
                }
            }
        }
        Ok(MiddlewareForwardResult::Stream(forward)) => {
            if let Some(in_flight) = route_in_flight.as_mut() {
                in_flight.retarget(&forward.selected_route);
            }
            let content_type = forward
                .upstream_headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "text/event-stream".to_string());
            let upstream_status = forward.upstream_status;
            let selected_format = candidates
                .iter()
                .find(|c| c.route_id == forward.selected_route)
                .or_else(|| candidates.first())
                .map(|c| c.format)
                .unwrap_or(ProviderFormat::Openai);
            let transformed: ServiceResponseStream =
                match stream_transform::select_stream_transform(selected_format, endpoint) {
                    Some(transform) => Box::pin(SseTransformStream::new(forward.body, transform)),
                    None => forward.body,
                };
            let keepalive = match config.sse_keepalive_ms.unwrap_or(10_000) {
                0 => None,
                ms => Some(Duration::from_millis(ms)),
            };
            let kept: ServiceResponseStream =
                Box::pin(KeepAliveStream::new(transformed, keepalive));

            let receipt_id = journal.peek_receipt_id();
            match service.finalize_middleware_response_stream(
                journal,
                kept,
                endpoint_path,
                Some(&content_type),
                requester,
                e2ee,
            ) {
                Ok(finalized) => {
                    let status =
                        StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
                    let mut headers = response_headers(&forward.upstream_headers, &content_type);
                    match &receipt_id {
                        Some(receipt_id) => {
                            insert_header(&mut headers, "x-receipt-id", receipt_id);
                            apply_e2ee_headers(&mut headers, finalized.e2ee.as_ref());
                        }
                        None => apply_e2ee_headers(&mut headers, finalized.e2ee.as_ref()),
                    }
                    headers.insert(
                        HeaderName::from_static("x-accel-buffering"),
                        HeaderValue::from_static("no"),
                    );
                    headers.insert(
                        HeaderName::from_static("cache-control"),
                        HeaderValue::from_static("no-cache"),
                    );
                    let guarded: ServiceResponseStream = Box::pin(InFlightStream {
                        inner: finalized.body,
                        _route_in_flight: route_in_flight.take(),
                    });
                    let stream_request_id = request_id.clone();
                    let body = Body::from_stream(guarded.scan((), move |_, chunk| {
                        std::future::ready(match chunk {
                            Ok(bytes) => Some(Ok::<_, std::io::Error>(bytes)),
                            Err(err) => {
                                tracing::warn!(
                                    target: "stream_abort",
                                    request_id = %stream_request_id,
                                    error = %err,
                                    "response stream error; ending body gracefully"
                                );
                                None
                            }
                        })
                    }));
                    (status, headers, body).into_response()
                }
                Err(err) => {
                    let status = forward_error_status(&err);
                    let detail = detail_snippet_text(&err.to_string());
                    log_generated_outcome(
                        outcome_ctx,
                        "finalize_stream",
                        status,
                        upstream_status,
                        &forward.selected_route,
                        forward.failed_attempts.len() as u32,
                        &detail,
                    );
                    service_error_response(surface, endpoint_path, service, &request_id, err, None)
                }
            }
        }
        Ok(MiddlewareForwardResult::UpstreamError(forward)) => {
            if let Some(in_flight) = route_in_flight.as_mut() {
                in_flight.retarget(&forward.selected_route);
            }
            let (status, body) = errors::normalize_upstream_error_parts(
                surface,
                forward.error.upstream_status,
                &forward.error.upstream_body,
                &received_body,
                Some(&request_id),
            );
            log_failed_attempts(outcome_ctx, &forward.failed_attempts, true);
            let detail = detail_snippet_bytes(&forward.error.upstream_body);
            log_generated_outcome(
                outcome_ctx,
                "stream_upstream",
                status,
                forward.error.upstream_status,
                &forward.selected_route,
                forward.failed_attempts.len() as u32,
                &detail,
            );
            finalize_generated(surface, service, endpoint_path, status, body, &[], e2ee)
        }
        Ok(MiddlewareForwardResult::AllFailed(forward)) => {
            log_failed_attempts(outcome_ctx, &forward.failed_attempts, stream);
            let status = forward_error_status(&forward.error);
            let detail = detail_snippet_text(&forward.error.to_string());
            log_generated_outcome(
                outcome_ctx,
                "all_candidates_failed",
                status,
                0,
                "",
                forward.failed_attempts.len() as u32,
                &detail,
            );
            service_error_response(
                surface,
                endpoint_path,
                service,
                &request_id,
                forward.error,
                e2ee,
            )
        }
        Err(err) => {
            let status = forward_error_status(&err);
            let detail = detail_snippet_text(&err.to_string());
            log_generated_outcome(outcome_ctx, "forward_error", status, 0, "", 0, &detail);
            service_error_response(surface, endpoint_path, service, &request_id, err, e2ee)
        }
    }
}

struct InFlightStream {
    inner: ServiceResponseStream,
    _route_in_flight: Option<RouteInFlight>,
}

impl Unpin for InFlightStream {}

impl Stream for InFlightStream {
    type Item = Result<bytes::Bytes, ServiceError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

fn forward_error_status(err: &ServiceError) -> u16 {
    match err {
        ServiceError::E2ee(_) => 400,
        ServiceError::UpstreamVerification(_) => 503,
        ServiceError::Upstream(UpstreamError::Routing(_)) => 404,
        _ => 502,
    }
}

fn service_error_response(
    surface: Surface,
    endpoint_path: &str,
    service: &AciService,
    request_id: &str,
    err: ServiceError,
    e2ee: Option<E2eeRequestContext>,
) -> Response {
    let status = forward_error_status(&err);
    let e2ee = match &err {
        ServiceError::E2ee(_) => None,
        _ => e2ee,
    };
    let body = errors::envelope_bytes(
        surface,
        errors::error_type(surface, status),
        &err.to_string(),
        Some(request_id),
    );
    finalize_generated(surface, service, endpoint_path, status, body, &[], e2ee)
}

fn finalize_generated(
    surface: Surface,
    service: &AciService,
    endpoint_path: &str,
    status: u16,
    body: Vec<u8>,
    extra_headers: &[(&'static str, String)],
    e2ee: Option<E2eeRequestContext>,
) -> Response {
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    for (name, value) in extra_headers {
        insert_header(&mut headers, name, value);
    }
    if e2ee.is_none() {
        return (status_code, headers, body).into_response();
    }
    match service.finalize_middleware_generated_response(
        endpoint_path,
        &body,
        Some("application/json"),
        e2ee,
    ) {
        Ok(finalized) => {
            apply_e2ee_headers(&mut headers, finalized.e2ee.as_ref());
            (status_code, headers, finalized.wire_body).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "E2EE generated-response finalization failed");
            errors::error_response(
                surface,
                500,
                errors::error_type(surface, 500),
                "response finalization failed",
                None,
            )
        }
    }
}

fn response_headers(
    upstream_headers: &std::collections::HashMap<String, String>,
    content_type: &str,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_headers {
        if is_gateway_owned(name)
            || is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("content-type")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(content_type) {
        headers.insert(CONTENT_TYPE, value);
    }
    headers
}

fn is_gateway_owned(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "x-receipt-id"
        || lower.starts_with("x-e2ee-")
        || lower.starts_with("x-aci-")
        || lower.starts_with("x-private-ai-gateway-")
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Stamp the E2EE verdict on every response this module returns.
///
/// `false` used to be omitted on two of these paths, and one of them is a
/// SUCCESS path: a streaming response whose receipt id is not yet journaled
/// returns 200 with no verdict at all. To a client that asked for E2EE, a
/// missing header reads as "this service is too old to say" rather than "your
/// request was NOT encrypted" — so one checking `!= "false"`, or treating the
/// gap as inconclusive-but-probably-fine, accepts a plaintext answer as a
/// protected one.
///
/// The safety property never depended on this: `true` is emitted if and only if
/// E2EE was applied, so a client requiring `== "true"` was always correct, and
/// still is. Saying `false` out loud just stops the silence from looking like
/// an answer. Error passthroughs elsewhere in the gateway may still omit it;
/// they carry an error status, so no caller can mistake one for a protected
/// reply.
fn apply_e2ee_headers(headers: &mut HeaderMap, e2ee: Option<&E2eeResponseInfo>) {
    match e2ee {
        Some(info) => {
            headers.insert(
                HeaderName::from_static("x-e2ee-applied"),
                HeaderValue::from_static("true"),
            );
            insert_header(headers, "x-e2ee-version", &info.version);
            insert_header(headers, "x-e2ee-algo", &info.algo);
        }
        None => {
            headers.insert(
                HeaderName::from_static("x-e2ee-applied"),
                HeaderValue::from_static("false"),
            );
        }
    }
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

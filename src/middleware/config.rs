//! Configuration for the middleware.
//!
//! Selected through the gateway's optional `middleware` config section. This
//! fork intentionally supports one middleware shape: one public model routed
//! across multiple configured upstreams with cache-aware and PIG-aware ordering.

use serde::{Deserialize, Serialize};

use super::types::Engine;

/// Router middleware settings.
///
/// The router serves EVERY model present in the upstream config (the config
/// is the allow-list; /v1/models lists them all). `public_model` names the
/// primary model: it is always listed in the catalog and is the one the
/// upstream health status tracks. If unset, it is derived when the upstream
/// config carries exactly one unique public model.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MiddlewareConfig {
    pub public_model: Option<String>,
    pub cache_threshold: f32,
    pub balance_abs_threshold: usize,
    pub balance_rel_threshold: f32,
    pub max_history_per_route: usize,
    /// Background upstream `/v1/metrics` polling interval. `0` disables metric
    /// polling and falls back to gateway-local in-flight routing only.
    pub metrics_poll_ms: u64,
    pub metrics_timeout_ms: u64,
    pub metrics_stale_ms: u64,
    pub metrics_path: String,
    /// Trust inbound `x-user-tier` for routing and upstream forwarding. Keep
    /// disabled unless a trusted front door strips or sets the header.
    pub trusted_user_tier_header: bool,
    pub default_engine: Option<Engine>,
    /// SSE keep-alive interval for streaming responses. Defaults to 10_000 ms;
    /// `0` disables the heartbeat.
    pub sse_keepalive_ms: Option<u64>,
    /// Allow clients to opt into backend web search per request (a top-level
    /// `"web_search": true` in the chat body). When enabled, the gateway adds
    /// the upstream's server-side search tool and, for non-streaming clients,
    /// folds the upstream stream back into one JSON that discloses every
    /// search query in a `web_searches` array. OFF by default: search queries
    /// derived from user prompts leave the attested boundary, so turning this
    /// on is an explicit operator decision.
    pub web_search_enabled: bool,
    /// Operator-set default system prompt (e.g. disclosing the model's
    /// knowledge cutoff and forbidding fabricated URLs). Prepended as a
    /// `{"role":"system"}` message to chat requests that carry no
    /// system/developer message of their own; requests that set one keep it.
    /// Injection happens AFTER the receipt's `request.received` commitment
    /// (which stays bound to the client's exact bytes) and is disclosed in the
    /// receipt via the `transparency.request_modified` event. Unset/empty = off.
    pub default_system_prompt: Option<String>,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        Self {
            public_model: None,
            cache_threshold: 0.30,
            balance_abs_threshold: 64,
            balance_rel_threshold: 1.50,
            max_history_per_route: 256,
            metrics_poll_ms: 1_000,
            metrics_timeout_ms: 800,
            metrics_stale_ms: 3_000,
            metrics_path: "/v1/metrics".to_string(),
            trusted_user_tier_header: false,
            default_engine: None,
            sse_keepalive_ms: None,
            web_search_enabled: false,
            default_system_prompt: None,
        }
    }
}

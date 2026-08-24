//! Single-model, multi-upstream router middleware.
//!
//! The middleware runs in-process between the public HTTP frontend and
//! `AciService`. It only orders candidate upstream routes. Provider verification,
//! channel binding, forwarding, and receipt finalization stay in `AciService`.

pub mod completion;
pub mod config;
pub mod errors;
pub mod request_transform;
pub mod response_transform;
mod router;
pub mod sse;
pub mod stream_transform;
pub mod types;
mod web_search;

use std::sync::Arc;

use axum::response::Response;
use serde_json::Value;

pub use completion::CompletionInput;
pub use config::MiddlewareConfig;

use crate::aggregator::service::AciService;
use crate::aggregator::upstream_config::UpstreamConfigManager;

/// Middleware handle held by the gateway's app state.
pub struct Middleware {
    router: router::RouterBackend,
}

impl Middleware {
    pub fn new(
        config: &MiddlewareConfig,
        upstream_config: Arc<UpstreamConfigManager>,
    ) -> Result<Self, String> {
        Ok(Self {
            router: router::RouterBackend::new(config, upstream_config)?,
        })
    }

    pub fn name(&self) -> &'static str {
        "router"
    }

    pub fn admin_snapshot(&self) -> Option<Value> {
        Some(self.router.admin_snapshot_value())
    }

    pub fn upstream_status_code(&self) -> u8 {
        self.router.upstream_status_code()
    }

    /// Serve `/v1/models` from the single public model selected by router
    /// middleware.
    pub async fn handle_catalog(&self, v1_path: &str) -> Response {
        self.router.handle_catalog(v1_path).await
    }

    /// Route the completion request across configured upstream candidates.
    pub async fn handle_completion(
        &self,
        service: &AciService,
        input: CompletionInput,
    ) -> Response {
        self.router.handle_completion(service, input).await
    }
}

//! In-process cache-aware router middleware for one public model.
//!
//! PAG still performs the verified upstream forward and receipt finalization.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};

use crate::aggregator::service::AciService;
use crate::aggregator::upstream_config::{
    PublicUpstreamConfig, UpstreamConfigManager, UpstreamConfigSnapshot, UpstreamMetricsTarget,
    UpstreamProvider,
};

use super::completion::{self, CompletionInput};
use super::config::MiddlewareConfig;
use super::errors::{self, Surface};
use super::request_transform::Endpoint;
use super::types::{ProviderFormat, RouteCandidate};

const MAX_ROUTING_HISTORY_CHARS: usize = 16_384;
const UPSTREAM_STATUS_GREEN: u8 = 0;
const UPSTREAM_STATUS_YELLOW: u8 = 1;
const UPSTREAM_STATUS_RED: u8 = 2;

#[derive(Clone)]
struct RouterRoute {
    route_id: String,
    upstream_name: String,
    candidate: RouteCandidate,
}

#[derive(Default, Clone)]
struct RouteStats {
    running: usize,
    processed: u64,
    selected_by_cache: u64,
    selected_by_load: u64,
    selected_by_order: u64,
}

#[derive(Default)]
struct RouterState {
    stats: HashMap<String, RouteStats>,
    history: HashMap<String, HashMap<String, Vec<String>>>,
    upstream_metrics: HashMap<String, UpstreamMetrics>,
}

#[derive(Default, Clone)]
struct UpstreamMetrics {
    ok: bool,
    error: Option<String>,
    updated_at: Option<Instant>,
    observed_running: Option<f64>,
    observed_waiting: Option<f64>,
    global_limit: Option<f64>,
    basic_limit: Option<f64>,
    basic_inflight: Option<f64>,
    premium_inflight: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserTier {
    Basic,
    Premium,
}

impl UserTier {
    fn from_header(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("premium") => Self::Premium,
            _ => Self::Basic,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Premium => "premium",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RoutePressure {
    blocked: bool,
    metrics_missing: bool,
    waiting: u64,
    fullness_milli: u64,
    effective_running: usize,
    processed: u64,
}

type RouteOrderKey = (u8, u8, u64, u64, usize, u64, String);

pub(super) struct RouterBackend {
    upstream_config: Arc<UpstreamConfigManager>,
    config: MiddlewareConfig,
    state: Arc<Mutex<RouterState>>,
}

#[derive(Debug, Clone)]
struct RouteSelection {
    route_id: String,
    reason: &'static str,
    cache_match_rate: f32,
    running_at_select: usize,
}

pub(super) struct RouteInFlight {
    route_id: Option<String>,
    state: Arc<Mutex<RouterState>>,
}

impl RouterBackend {
    pub fn new(
        config: &MiddlewareConfig,
        upstream_config: Arc<UpstreamConfigManager>,
    ) -> Result<Self, String> {
        if config
            .public_model
            .as_deref()
            .is_some_and(|model| model.trim().is_empty())
        {
            return Err("middleware.public_model must not be empty".to_string());
        }
        let state = Arc::new(Mutex::new(RouterState::default()));
        spawn_metrics_poller(config.clone(), upstream_config.clone(), state.clone());
        Ok(Self {
            upstream_config,
            config: config.clone(),
            state,
        })
    }

    fn public_model(&self, snapshot: &UpstreamConfigSnapshot) -> Result<Option<String>, String> {
        if let Some(model) = self.config.public_model.as_deref() {
            return Ok(Some(model.trim().to_string()));
        }
        let mut models = BTreeSet::new();
        for upstream in &snapshot.upstreams {
            if !upstream.enabled {
                continue;
            }
            for public_model in upstream.models.keys() {
                models.insert(public_model.clone());
            }
        }
        match models.len() {
            0 => Ok(None),
            1 => Ok(models.into_iter().next()),
            _ => Err(
                "router middleware requires exactly one public model; set middleware.public_model \
                 or remove extra public models from upstream config"
                    .to_string(),
            ),
        }
    }

    fn model_routes(&self, model: &str) -> Vec<RouterRoute> {
        let snapshot = self.upstream_config.snapshot();
        let mut routes = Vec::new();
        for upstream in snapshot.upstreams {
            if upstream.enabled && upstream.models.contains_key(model) {
                routes.push(route_from_upstream(&upstream, model, &self.config));
            }
        }
        routes
    }

    fn ordered_routes(
        &self,
        public_model: &str,
        input: &CompletionInput,
    ) -> (Vec<RouterRoute>, Option<RouteSelection>) {
        let tier = self.request_tier(input);
        let requested_model = input.params.get("model").and_then(Value::as_str);
        if requested_model != Some(public_model) {
            return (Vec::new(), None);
        }

        let mut routes = self.model_routes(public_model);
        let routing_text = bounded_routing_text(&input.params, input.endpoint);
        let selected = {
            let mut state = self.state.lock().expect("router state poisoned");
            state.select(public_model, &routing_text, &routes, &self.config, tier)
        };
        let Some(selected) = selected.clone() else {
            return (routes, None);
        };

        let loads = {
            let state = self.state.lock().expect("router state poisoned");
            routes
                .iter()
                .map(|route| {
                    (
                        route.route_id.clone(),
                        state
                            .route_pressure(route, &self.config, tier)
                            .effective_running,
                    )
                })
                .collect::<HashMap<_, _>>()
        };
        routes.sort_by(|a, b| {
            if a.route_id == selected.route_id {
                return std::cmp::Ordering::Less;
            }
            if b.route_id == selected.route_id {
                return std::cmp::Ordering::Greater;
            }
            let a_load = loads.get(&a.route_id).copied().unwrap_or(0);
            let b_load = loads.get(&b.route_id).copied().unwrap_or(0);
            a_load
                .cmp(&b_load)
                .then_with(|| a.route_id.cmp(&b.route_id))
        });
        (routes, Some(selected))
    }

    pub(super) fn admin_snapshot_value(&self) -> Value {
        let upstream_snapshot = self.upstream_config.snapshot();
        let public_model = self.public_model(&upstream_snapshot);
        let state = self.state.lock().expect("router state poisoned");
        let mut routes = Vec::new();
        for upstream in &upstream_snapshot.upstreams {
            for model in upstream.models.keys() {
                let route_id = format!("{}:{model}", upstream.name);
                let stats = state.stats.get(&route_id).cloned().unwrap_or_default();
                let history_samples = state
                    .history
                    .get(model)
                    .and_then(|by_route| by_route.get(&route_id))
                    .map_or(0, Vec::len);
                routes.push(json!({
                    "route_id": route_id,
                    "enabled": upstream.enabled,
                    "upstream_name": upstream.name,
                    "public_model": model,
                    "provider": provider_name(upstream.provider),
                    "running": stats.running,
                    "processed": stats.processed,
                    "selected_by_cache": stats.selected_by_cache,
                    "selected_by_load": stats.selected_by_load,
                    "selected_by_order": stats.selected_by_order,
                    "history_samples": history_samples,
                    "bearer_token_configured": upstream.bearer_token_configured,
                    "pig_metrics": state.metrics_admin_json(&upstream.name, &self.config),
                }));
            }
        }
        routes.sort_by(|a, b| {
            a.get("route_id")
                .and_then(Value::as_str)
                .cmp(&b.get("route_id").and_then(Value::as_str))
        });
        json!({
            "mode": "router",
            "purpose": "single_model_multi_backend_cache_and_load_aware_routing",
            "config": self.config,
            "routing_text_max_chars": MAX_ROUTING_HISTORY_CHARS,
            "public_model": public_model.as_ref().ok().and_then(Clone::clone),
            "config_error": public_model.err(),
            "upstream_config_digest": upstream_snapshot.config_digest,
            "routes": routes,
        })
    }

    pub(super) fn upstream_status_code(&self) -> u8 {
        let upstream_snapshot = self.upstream_config.snapshot();
        let public_model = match self.public_model(&upstream_snapshot) {
            Ok(Some(model)) => model,
            Ok(None) | Err(_) => return UPSTREAM_STATUS_RED,
        };
        let routes = upstream_snapshot
            .upstreams
            .iter()
            .filter(|upstream| upstream.enabled && upstream.models.contains_key(&public_model))
            .map(|upstream| route_from_upstream(upstream, &public_model, &self.config))
            .collect::<Vec<_>>();
        let state = self.state.lock().expect("router state poisoned");
        state.upstream_status_code(&routes, &self.config, UserTier::Basic)
    }

    pub async fn handle_catalog(&self, v1_path: &str) -> Response {
        if v1_path != "/v1/models" {
            return errors::error_response(
                Surface::Openai,
                404,
                "not_found",
                "router middleware only serves /v1/models catalog",
                None,
            );
        }
        let snapshot = self.upstream_config.snapshot();
        let public_model = match self.public_model(&snapshot) {
            Ok(model) => model,
            Err(err) => {
                return errors::error_response(
                    Surface::Openai,
                    503,
                    "service_unavailable",
                    &err,
                    None,
                );
            }
        };
        let data = public_model
            .into_iter()
            .map(|id| {
                json!({
                    "id": id,
                    "object": "model",
                    "owned_by": "phala",
                })
            })
            .collect::<Vec<_>>();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        (
            StatusCode::OK,
            headers,
            serde_json::to_vec(&json!({"object": "list", "data": data})).unwrap_or_default(),
        )
            .into_response()
    }

    pub async fn handle_completion(
        &self,
        service: &AciService,
        input: CompletionInput,
    ) -> Response {
        let snapshot = self.upstream_config.snapshot();
        let public_model = match self.public_model(&snapshot) {
            Ok(Some(model)) => model,
            Ok(None) => String::new(),
            Err(err) => {
                return errors::error_response(
                    input.surface,
                    503,
                    "service_unavailable",
                    &err,
                    Some(&input.request_id),
                );
            }
        };
        let mut input = input;
        let (routes, selected) = self.ordered_routes(&public_model, &input);
        let user_tier = self.request_tier(&input);
        if !self.config.trusted_user_tier_header {
            input.user_tier = None;
        }
        let route_in_flight = selected
            .as_ref()
            .map(|selection| RouteInFlight::start(self.state.clone(), selection));
        if let Some(selection) = selected.as_ref() {
            tracing::debug!(
                public_model,
                user_tier = user_tier.as_str(),
                selected_route = %selection.route_id,
                reason = selection.reason,
                cache_match_rate = selection.cache_match_rate,
                running_at_select = selection.running_at_select,
                candidate_count = routes.len(),
                "router middleware selected upstream route"
            );
        } else {
            tracing::debug!(public_model, "router middleware found no route");
        }

        completion::run(
            service,
            self.config.sse_keepalive_ms,
            self.config.default_system_prompt.as_deref(),
            input,
            routes.into_iter().map(|route| route.candidate).collect(),
            route_in_flight,
        )
        .await
    }

    fn request_tier(&self, input: &CompletionInput) -> UserTier {
        if self.config.trusted_user_tier_header {
            UserTier::from_header(input.user_tier.as_deref())
        } else {
            UserTier::Basic
        }
    }
}

impl RouteInFlight {
    fn start(state: Arc<Mutex<RouterState>>, selection: &RouteSelection) -> Self {
        {
            let mut state_guard = state.lock().expect("router state poisoned");
            state_guard.mark_started(selection);
        }
        Self {
            route_id: Some(selection.route_id.clone()),
            state,
        }
    }

    pub(super) fn retarget(&mut self, route_id: &str) {
        if self.route_id.as_deref() == Some(route_id) {
            return;
        }
        let mut state = self.state.lock().expect("router state poisoned");
        if let Some(previous) = self.route_id.replace(route_id.to_string()) {
            state.decrement_running(&previous);
        }
        state.stats.entry(route_id.to_string()).or_default().running += 1;
    }
}

impl Drop for RouteInFlight {
    fn drop(&mut self) {
        if let Some(route_id) = self.route_id.take() {
            let mut state = self.state.lock().expect("router state poisoned");
            state.decrement_running(&route_id);
        }
    }
}

impl RouterState {
    fn mark_started(&mut self, selection: &RouteSelection) {
        let stats = self.stats.entry(selection.route_id.clone()).or_default();
        stats.running += 1;
        stats.processed += 1;
        match selection.reason {
            "cache" => stats.selected_by_cache += 1,
            "single" => stats.selected_by_order += 1,
            _ => stats.selected_by_load += 1,
        }
    }

    fn decrement_running(&mut self, route_id: &str) {
        if let Some(stats) = self.stats.get_mut(route_id) {
            stats.running = stats.running.saturating_sub(1);
        }
    }

    fn least_loaded<'a>(
        &self,
        routes: &'a [RouterRoute],
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> Option<&'a RouterRoute> {
        routes.iter().min_by(|a, b| {
            self.route_order_key(a, config, tier)
                .cmp(&self.route_order_key(b, config, tier))
        })
    }

    fn route_order_key(
        &self,
        route: &RouterRoute,
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> RouteOrderKey {
        let pressure = self.route_pressure(route, config, tier);
        (
            u8::from(pressure.blocked),
            u8::from(pressure.metrics_missing),
            pressure.waiting,
            pressure.fullness_milli,
            pressure.effective_running,
            pressure.processed,
            route.route_id.clone(),
        )
    }

    fn route_pressure(
        &self,
        route: &RouterRoute,
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> RoutePressure {
        let stats = self.stats.get(&route.route_id).cloned().unwrap_or_default();
        let local_running = stats.running;
        let Some(metrics) = self.upstream_metrics.get(&route.upstream_name) else {
            return RoutePressure {
                blocked: false,
                metrics_missing: true,
                waiting: 0,
                fullness_milli: 0,
                effective_running: local_running,
                processed: stats.processed,
            };
        };
        if metrics.is_stale(config) || !metrics.ok {
            return RoutePressure {
                blocked: false,
                metrics_missing: true,
                waiting: 0,
                fullness_milli: 0,
                effective_running: local_running,
                processed: stats.processed,
            };
        }

        let observed_running = metrics.observed_running.unwrap_or(0.0).max(0.0);
        let observed_waiting = metrics.observed_waiting.unwrap_or(0.0).max(0.0);
        let global_fullness = ratio_milli(observed_running, metrics.global_limit);
        let tier_fullness = match tier {
            UserTier::Premium => global_fullness,
            UserTier::Basic => global_fullness.max(ratio_milli(
                metrics.basic_inflight.unwrap_or(0.0).max(0.0),
                metrics.basic_limit,
            )),
        };
        let effective_running = local_running.max(observed_running.ceil() as usize);
        RoutePressure {
            blocked: observed_waiting > 0.0 || tier_fullness >= 1_000,
            metrics_missing: false,
            waiting: observed_waiting.ceil() as u64,
            fullness_milli: tier_fullness,
            effective_running,
            processed: stats.processed,
        }
    }

    fn upstream_status_code(
        &self,
        routes: &[RouterRoute],
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> u8 {
        if routes.is_empty() {
            return UPSTREAM_STATUS_RED;
        }
        let mut saw_yellow = false;
        for route in routes {
            match self.route_status_code(route, config, tier) {
                UPSTREAM_STATUS_GREEN => return UPSTREAM_STATUS_GREEN,
                UPSTREAM_STATUS_YELLOW => saw_yellow = true,
                _ => {}
            }
        }
        if saw_yellow {
            UPSTREAM_STATUS_YELLOW
        } else {
            UPSTREAM_STATUS_RED
        }
    }

    fn route_status_code(
        &self,
        route: &RouterRoute,
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> u8 {
        let pressure = self.route_pressure(route, config, tier);
        if pressure.blocked || pressure.waiting > 0 || pressure.fullness_milli >= 1_000 {
            return UPSTREAM_STATUS_RED;
        }
        if pressure.metrics_missing || pressure.fullness_milli >= 850 {
            return UPSTREAM_STATUS_YELLOW;
        }
        let Some(metrics) = self.upstream_metrics.get(&route.upstream_name) else {
            return UPSTREAM_STATUS_YELLOW;
        };
        let global_limit_known = metrics.global_limit.is_some_and(|limit| limit > 0.0);
        let tier_limit_known = match tier {
            UserTier::Premium => true,
            UserTier::Basic => metrics.basic_limit.is_some_and(|limit| limit > 0.0),
        };
        if !global_limit_known || !tier_limit_known {
            return UPSTREAM_STATUS_YELLOW;
        }
        UPSTREAM_STATUS_GREEN
    }

    fn select(
        &mut self,
        model: &str,
        text: &str,
        routes: &[RouterRoute],
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> Option<RouteSelection> {
        if routes.is_empty() {
            return None;
        }
        for route in routes {
            self.stats.entry(route.route_id.clone()).or_default();
            self.history
                .entry(model.to_string())
                .or_default()
                .entry(route.route_id.clone())
                .or_default();
        }
        if routes.len() == 1 {
            let route_id = routes[0].route_id.clone();
            let running_at_select = self.stats.get(&route_id).map_or(0, |s| s.running);
            self.record_history(model, &route_id, text, config.max_history_per_route);
            return Some(RouteSelection {
                route_id,
                reason: "single",
                cache_match_rate: 0.0,
                running_at_select,
            });
        }

        let (min_load, max_load) = routes
            .iter()
            .fold((usize::MAX, 0usize), |(min, max), route| {
                let load = self.route_pressure(route, config, tier).effective_running;
                (min.min(load), max.max(load))
            });
        let min_load = if min_load == usize::MAX { 0 } else { min_load };
        let imbalanced = max_load.saturating_sub(min_load) > config.balance_abs_threshold
            && (max_load as f32) > (min_load as f32 * config.balance_rel_threshold);

        let selected = if imbalanced || text.is_empty() {
            self.least_loaded(routes, config, tier).map(|route| {
                let pressure = self.route_pressure(route, config, tier);
                RouteSelection {
                    route_id: route.route_id.clone(),
                    reason: if imbalanced {
                        "load_imbalance"
                    } else {
                        "no_text"
                    },
                    cache_match_rate: 0.0,
                    running_at_select: pressure.effective_running,
                }
            })
        } else {
            self.select_cache_aware(model, text, routes, config, tier)
        }?;

        self.record_history(
            model,
            &selected.route_id,
            text,
            config.max_history_per_route,
        );
        Some(selected)
    }

    fn select_cache_aware(
        &self,
        model: &str,
        text: &str,
        routes: &[RouterRoute],
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> Option<RouteSelection> {
        let input_chars = text.chars().count().max(1);
        let history = self.history.get(model);
        let mut best: Option<(&RouterRoute, f32, RouteOrderKey)> = None;
        for route in routes {
            let matched = history
                .and_then(|by_route| by_route.get(&route.route_id))
                .map(|samples| {
                    samples
                        .iter()
                        .map(|sample| common_prefix_chars(sample, text))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            let rate = matched as f32 / input_chars as f32;
            let order_key = self.route_order_key(route, config, tier);
            let replace = match best.as_ref() {
                None => true,
                Some((_, best_rate, best_key)) => {
                    rate > *best_rate || (rate == *best_rate && order_key < *best_key)
                }
            };
            if replace {
                best = Some((route, rate, order_key));
            }
        }
        let (cache_route, rate, _) = best?;
        let least = self.least_loaded(routes, config, tier)?;
        if rate > config.cache_threshold
            && self.cache_route_is_acceptable(cache_route, least, config, tier)
        {
            let pressure = self.route_pressure(cache_route, config, tier);
            Some(RouteSelection {
                route_id: cache_route.route_id.clone(),
                reason: "cache",
                cache_match_rate: rate,
                running_at_select: pressure.effective_running,
            })
        } else {
            let pressure = self.route_pressure(least, config, tier);
            Some(RouteSelection {
                route_id: least.route_id.clone(),
                reason: "least_running",
                cache_match_rate: rate,
                running_at_select: pressure.effective_running,
            })
        }
    }

    fn cache_route_is_acceptable(
        &self,
        cache_route: &RouterRoute,
        least_route: &RouterRoute,
        config: &MiddlewareConfig,
        tier: UserTier,
    ) -> bool {
        let cache = self.route_pressure(cache_route, config, tier);
        let least = self.route_pressure(least_route, config, tier);
        if cache.blocked && !least.blocked {
            return false;
        }
        if cache.metrics_missing && !least.metrics_missing {
            return false;
        }
        if cache.waiting > 0 && least.waiting == 0 {
            return false;
        }
        if cache.fullness_milli > least.fullness_milli.saturating_add(250) {
            return false;
        }
        let gap = cache
            .effective_running
            .saturating_sub(least.effective_running);
        if gap > config.balance_abs_threshold
            && (cache.effective_running as f32)
                > (least.effective_running as f32 * config.balance_rel_threshold)
        {
            return false;
        }
        true
    }

    fn record_history(&mut self, model: &str, route_id: &str, text: &str, max_samples: usize) {
        if text.is_empty() || max_samples == 0 {
            return;
        }
        let text = limit_chars(text, MAX_ROUTING_HISTORY_CHARS);
        let samples = self
            .history
            .entry(model.to_string())
            .or_default()
            .entry(route_id.to_string())
            .or_default();
        samples.push(text);
        if samples.len() > max_samples {
            let overflow = samples.len() - max_samples;
            samples.drain(0..overflow);
        }
    }

    fn update_upstream_metrics(&mut self, upstream_name: String, metrics: UpstreamMetrics) {
        self.upstream_metrics.insert(upstream_name, metrics);
    }

    fn retain_upstream_metrics(&mut self, upstream_names: &HashSet<String>) {
        self.upstream_metrics
            .retain(|name, _| upstream_names.contains(name));
    }

    fn metrics_admin_json(&self, upstream_name: &str, config: &MiddlewareConfig) -> Value {
        let Some(metrics) = self.upstream_metrics.get(upstream_name) else {
            return json!({
                "ok": false,
                "stale": true,
                "error": "not_collected",
            });
        };
        json!({
            "ok": metrics.ok,
            "stale": metrics.is_stale(config),
            "error": metrics.error,
            "observed_running": metrics.observed_running,
            "observed_waiting": metrics.observed_waiting,
            "global_limit": metrics.global_limit,
            "basic_limit": metrics.basic_limit,
            "basic_inflight": metrics.basic_inflight,
            "premium_inflight": metrics.premium_inflight,
            "age_ms": metrics.age_ms(),
        })
    }
}

impl UpstreamMetrics {
    fn collected_error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            updated_at: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn is_stale(&self, config: &MiddlewareConfig) -> bool {
        let Some(updated_at) = self.updated_at else {
            return true;
        };
        updated_at.elapsed() > Duration::from_millis(config.metrics_stale_ms)
    }

    fn age_ms(&self) -> Option<u64> {
        self.updated_at
            .map(|updated_at| updated_at.elapsed().as_millis() as u64)
    }
}

fn ratio_milli(value: f64, limit: Option<f64>) -> u64 {
    let Some(limit) = limit else {
        return 0;
    };
    if limit <= 0.0 {
        return 0;
    }
    ((value / limit) * 1_000.0).max(0.0).round() as u64
}

fn spawn_metrics_poller(
    config: MiddlewareConfig,
    upstream_config: Arc<UpstreamConfigManager>,
    state: Arc<Mutex<RouterState>>,
) {
    if config.metrics_poll_ms == 0 {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(config.metrics_timeout_ms))
            .timeout(Duration::from_millis(config.metrics_timeout_ms))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(error = %err, "router middleware could not build metrics client");
                return;
            }
        };
        let poll = Duration::from_millis(config.metrics_poll_ms);
        loop {
            let targets = upstream_config.metrics_targets();
            let live_names = targets
                .iter()
                .map(|target| target.upstream_name.clone())
                .collect::<HashSet<_>>();
            let fetched = futures_util::future::join_all(targets.into_iter().map(|target| {
                let upstream_name = target.upstream_name.clone();
                async {
                    let metrics = fetch_upstream_metrics(&client, &config, target).await;
                    (upstream_name, metrics)
                }
            }))
            .await;
            for (upstream_name, metrics) in fetched {
                let mut state = state.lock().expect("router state poisoned");
                state.update_upstream_metrics(upstream_name, metrics);
            }
            {
                let mut state = state.lock().expect("router state poisoned");
                state.retain_upstream_metrics(&live_names);
            }
            tokio::time::sleep(poll).await;
        }
    });
}

async fn fetch_upstream_metrics(
    client: &reqwest::Client,
    config: &MiddlewareConfig,
    target: UpstreamMetricsTarget,
) -> UpstreamMetrics {
    let path = if config.metrics_path.starts_with('/') {
        config.metrics_path.as_str()
    } else {
        "/v1/metrics"
    };
    let url = format!("{}{}", target.base_url.trim_end_matches('/'), path);
    let mut req = client.get(url).header("accept", "text/plain");
    if let Some(token) = target.bearer_token.as_deref() {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return UpstreamMetrics::collected_error(format!("http_{status}"));
            }
            match resp.text().await {
                Ok(body) => parse_upstream_metrics(&body),
                Err(err) => UpstreamMetrics::collected_error(format!("read_error: {err}")),
            }
        }
        Err(err) => UpstreamMetrics::collected_error(format!("fetch_error: {err}")),
    }
}

fn parse_upstream_metrics(text: &str) -> UpstreamMetrics {
    let mut metrics = UpstreamMetrics {
        ok: true,
        updated_at: Some(Instant::now()),
        ..Default::default()
    };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name_and_labels, value)) = parse_prometheus_sample(line) else {
            continue;
        };
        let (name, labels) = split_metric_name_labels(name_and_labels);
        match name {
            "pig_dynamic_observed_running" => metrics.observed_running = Some(value),
            "pig_dynamic_observed_waiting" => metrics.observed_waiting = Some(value),
            "pig_dynamic_global_limit" => metrics.global_limit = Some(value),
            "pig_tier_basic_limit" => metrics.basic_limit = Some(value),
            "pig_tier_inflight" => match labels.get("tier").map(String::as_str) {
                Some("basic") => metrics.basic_inflight = Some(value),
                Some("premium") => metrics.premium_inflight = Some(value),
                _ => {}
            },
            _ => {}
        }
    }
    if metrics.observed_running.is_none()
        && metrics.observed_waiting.is_none()
        && metrics.global_limit.is_none()
        && metrics.basic_limit.is_none()
    {
        return UpstreamMetrics::collected_error("pig_metrics_missing");
    }
    metrics
}

fn parse_prometheus_sample(line: &str) -> Option<(&str, f64)> {
    let split_at = line.rfind(|c: char| c.is_whitespace())?;
    let (left, right) = line.split_at(split_at);
    right
        .trim()
        .parse::<f64>()
        .ok()
        .map(|value| (left.trim(), value))
}

fn split_metric_name_labels(input: &str) -> (&str, HashMap<String, String>) {
    let Some(open) = input.find('{') else {
        return (input, HashMap::new());
    };
    let name = &input[..open];
    let labels_text = input[open + 1..].trim_end_matches('}');
    let mut labels = HashMap::new();
    for part in labels_text.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        labels.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    (name, labels)
}

fn route_from_upstream(
    upstream: &PublicUpstreamConfig,
    public_model: &str,
    config: &MiddlewareConfig,
) -> RouterRoute {
    let route_id = format!("{}:{public_model}", upstream.name);
    RouterRoute {
        route_id: route_id.clone(),
        upstream_name: upstream.name.clone(),
        candidate: RouteCandidate {
            route_id,
            format: provider_format(upstream.provider),
            engine: config.default_engine,
        },
    }
}

fn provider_format(provider: UpstreamProvider) -> ProviderFormat {
    match provider {
        UpstreamProvider::Anthropic => ProviderFormat::Anthropic,
        _ => ProviderFormat::Openai,
    }
}

fn provider_name(provider: UpstreamProvider) -> &'static str {
    match provider {
        UpstreamProvider::OpenAiCompatible => "openai-compatible",
        UpstreamProvider::Anthropic => "anthropic",
        UpstreamProvider::AciService => "aci-service",
        UpstreamProvider::Chutes => "chutes",
        UpstreamProvider::Tinfoil => "tinfoil",
        UpstreamProvider::NearAi => "near-ai",
        UpstreamProvider::PhalaDirect => "phala-direct",
    }
}

fn bounded_routing_text(params: &Value, endpoint: Endpoint) -> String {
    let mut builder = BoundedText::new(MAX_ROUTING_HISTORY_CHARS);
    match endpoint {
        Endpoint::Complete => append_prompt(&mut builder, params.get("prompt")),
        Endpoint::Embed => append_prompt(&mut builder, params.get("input")),
        Endpoint::Messages | Endpoint::ChatComplete => {
            append_messages(&mut builder, params.get("messages"))
        }
        Endpoint::CreateModelResponse => append_prompt(&mut builder, params.get("input")),
    }
    builder.finish()
}

fn limit_chars(text: &str, max_chars: usize) -> String {
    let mut builder = BoundedText::new(max_chars);
    builder.push(text);
    builder.finish()
}

struct BoundedText {
    out: String,
    remaining: usize,
}

impl BoundedText {
    fn new(max_chars: usize) -> Self {
        Self {
            out: String::new(),
            remaining: max_chars,
        }
    }

    fn is_full(&self) -> bool {
        self.remaining == 0
    }

    fn push(&mut self, text: &str) {
        if self.remaining == 0 || text.is_empty() {
            return;
        }
        for ch in text.chars().take(self.remaining) {
            self.out.push(ch);
            self.remaining -= 1;
        }
    }

    fn separator(&mut self, text: &str) {
        if !self.out.is_empty() {
            self.push(text);
        }
    }

    fn finish(self) -> String {
        self.out
    }
}

fn append_prompt(out: &mut BoundedText, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    append_prompt_value(out, value);
}

fn append_prompt_value(out: &mut BoundedText, value: &Value) {
    if out.is_full() {
        return;
    }
    match value {
        Value::String(s) => out.push(s),
        Value::Number(n) => out.push(&n.to_string()),
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.separator(" ");
                }
                append_prompt_value(out, item);
                if out.is_full() {
                    break;
                }
            }
        }
        Value::Object(obj) => {
            if let Some(value) = obj.get("text").or_else(|| obj.get("content")) {
                append_prompt_value(out, value);
            }
        }
        _ => {}
    }
}

fn append_messages(out: &mut BoundedText, value: Option<&Value>) {
    let Some(messages) = value.and_then(Value::as_array) else {
        return;
    };
    for msg in messages {
        out.separator("\n");
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
        out.push(role);
        out.push(":");
        append_prompt(out, msg.get("content"));
        if out.is_full() {
            break;
        }
    }
}

fn common_prefix_chars(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn routing_text_uses_chat_messages_not_only_session_id() {
        let text = bounded_routing_text(
            &json!({
                "messages": [
                    {"role": "system", "content": "stable prefix"},
                    {"role": "user", "content": "hello"}
                ]
            }),
            Endpoint::ChatComplete,
        );
        assert!(text.contains("stable prefix"));
        assert!(text.contains("hello"));
    }

    #[test]
    fn cache_prefers_previous_prefix_when_balanced() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig {
            cache_threshold: 0.25,
            balance_abs_threshold: 64,
            balance_rel_threshold: 1.5,
            max_history_per_route: 16,
            ..Default::default()
        };
        let routes = vec![test_route("a:m"), test_route("b:m")];
        assert_eq!(
            state
                .select("m", "hello world", &routes, &config, UserTier::Basic)
                .map(|s| s.route_id)
                .as_deref(),
            Some("a:m")
        );
        assert_eq!(
            state
                .select("m", "hello there", &routes, &config, UserTier::Basic)
                .map(|s| s.route_id)
                .as_deref(),
            Some("a:m")
        );
    }

    #[test]
    fn no_cache_tie_uses_processed_count_to_spread_idle_routes() {
        let state = Arc::new(Mutex::new(RouterState::default()));
        let config = MiddlewareConfig {
            cache_threshold: 0.9,
            balance_abs_threshold: 64,
            balance_rel_threshold: 1.5,
            max_history_per_route: 16,
            ..Default::default()
        };
        let routes = vec![test_route("a:m"), test_route("b:m")];
        let first = {
            let mut locked = state.lock().unwrap();
            locked
                .select("m", "aaaa", &routes, &config, UserTier::Basic)
                .unwrap()
        };
        assert_eq!(first.route_id, "a:m");
        drop(RouteInFlight::start(state.clone(), &first));

        let second = {
            let mut locked = state.lock().unwrap();
            locked
                .select("m", "zzzz", &routes, &config, UserTier::Basic)
                .unwrap()
        };
        assert_eq!(second.route_id, "b:m");
    }

    #[test]
    fn pig_pressure_overrides_cache_affinity() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig {
            cache_threshold: 0.25,
            balance_abs_threshold: 64,
            balance_rel_threshold: 1.5,
            max_history_per_route: 16,
            ..Default::default()
        };
        let routes = vec![test_route("a:m"), test_route("b:m")];
        assert_eq!(
            state
                .select("m", "stable prefix one", &routes, &config, UserTier::Basic)
                .map(|s| s.route_id)
                .as_deref(),
            Some("a:m")
        );
        state.update_upstream_metrics(
            "a".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(10.0),
                observed_waiting: Some(1.0),
                global_limit: Some(10.0),
                basic_limit: Some(9.0),
                basic_inflight: Some(9.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );
        state.update_upstream_metrics(
            "b".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(1.0),
                observed_waiting: Some(0.0),
                global_limit: Some(10.0),
                basic_limit: Some(9.0),
                basic_inflight: Some(1.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );

        let selected = state
            .select("m", "stable prefix two", &routes, &config, UserTier::Basic)
            .unwrap();
        assert_eq!(selected.route_id, "b:m");
        assert_eq!(selected.reason, "least_running");
    }

    #[test]
    fn premium_does_not_treat_basic_full_as_blocked() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig {
            cache_threshold: 0.25,
            balance_abs_threshold: 64,
            balance_rel_threshold: 1.5,
            max_history_per_route: 16,
            ..Default::default()
        };
        let routes = vec![test_route("a:m"), test_route("b:m")];
        state.update_upstream_metrics(
            "a".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(4.0),
                observed_waiting: Some(0.0),
                global_limit: Some(10.0),
                basic_limit: Some(4.0),
                basic_inflight: Some(4.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );
        state.update_upstream_metrics(
            "b".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(5.0),
                observed_waiting: Some(0.0),
                global_limit: Some(10.0),
                basic_limit: Some(8.0),
                basic_inflight: Some(2.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );

        let basic = state
            .select("m", "cold-basic", &routes, &config, UserTier::Basic)
            .unwrap();
        let mut premium_state = RouterState::default();
        premium_state.update_upstream_metrics(
            "a".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(4.0),
                observed_waiting: Some(0.0),
                global_limit: Some(10.0),
                basic_limit: Some(4.0),
                basic_inflight: Some(4.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );
        premium_state.update_upstream_metrics(
            "b".to_string(),
            UpstreamMetrics {
                ok: true,
                updated_at: Some(Instant::now()),
                observed_running: Some(5.0),
                observed_waiting: Some(0.0),
                global_limit: Some(10.0),
                basic_limit: Some(8.0),
                basic_inflight: Some(2.0),
                premium_inflight: Some(0.0),
                error: None,
            },
        );
        let premium = premium_state
            .select("m", "cold-premium", &routes, &config, UserTier::Premium)
            .unwrap();

        assert_eq!(basic.route_id, "b:m");
        assert_eq!(premium.route_id, "a:m");
    }

    #[test]
    fn upstream_status_returns_green_when_any_route_has_capacity() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig::default();
        let routes = vec![test_route("a:m"), test_route("b:m")];
        state.update_upstream_metrics("a".to_string(), test_metrics(10.0, 1.0, 10.0, 9.0, 9.0));
        state.update_upstream_metrics("b".to_string(), test_metrics(2.0, 0.0, 10.0, 9.0, 2.0));

        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Basic),
            UPSTREAM_STATUS_GREEN
        );
    }

    #[test]
    fn upstream_status_returns_yellow_for_missing_or_near_full_metrics() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig::default();
        let routes = vec![test_route("a:m")];

        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Basic),
            UPSTREAM_STATUS_YELLOW
        );

        state.update_upstream_metrics("a".to_string(), test_metrics(8.6, 0.0, 10.0, 9.0, 7.0));
        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Basic),
            UPSTREAM_STATUS_YELLOW
        );
    }

    #[test]
    fn upstream_status_returns_red_when_all_routes_are_blocked() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig::default();
        let routes = vec![test_route("a:m"), test_route("b:m")];
        state.update_upstream_metrics("a".to_string(), test_metrics(10.0, 0.0, 10.0, 9.0, 9.0));
        state.update_upstream_metrics("b".to_string(), test_metrics(2.0, 1.0, 10.0, 9.0, 2.0));

        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Basic),
            UPSTREAM_STATUS_RED
        );
    }

    #[test]
    fn upstream_status_treats_basic_full_as_red() {
        let mut state = RouterState::default();
        let config = MiddlewareConfig::default();
        let routes = vec![test_route("a:m")];
        state.update_upstream_metrics("a".to_string(), test_metrics(4.0, 0.0, 10.0, 4.0, 4.0));

        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Basic),
            UPSTREAM_STATUS_RED
        );
        assert_eq!(
            state.upstream_status_code(&routes, &config, UserTier::Premium),
            UPSTREAM_STATUS_GREEN
        );
    }

    #[test]
    fn in_flight_guard_can_retarget_and_drops_running_count() {
        let state = Arc::new(Mutex::new(RouterState::default()));
        let selection = RouteSelection {
            route_id: "a:m".to_string(),
            reason: "least_running",
            cache_match_rate: 0.0,
            running_at_select: 0,
        };

        let mut guard = RouteInFlight::start(state.clone(), &selection);
        assert_eq!(state.lock().unwrap().stats["a:m"].running, 1);

        guard.retarget("b:m");
        {
            let locked = state.lock().unwrap();
            assert_eq!(locked.stats["a:m"].running, 0);
            assert_eq!(locked.stats["b:m"].running, 1);
        }

        drop(guard);
        assert_eq!(state.lock().unwrap().stats["b:m"].running, 0);
    }

    #[test]
    fn routing_history_is_bounded() {
        let mut state = RouterState::default();
        let long = "x".repeat(MAX_ROUTING_HISTORY_CHARS + 10);

        state.record_history("m", "a:m", &long, 16);

        let len = state.history["m"]["a:m"][0].chars().count();
        assert_eq!(len, MAX_ROUTING_HISTORY_CHARS);
    }

    #[test]
    fn bounded_routing_text_caps_extracted_prompt_text() {
        let long = "x".repeat(MAX_ROUTING_HISTORY_CHARS + 10);
        let text = bounded_routing_text(
            &json!({
                "messages": [
                    {"role": "system", "content": long},
                    {"role": "user", "content": "must not be reached"}
                ]
            }),
            Endpoint::ChatComplete,
        );

        assert_eq!(text.chars().count(), MAX_ROUTING_HISTORY_CHARS);
        assert!(text.starts_with("system:"));
        assert!(!text.contains("must not be reached"));
    }

    fn test_route(route_id: &str) -> RouterRoute {
        let upstream_name = route_id.split(':').next().unwrap_or(route_id).to_string();
        RouterRoute {
            route_id: route_id.to_string(),
            upstream_name,
            candidate: RouteCandidate {
                route_id: route_id.to_string(),
                format: ProviderFormat::Openai,
                engine: None,
            },
        }
    }

    fn test_metrics(
        observed_running: f64,
        observed_waiting: f64,
        global_limit: f64,
        basic_limit: f64,
        basic_inflight: f64,
    ) -> UpstreamMetrics {
        UpstreamMetrics {
            ok: true,
            updated_at: Some(Instant::now()),
            observed_running: Some(observed_running),
            observed_waiting: Some(observed_waiting),
            global_limit: Some(global_limit),
            basic_limit: Some(basic_limit),
            basic_inflight: Some(basic_inflight),
            premium_inflight: Some(0.0),
            error: None,
        }
    }
}

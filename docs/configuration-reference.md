# Configuration Reference

Private AI Gateway uses one read-only static config file and one writable state
directory. Operators must choose the config file with
`PRIVATE_AI_GATEWAY_CONFIG_PATH` and put gateway policy in that file.

## Runtime Files

| Item | Owner | Runtime path |
| --- | --- | --- |
| Static gateway config | Deployment | Required. Selected by `PRIVATE_AI_GATEWAY_CONFIG_PATH`. |
| Upstream seed config | Deployment | Selected by `upstream_config_seed_path` in the static gateway config. |
| Active upstream config | Gateway | `<state_dir>/upstreams.json` |
| Attested-session log | Gateway | `<state_dir>/sessions.jsonl` |

Operators configure `state_dir`, not the individual writable files inside it.
The gateway creates `state_dir` on startup, seeds `upstreams.json` from the
read-only upstream seed only when the active file is missing or empty, and
updates `upstreams.json` through the upstream admin API. Use
`PATCH /v1/admin/upstreams/{name}` for safe enable/disable toggles. Use
`PUT /v1/admin/upstreams` only for intentional full-config replacement.

Unknown fields in the static gateway config are rejected at startup.

## Minimal Config

This is the smallest practical container config.

```json
{
  "bind": "0.0.0.0:8086",
  "state_dir": "/var/lib/private-ai-gateway",
  "upstream_config_seed_path": "/etc/private-ai-gateway/upstreams.seed.json",
  "admin_token": "<long-random-admin-token>",
  "api_token": "<long-random-api-token>",
  "dstack_endpoint": "unix:/var/run/dstack.sock"
}
```

## Config Fields

| Field | Default | Meaning |
| --- | --- | --- |
| `bind` | `127.0.0.1:8086` | Public HTTP listener address. Use `0.0.0.0:8086` in containers that expose the gateway port. |
| `state_dir` | `/var/lib/private-ai-gateway` | Gateway-owned writable state directory. The active upstream config and attested-session log are derived from this directory. |
| `upstream_config_seed_path` | unset | Read-only JSON seed copied to `<state_dir>/upstreams.json` only when the active upstream config is missing or empty. |
| `admin_token` | unset | Bearer token for `GET`, `PUT`, and `PATCH` upstream admin APIs. When unset, the admin API is not exposed. |
| `api_token` | unset | Bearer token for `/v1/models`, `/v1/metrics`, `/v1/upstream-status`, and OpenAI-compatible inference POST endpoints. When unset, those endpoints remain open for local development. Production deployments should set it. |
| `dstack_endpoint` | dstack SDK default | dstack SDK endpoint, such as `unix:/var/run/dstack.sock`. |
| `middleware` | unset | Optional middleware section. When present, the gateway runs in-process middleware before the verified backend forward; when unset it serves directly. See [Middleware](#middleware). |

## Middleware

The optional `middleware` section runs middleware in the request path. The
middleware is inside the gateway process, after frontend normalization and
before the verified backend forward. It may choose routes or transform request
and response payloads, but upstream verification, channel binding, forwarding,
and receipt finalization remain backend responsibilities. When the section is
omitted the gateway serves directly.

This fork supports one middleware shape: a single public model routed across
multiple configured upstreams with cache-aware and PIG-aware load ordering. The
router polls each configured upstream's metrics endpoint in the background and
uses PIG's observed running, waiting, global limit, and tier counters to avoid
full or pressured nodes before forwarding. Under balanced pressure it still
prefers warmed prefixes; when equally idle it uses processed-count tie-breaking
so cold traffic spreads across nodes. If upstream metrics are unavailable or
stale, routing falls back to gateway-local in-flight counters instead of
blocking traffic. It does not use `control_url`, `proxy_url`, or an external
adapter/vLLM Router process. See [router-middleware.md](router-middleware.md)
for the selection algorithm and security boundary.

| Field | Default | Use |
| --- | --- | --- |
| `middleware.public_model` | unset | Public model id served by this gateway. When unset, the router derives it from the live upstream config and requires exactly one unique public model. |
| `middleware.cache_threshold` | `0.30` | Minimum common-prefix match rate needed to prefer a previously warmed route when load is balanced. |
| `middleware.balance_abs_threshold` | `64` | Absolute running-request gap above which the router ignores cache affinity and drains toward the least-running route. |
| `middleware.balance_rel_threshold` | `1.50` | Relative running-request gap above which the router ignores cache affinity and drains toward the least-running route. |
| `middleware.max_history_per_route` | `256` | Maximum routing-text samples kept per public model and route for prefix matching. Each stored routing text is capped internally and the cap is visible as `routing_text_max_chars` in `/v1/admin/router`. |
| `middleware.metrics_poll_ms` | `1000` | Background upstream metrics polling interval. Set to `0` to disable PIG-aware routing and use only gateway-local in-flight counters. |
| `middleware.metrics_timeout_ms` | `800` | Per-upstream metrics request timeout. Polling is concurrent, so one slow upstream does not serially delay the full target set. |
| `middleware.metrics_stale_ms` | `3000` | Age after which a metrics sample is ignored and the route falls back to local in-flight state. |
| `middleware.metrics_path` | `/v1/metrics` | Metrics path appended to each upstream base URL. The upstream's configured bearer token is used for metrics auth. |
| `middleware.trusted_user_tier_header` | `false` | Whether inbound `x-user-tier` is trusted for routing and forwarding to PIG. Keep `false` for public endpoints unless a trusted front door strips or sets this header. With the default, all requests are routed as `basic` and no caller-supplied tier header is forwarded. |
| `middleware.default_engine` | unset | Optional engine hint put into synthetic route candidates, for example `vllm` or `sglang`. |
| `middleware.sse_keepalive_ms` | `10000` | Idle keep-alive interval for streaming responses; `0` disables the heartbeat. |

The inference HTTP surface accepts request bodies up to 32 MB. This is a
bounded increase over axum's 2 MB default so multimodal payloads with base64
image parts are not rejected before the gateway can log or classify them.

Request outcome observation is always on for the router middleware completion
path. Failed requests that reach routing, shaping, upstream forwarding, or
response finalization emit structured `request_outcome` tracing lines with
request id, public model, selected route when known, attempt index,
client-facing status, upstream status, phase, and duration. Final 429 responses
are excluded from this log to avoid high-volume noise. Error detail is
single-line and length-capped, and is emitted only when the `request_outcome`
target is enabled at `debug` through `RUST_LOG`; the default info line keeps
detail blank. Stream body errors additionally emit `stream_abort` and then end
the HTTP body gracefully instead of forcing Hyper to reset the connection.

```json
{
  "middleware": {
    "public_model": "public-model",
    "cache_threshold": 0.3,
    "balance_abs_threshold": 64,
    "balance_rel_threshold": 1.5,
    "max_history_per_route": 256,
    "metrics_poll_ms": 1000,
    "metrics_timeout_ms": 800,
    "metrics_stale_ms": 3000,
    "metrics_path": "/v1/metrics",
    "trusted_user_tier_header": false,
    "default_engine": "vllm"
  }
}
```

The route set comes from the active upstream config. Dynamic upstream inspection
and replacement remain `GET` and `PUT /v1/admin/upstreams` with the gateway
admin bearer token. Dynamic enable/disable should use
`PATCH /v1/admin/upstreams/{name}` so the node remains visible in admin
snapshots.
The router exposes an authenticated
`GET /v1/admin/router` snapshot with current route counters, in-flight counts,
selection counters, history sample counts, redacted PIG metrics status, router
config, and upstream config digest. The endpoint returns `404` when the admin
token is unset or the middleware is not enabled. The snapshot never includes
upstream bearer tokens.

Tier handling is deliberately fail-safe. The router can use PIG's basic and
premium counters, but it trusts the caller's `x-user-tier` only when
`middleware.trusted_user_tier_header=true`. Otherwise the router treats the
request as `basic` and removes the header before forwarding, so a public client
cannot self-promote into the premium lane.

## Source Provenance

Source provenance is not a gateway config field. The gateway reports source
provenance from the dstack git-launcher pin at
`/etc/git-launcher/gateway.conf`:

```text
REPO_URL=https://github.com/hieule88/phala-llm-router.git
COMMIT_SHA=<audited-full-40-or-64-hex-commit-sha>
WORK_DIR=/var/lib/git-launcher/private-ai-gateway-router
```

When the launcher config is absent, source provenance is unknown and the
gateway omits `source_provenance` from attestation reports. Production
deployments should use `git-launcher`; relying parties should compare reported
source provenance, when present, with the `REPO_URL` and `COMMIT_SHA` covered by
the attested dstack compose.

If the launcher config exists, `COMMIT_SHA` must be a full 40- or 64-character
hexadecimal commit hash. Branch names, tags, and short hashes are rejected at
startup.

## TLS Binding

TLS binding is optional. Configure it only when clients verify the gateway's
public TLS certificate SPKI from the attested keyset.

| Field | Use |
| --- | --- |
| `tls.domain_certificates` | One mounted leaf certificate per public hostname. |

For multi-domain listening, use `tls.domain_certificates`:

```json
{
  "tls": {
    "domain_certificates": [
      {
        "domain": "api.example.com",
        "certificate_path": "/run/certs/api.pem"
      },
      {
        "domain": "chat.example.com",
        "certificate_path": "/run/certs/chat.pem"
      }
    ]
  }
}
```

Raw SPKI digest inputs are not supported. The gateway reads mounted leaf
certificates, computes `sha256(SPKI)`, and publishes those digests in the
attested keyset. When `tls.domain_certificates` is configured, the request
`Host` selects the matching downstream TLS binding for
`/v1/attestation/report`. Unknown hosts return `404 not_found`.

## Upstream Config

The upstream seed file and active upstream database use the same JSON shape: an
array of upstream entries. The seed file is deployment-owned and read-only. The
active file at `<state_dir>/upstreams.json` is gateway-owned and is replaced by
the admin API.

```json
[
  {
    "name": "route-a",
    "enabled": true,
    "provider": "aci-service",
    "base_url": "https://upstream-a.example",
    "models": {
      "public-model": "provider-model"
    },
    "accepted_workload_ids": ["<workload-id>"],
    "accepted_dstack_kms_root_public_keys": ["<kms-root-public-key>"]
  }
]
```

`enabled` defaults to `true`. Set it to `false` when a configured node should
remain visible to admin tooling but must not receive traffic. Disabled upstreams
are excluded from middleware route candidates, PIG metrics polling, attestation
prewarm/refresh, and provider session refresh.

For operational disable/re-enable flows, prefer:

```text
PATCH /v1/admin/upstreams/route-a
{"enabled": false}
```

This preserves the rest of the node config, including bearer-token presence and
model mapping. `PUT /v1/admin/upstreams` replaces the whole file and will remove
any upstream omitted from the submitted array.

Supported `provider` values:

| Provider | Use |
| --- | --- |
| `openai-compatible` | Generic OpenAI-compatible upstream with no provider-owned verifier. |
| `aci-service` | ACI service that exposes dstack/DCAP evidence. |
| `tinfoil` | Tinfoil provider adapter. |
| `near-ai` | NEAR AI provider adapter. |
| `chutes` | Chutes provider adapter. |
| `phala-direct` | Direct Phala dstack-vllm-proxy endpoint. |

Provider verification policy belongs on the upstream entry. For ACI service
routes, configure accepted workload ids, image digests, or dstack KMS root
public keys on that entry.

For `aci-service`, `base_url` is the HTTPS origin used for both model traffic and
`/v1/attestation/report`. The router fetches the report through normal TLS,
derives the attested TLS SPKI binding from that report, then pins that SPKI for
the actual upstream model request.

## Environment Variables

The gateway runtime reads only these environment variables. Provider verifier
bridges may consume provider-specific environment variables such as
`DSTACK_VERIFIER_URL` or `PRIVATE_AI_VERIFIER_DIR`.

| Variable | Use |
| --- | --- |
| `PRIVATE_AI_GATEWAY_CONFIG_PATH` | Required. Selects the static gateway config file. |
| `RUST_LOG` | Tracing filter consumed by `tracing_subscriber`. |

Deployment tooling also uses these variables:

| Variable | Use |
| --- | --- |
| `PRIVATE_AI_GATEWAY_CACHE_DIR` | `entrypoint.sh` build and toolchain cache root. Defaults to `/var/lib/private-ai-gateway/cache`. |
| `CARGO_HOME` | Optional override for Cargo cache. Defaults under `PRIVATE_AI_GATEWAY_CACHE_DIR`. |
| `RUSTUP_HOME` | Optional override for Rustup state. Defaults under `PRIVATE_AI_GATEWAY_CACHE_DIR`. |
| `CARGO_TARGET_DIR` | Optional override for Cargo build output. Defaults under `PRIVATE_AI_GATEWAY_CACHE_DIR`. |
| `PRIVATE_AI_GATEWAY_REPO_COMMIT` | Used by `deploy/compose.yaml` interpolation for the git-launcher `COMMIT_SHA` pin. |
| `PRIVATE_AI_GATEWAY_ADMIN_TOKEN` | Used by `deploy/compose.yaml` interpolation for the static config's `admin_token`. |
| `PRIVATE_AI_GATEWAY_API_TOKEN` | Used by `deploy/compose.yaml` interpolation for the static config's `api_token`. |

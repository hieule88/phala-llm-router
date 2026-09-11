#!/usr/bin/env python3
"""Sync the gateway's NEAR AI upstream model map with what NEAR AI actually serves.

Selects the NEAR AI models that are safe for this gateway and updates the
upstream map over the admin API (PUT /v1/admin/upstreams) — no redeploy needed.

A model is mapped only when ALL hold:
  - `owned_by` == "nearai"      — runs on NEAR's TEE GPUs; proxied providers
                                  (anthropic/openai/google/x-ai/…) reject the
                                  web_context_search tool with HTTP 400, so a
                                  websearch-enabled request would fail outright
  - `is_ready` is true          — actually serving
  - "tools" in supported_features — required by the websearch tool injection
  - not past its `deprecation_date` (models with a FUTURE date are kept and
    warned about; pass --drop-deprecating to remove them proactively)

Public aliases: an upstream id already present in the gateway map keeps its
existing alias (clients keep working); a new id gets the segment after "/",
lowercased, with a trailing "-fp8" stripped (matches existing convention:
z-ai/glm-5.3-flash -> glm-5.3-flash, Qwen/Qwen3.6-35B-A3B-FP8 -> qwen3.6-35b-a3b).

Dry-run by default — prints the diff and exits. Pass --apply to PUT the new map.

Usage:
  python3 scripts/sync_nearai_models.py --api-key sk-... \
      --gateway https://<app>-8086.dstack-pha-prod9.phala.network \
      --admin-token <token> [--apply] [--drop-deprecating]

  # tokens can come from the environment instead of flags:
  #   NEARAI_API_KEY, GATEWAY_URL, PRIVATE_AI_GATEWAY_ADMIN_TOKEN
  source phala.env && python3 scripts/sync_nearai_models.py \
      --api-key sk-... --gateway https://... --apply
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

NEARAI_BASE = "https://cloud-api.near.ai"


def http_json(url, *, token, method="GET", body=None, timeout=30):
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        sys.exit(f"error: {method} {url} -> HTTP {e.code}\n{detail}")
    except urllib.error.URLError as e:
        sys.exit(f"error: {method} {url} -> {e.reason}")


def parse_deprecation(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None  # unparseable date: treat as not scheduled, but it prints raw


def default_alias(upstream_id):
    alias = upstream_id.rsplit("/", 1)[-1].lower()
    if alias.endswith("-fp8"):
        alias = alias[: -len("-fp8")]
    return alias


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api-key", default=os.environ.get("NEARAI_API_KEY"),
                    help="NEAR AI API key (env NEARAI_API_KEY)")
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY_URL"),
                    help="gateway base URL (env GATEWAY_URL)")
    ap.add_argument("--admin-token",
                    default=os.environ.get("PRIVATE_AI_GATEWAY_ADMIN_TOKEN"),
                    help="gateway admin token (env PRIVATE_AI_GATEWAY_ADMIN_TOKEN)")
    ap.add_argument("--base-url", default=NEARAI_BASE,
                    help=f"NEAR AI API base (default {NEARAI_BASE})")
    ap.add_argument("--upstream", default="nearai",
                    help="name of the upstream entry to sync (default: nearai)")
    ap.add_argument("--apply", action="store_true",
                    help="PUT the new map to the gateway (default: dry-run)")
    ap.add_argument("--drop-deprecating", action="store_true",
                    help="also remove models whose deprecation date is still in the future")
    args = ap.parse_args()

    for name, value in (("--api-key", args.api_key), ("--gateway", args.gateway),
                        ("--admin-token", args.admin_token)):
        if not value:
            ap.error(f"{name} is required (flag or its environment variable)")
    gateway = args.gateway.rstrip("/")
    now = datetime.now(timezone.utc)

    # ── What the gateway currently maps ──────────────────────────────────────
    current_cfg = http_json(f"{gateway}/v1/admin/upstreams", token=args.admin_token)
    upstreams = current_cfg.get("upstreams") or []
    others = [u["name"] for u in upstreams if u["name"] != args.upstream]
    if others:
        # PUT replaces the whole config, and GET never returns the other
        # upstreams' bearer tokens — refusing beats silently wiping them.
        sys.exit(f"error: gateway also has upstreams {others}; this script only "
                 f"handles a config whose sole upstream is '{args.upstream}'")
    entry = next((u for u in upstreams if u["name"] == args.upstream), None)
    current_map = dict(entry["models"]) if entry else {}
    alias_of = {upstream_id: alias for alias, upstream_id in current_map.items()}

    # ── What NEAR AI serves ──────────────────────────────────────────────────
    catalog = http_json(f"{args.base_url}/v1/models", token=args.api_key)["data"]
    eligible, skipped = {}, []
    for m in catalog:
        mid = m["id"]
        if m.get("owned_by") != "nearai":
            continue  # proxied providers break websearch (400 on the tool)
        dep = parse_deprecation(m.get("deprecation_date"))
        if m.get("is_ready") is not True:
            skipped.append((mid, "not ready"))
        elif "tools" not in (m.get("supported_features") or []):
            skipped.append((mid, "no tool support (websearch would fail)"))
        elif dep and dep <= now:
            skipped.append((mid, f"deprecated since {dep:%Y-%m-%d %H:%M} UTC"))
        elif dep and args.drop_deprecating:
            skipped.append((mid, f"deprecating {dep:%Y-%m-%d %H:%M} UTC (--drop-deprecating)"))
        elif dep and mid not in alias_of:
            # A live but already-scheduled model: keep it if clients depend on
            # it, but never ONBOARD a model that is about to disappear.
            skipped.append((mid, f"deprecating {dep:%Y-%m-%d %H:%M} UTC — not adding"))
        else:
            eligible[mid] = dep

    # ── New map: keep existing aliases, add defaults for new ids ─────────────
    new_map = {}
    for mid in sorted(eligible):
        alias = alias_of.get(mid) or default_alias(mid)
        if alias in new_map:
            sys.exit(f"error: alias collision '{alias}' "
                     f"({new_map[alias]} vs {mid}) — map one of them manually")
        new_map[alias] = mid

    # ── Report ───────────────────────────────────────────────────────────────
    added = sorted(set(new_map) - set(current_map))
    removed = sorted(set(current_map) - set(new_map))
    kept = sorted(set(new_map) & set(current_map))
    print(f"NEAR AI catalog: {len(catalog)} models, "
          f"{sum(1 for m in catalog if m.get('owned_by') == 'nearai')} owned by nearai, "
          f"{len(eligible)} eligible")
    for mid, why in sorted(skipped):
        print(f"  skip  {mid:42} {why}")
    print(f"\nGateway map '{args.upstream}' @ {gateway}")
    for alias in kept:
        note = ""
        dep = eligible.get(new_map[alias])
        if dep:
            note = f"  ⚠ DEPRECATING {dep:%Y-%m-%d %H:%M} UTC — plan removal"
        print(f"  keep  {alias:24} -> {new_map[alias]}{note}")
    for alias in added:
        print(f"  ADD   {alias:24} -> {new_map[alias]}")
    for alias in removed:
        print(f"  DROP  {alias:24} -> {current_map[alias]}")
    if not added and not removed:
        print("  (no changes)")

    if not args.apply:
        print("\ndry-run only — re-run with --apply to update the gateway")
        return
    if not new_map:
        sys.exit("error: refusing to apply an EMPTY model map")

    payload = [{
        "name": args.upstream,
        "enabled": True,
        "provider": "openai-compatible",
        "base_url": args.base_url,
        "models": new_map,
        "bearer_token": args.api_key,
    }]
    result = http_json(f"{gateway}/v1/admin/upstreams", token=args.admin_token,
                       method="PUT", body=payload)
    print(f"\napplied — config digest: {result.get('config_digest')}")
    served = http_json(f"{gateway}/v1/admin/upstreams", token=args.admin_token)
    live = sorted(served["upstreams"][0]["models"])
    print(f"gateway now maps: {', '.join(live)}")


if __name__ == "__main__":
    main()

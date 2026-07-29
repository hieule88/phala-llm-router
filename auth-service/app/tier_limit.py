"""Per-tier sliding-window rate limiter.

Distinct from the auth service's monthly quota (which bounds total proves
per billing period) — this bounds the *short-term* arrival rate per
identity to prevent a single user from monopolising the upstream prover
queue or the TEE's dstack quota.

Design mirrors the limiter in `phala-TEE/attestation-proxy/rate_limit.py`
but keys on identity_id and resolves the limit through the tier name. The
two limiters do not share state — the proxy's IP-based limit guards the
attestation endpoint, and this one (when wired up via F4) guards the gRPC
Prove path.
"""

import asyncio
import time
from collections import deque

from .tiers import get_tier


class TierRateLimiter:
    """Per-identity sliding window, with the limit driven by tier.

    A separate deque per identity holds monotonic timestamps within the
    window. Stale entries evict on the next check. The bucket dict is
    capped (`max_keys`) so an attacker rotating identities cannot grow
    memory without bound — same defence as the proxy's IP limiter.
    """

    DEFAULT_MAX_KEYS = 100_000
    DEFAULT_WINDOW_SEC = 1.0

    def __init__(
        self,
        window_sec: float = DEFAULT_WINDOW_SEC,
        max_keys: int = DEFAULT_MAX_KEYS,
    ):
        if window_sec <= 0:
            raise ValueError("window_sec must be > 0")
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self.window_sec = window_sec
        self.max_keys = max_keys
        self._buckets: dict[int, deque] = {}
        self._lock = asyncio.Lock()
        self._calls_since_sweep = 0
        self._sweep_every = 1000

    async def check(
        self,
        identity_id: int,
        tier_name: str,
        now: float | None = None,
    ) -> bool:
        """Return True if a request for this identity at this tier is allowed.

        `tier_name` is looked up each call so a tier upgrade takes effect
        immediately — the limit can change between consecutive checks
        without needing to invalidate the bucket.
        """
        tier = get_tier(tier_name)
        limit = tier.rps
        if now is None:
            now = time.monotonic()
        cutoff = now - self.window_sec
        async with self._lock:
            bucket = self._buckets.setdefault(identity_id, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            allowed = len(bucket) < limit
            if allowed:
                bucket.append(now)

            self._calls_since_sweep += 1
            if self._calls_since_sweep >= self._sweep_every:
                self._calls_since_sweep = 0
                self._sweep_locked(cutoff)

            if len(self._buckets) > self.max_keys:
                self._evict_oldest_locked()

            return allowed

    def _sweep_locked(self, cutoff: float) -> None:
        stale = [k for k, b in self._buckets.items() if not b or b[-1] < cutoff]
        for k in stale:
            self._buckets.pop(k, None)

    def _evict_oldest_locked(self) -> None:
        ordered = sorted(
            self._buckets.items(),
            key=lambda kv: kv[1][-1] if kv[1] else float("-inf"),
        )
        to_drop = len(self._buckets) - self.max_keys
        for k, _ in ordered[:to_drop]:
            self._buckets.pop(k, None)

    async def reset(self) -> None:
        """Clear all buckets — tests only."""
        async with self._lock:
            self._buckets.clear()
            self._calls_since_sweep = 0

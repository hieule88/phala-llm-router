"""Tier definitions.

Centralised here so the auth-service handlers, the rate limiter, and any
external tooling agree on the numbers. Changing a tier value here is the
only place a deployment needs to touch.

Two numbers per tier:
  - `prove_per_month` — total quota issued at the start of each billing
    period. Becomes the `balances.balance` value on monthly renewal.
  - `rps` — maximum sustained prove requests per second from a single
    identity. Bursts may briefly exceed this depending on the rate
    limiter's window size.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Tier:
    name: str
    prove_per_month: int
    rps: int


TIERS: dict[str, Tier] = {
    "free":    Tier(name="free",    prove_per_month=100,     rps=1),
    "starter": Tier(name="starter", prove_per_month=10_000,  rps=10),
    "pro":     Tier(name="pro",     prove_per_month=100_000, rps=50),
}


def get_tier(name: str) -> Tier:
    """Look up a tier by name; falls back to `free` for unknown values so a
    misconfigured user record can never bypass limits."""
    return TIERS.get(name, TIERS["free"])

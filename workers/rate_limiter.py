"""
Cloudflare Workers KV-based Rate Limiter.

Implements a sliding-window rate limiter that mirrors the behaviour of
Cloudflare's Workers KV namespace with a Redis-compatible in-process
backend for local testing.

Algorithm
---------
Sliding-window log: store per-key timestamps in a sorted list.  On each
request, evict entries older than the window, count remaining entries, and
either allow or deny.

Burst allowance lets a client exceed the per-second rate for short
intervals without being blocked, provided the average over the full window
remains within the limit.

Public API
----------
RateLimiter(store, config)         — main class
RateLimiter.is_allowed(key)        → (allowed: bool, metadata: dict)
RateLimiter.get_status(key)        → dict
RateLimiter.reset(key)             → None
KVStore                            — in-process KV (Redis-compatible interface)
RateLimitConfig                    — configuration dataclass
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# KV Store (in-process, Redis-compatible interface)
# ---------------------------------------------------------------------------

class KVStore:
    """
    Thread-safe in-process key-value store with sorted-set semantics.

    Mirrors the Redis commands used by sliding-window rate limiters:
    - ``zadd(key, score, member)``
    - ``zrangebyscore(key, min_score, max_score)``
    - ``zremrangebyscore(key, min_score, max_score)``
    - ``zcard(key)``
    - ``delete(key)``
    - ``expire(key, ttl_seconds)`` (no-op for in-process; GC is implicit)
    """

    def __init__(self) -> None:
        self._data: dict[str, list[tuple[float, str]]] = {}
        self._lock = threading.Lock()
        self._member_counter: int = 0

    # -- sorted-set operations ------------------------------------------------

    def zadd(self, key: str, score: float, member: str | None = None) -> None:
        """Add (score, member) to the sorted set at *key*."""
        if member is None:
            with self._lock:
                self._member_counter += 1
                member = str(self._member_counter)
        with self._lock:
            bucket = self._data.setdefault(key, [])
            bucket.append((score, member))
            bucket.sort(key=lambda x: x[0])

    def zrangebyscore(
        self, key: str, min_score: float, max_score: float
    ) -> list[tuple[float, str]]:
        """Return all entries with score in [min_score, max_score]."""
        with self._lock:
            bucket = self._data.get(key, [])
            return [
                (score, member)
                for score, member in bucket
                if min_score <= score <= max_score
            ]

    def zremrangebyscore(
        self, key: str, min_score: float, max_score: float
    ) -> int:
        """Remove all entries with score in [min_score, max_score]. Returns count removed."""
        with self._lock:
            bucket = self._data.get(key, [])
            before = len(bucket)
            self._data[key] = [
                (score, member)
                for score, member in bucket
                if not (min_score <= score <= max_score)
            ]
            return before - len(self._data[key])

    def zcard(self, key: str) -> int:
        """Return number of entries in the sorted set at *key*."""
        with self._lock:
            return len(self._data.get(key, []))

    def delete(self, key: str) -> None:
        """Delete the key entirely."""
        with self._lock:
            self._data.pop(key, None)

    def expire(self, key: str, ttl_seconds: int) -> None:
        """No-op in the in-process backend (data is GC'd implicitly via score eviction)."""

    def keys(self) -> list[str]:
        """Return all current keys (for diagnostics)."""
        with self._lock:
            return list(self._data.keys())


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RateLimitConfig:
    """
    Rate-limiter configuration.

    Attributes
    ----------
    requests_per_window:
        Maximum number of requests allowed in the sliding window.
    window_seconds:
        Duration of the sliding window in seconds.
    burst_multiplier:
        Fraction above the limit allowed as instantaneous burst.
        ``burst_multiplier=1.5`` means up to 150% of the limit in any
        sub-window equal to ``burst_window_seconds``.
    burst_window_seconds:
        The sub-window used to evaluate burst allowance.
    key_prefix:
        Namespace prefix added to every KV key (prevents collisions).
    """

    requests_per_window: int = 100
    window_seconds: float = 60.0
    burst_multiplier: float = 1.5
    burst_window_seconds: float = 1.0
    key_prefix: str = "rl:"


# ---------------------------------------------------------------------------
# Rate limiter result
# ---------------------------------------------------------------------------

@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    reset_at: float          # Unix timestamp when the oldest entry expires
    retry_after: float       # seconds to wait if denied (0.0 if allowed)
    burst_remaining: int
    request_count: int


# ---------------------------------------------------------------------------
# Main rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Sliding-window rate limiter backed by a :class:`KVStore`.

    Parameters
    ----------
    store:
        A :class:`KVStore` instance (or any object with the same interface).
    config:
        :class:`RateLimitConfig` with window/limit parameters.
    clock:
        Callable returning the current time as a float.  Defaults to
        ``time.time``.  Override in tests to control time.
    """

    def __init__(
        self,
        store: KVStore,
        config: RateLimitConfig | None = None,
        clock: Any = None,
    ) -> None:
        self._store = store
        self._config = config or RateLimitConfig()
        self._clock: Any = clock or time.time

    # -- public interface -----------------------------------------------------

    def is_allowed(self, key: str) -> tuple[bool, RateLimitResult]:
        """
        Evaluate whether the request identified by *key* should be allowed.

        Parameters
        ----------
        key:
            Rate-limit key (e.g. ``"ip:203.0.113.1"`` or ``"route:/api/v1/chat"``).

        Returns
        -------
        tuple[bool, RateLimitResult]
            ``(True, result)`` if the request is within the rate limit.
            ``(False, result)`` if it should be rejected.
        """
        now = self._clock()
        cfg = self._config
        kv_key = f"{cfg.key_prefix}{key}"
        window_start = now - cfg.window_seconds
        burst_start = now - cfg.burst_window_seconds

        # Burst limit: how many requests are allowed in the burst sub-window.
        # Computed as: (burst_window / full_window) * limit * burst_multiplier,
        # floored at 1.  When burst_window == full_window this equals limit * multiplier.
        ratio = cfg.burst_window_seconds / cfg.window_seconds
        burst_limit = max(1, int(cfg.requests_per_window * ratio * cfg.burst_multiplier))

        # Evict expired entries (older than the full window)
        self._store.zremrangebyscore(kv_key, 0, window_start)

        # Count current full window
        current_count = self._store.zcard(kv_key)

        # Count burst sub-window
        burst_entries = self._store.zrangebyscore(kv_key, burst_start, now)
        burst_count = len(burst_entries)

        # Determine oldest entry's expiry (for Retry-After header)
        all_entries = self._store.zrangebyscore(kv_key, window_start, now)
        reset_at = (all_entries[0][0] + cfg.window_seconds) if all_entries else (now + cfg.window_seconds)

        # Allow/deny: only apply burst gate if burst_limit < full window limit
        # (avoids the burst gate blocking legitimate traffic when the burst window
        #  is much shorter than the full window and all requests arrive at the same instant)
        window_ok = current_count < cfg.requests_per_window
        if burst_limit < cfg.requests_per_window:
            burst_ok = burst_count < burst_limit
        else:
            burst_ok = True
        allowed = window_ok and burst_ok

        if allowed:
            self._store.zadd(kv_key, now)
            self._store.expire(kv_key, int(cfg.window_seconds) + 1)
            current_count += 1

        remaining = max(0, cfg.requests_per_window - current_count)
        burst_remaining = max(0, burst_limit - burst_count - (1 if allowed else 0))
        retry_after = 0.0 if allowed else max(0.0, reset_at - now)

        result = RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            limit=cfg.requests_per_window,
            reset_at=reset_at,
            retry_after=retry_after,
            burst_remaining=burst_remaining,
            request_count=current_count,
        )
        return allowed, result

    def get_status(self, key: str) -> dict[str, Any]:
        """Return current rate-limit status for *key* without consuming a slot."""
        now = self._clock()
        cfg = self._config
        kv_key = f"{cfg.key_prefix}{key}"
        window_start = now - cfg.window_seconds

        self._store.zremrangebyscore(kv_key, 0, window_start)
        current_count = self._store.zcard(kv_key)
        remaining = max(0, cfg.requests_per_window - current_count)

        all_entries = self._store.zrangebyscore(kv_key, window_start, now)
        reset_at = (all_entries[0][0] + cfg.window_seconds) if all_entries else now

        return {
            "key": key,
            "count": current_count,
            "limit": cfg.requests_per_window,
            "remaining": remaining,
            "window_seconds": cfg.window_seconds,
            "reset_at": reset_at,
        }

    def reset(self, key: str) -> None:
        """Clear all rate-limit data for *key*."""
        kv_key = f"{self._config.key_prefix}{key}"
        self._store.delete(kv_key)

    # -- per-route helpers ----------------------------------------------------

    @staticmethod
    def route_key(route: str, identifier: str) -> str:
        """Build a combined key from a route and an IP/user identifier."""
        return f"route:{route}:id:{identifier}"

    @staticmethod
    def ip_key(ip_address: str) -> str:
        """Build a per-IP rate-limit key."""
        return f"ip:{ip_address}"

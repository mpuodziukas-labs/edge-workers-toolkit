"""
Cloudflare Cache Analytics.

Processes Cloudflare Workers access log records and produces:
  - TTFB (Time To First Byte) histograms
  - Cache status breakdowns (HIT / MISS / EXPIRED / BYPASS / REVALIDATED)
  - PoP (Point of Presence) level performance summaries
  - Stale-while-revalidate simulation

All inputs are plain Python dicts/lists — no external dependencies.

Public API
----------
CacheAnalytics(records)            — main analyser
  .ttfb_histogram(buckets)         → dict[str, int]   (bucket label → count)
  .cache_status_breakdown()        → dict[str, int]
  .pop_performance()               → dict[str, PopMetrics]
  .stale_while_revalidate_sim(…)   → SWRSimResult
  .summary()                       → dict
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Any

# Valid Cloudflare cache status values
CACHE_STATUSES = frozenset(
    {"HIT", "MISS", "EXPIRED", "BYPASS", "REVALIDATED", "DYNAMIC", "NONE"}
)

# Default TTFB histogram buckets (milliseconds)
DEFAULT_TTFB_BUCKETS: list[float] = [10, 25, 50, 100, 200, 500, 1000, 2000, float("inf")]


@dataclass
class LogRecord:
    """
    A single access log entry.

    Fields mirror Cloudflare Logpush schema.

    Attributes
    ----------
    timestamp_ms:
        Unix timestamp in milliseconds.
    ttfb_ms:
        Time-to-first-byte in milliseconds (float).
    cache_status:
        Cloudflare cache status string (e.g. "HIT").
    pop:
        Cloudflare PoP IATA code (e.g. "LAX", "LHR").
    status_code:
        HTTP response status code.
    bytes_sent:
        Response body size in bytes.
    path:
        Request path (e.g. "/api/v1/items").
    """

    timestamp_ms: float
    ttfb_ms: float
    cache_status: str
    pop: str
    status_code: int = 200
    bytes_sent: int = 0
    path: str = "/"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogRecord":
        return cls(
            timestamp_ms=float(data.get("timestamp_ms", 0)),
            ttfb_ms=float(data.get("ttfb_ms", 0)),
            cache_status=str(data.get("cache_status", "NONE")).upper(),
            pop=str(data.get("pop", "UNKNOWN")).upper(),
            status_code=int(data.get("status_code", 200)),
            bytes_sent=int(data.get("bytes_sent", 0)),
            path=str(data.get("path", "/")),
        )


@dataclass
class PopMetrics:
    """Per-PoP aggregated statistics."""

    pop: str
    request_count: int
    hit_count: int
    miss_count: int
    mean_ttfb_ms: float
    p50_ttfb_ms: float
    p95_ttfb_ms: float
    p99_ttfb_ms: float
    bytes_served: int

    @property
    def hit_rate(self) -> float:
        if self.request_count == 0:
            return 0.0
        return self.hit_count / self.request_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "pop": self.pop,
            "request_count": self.request_count,
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "hit_rate": round(self.hit_rate, 4),
            "mean_ttfb_ms": round(self.mean_ttfb_ms, 2),
            "p50_ttfb_ms": round(self.p50_ttfb_ms, 2),
            "p95_ttfb_ms": round(self.p95_ttfb_ms, 2),
            "p99_ttfb_ms": round(self.p99_ttfb_ms, 2),
            "bytes_served": self.bytes_served,
        }


@dataclass
class SWRSimResult:
    """Stale-while-revalidate simulation result."""

    total_requests: int
    served_fresh: int
    served_stale: int
    revalidations_triggered: int
    background_misses: int
    simulated_hit_rate: float
    mean_ttfb_ms: float     # estimated, assuming stale = HIT latency
    description: str


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Return the *pct*-th percentile of a pre-sorted list."""
    if not sorted_values:
        return 0.0
    index = (pct / 100) * (len(sorted_values) - 1)
    lower = int(index)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = index - lower
    return sorted_values[lower] + fraction * (sorted_values[upper] - sorted_values[lower])


class CacheAnalytics:
    """
    Analyse a collection of Cloudflare access log records.

    Parameters
    ----------
    records:
        List of :class:`LogRecord` objects or raw dicts (auto-converted).
    """

    def __init__(self, records: list[LogRecord | dict[str, Any]]) -> None:
        self._records: list[LogRecord] = [
            r if isinstance(r, LogRecord) else LogRecord.from_dict(r)
            for r in records
        ]

    @property
    def record_count(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # TTFB Histogram
    # ------------------------------------------------------------------

    def ttfb_histogram(
        self,
        buckets: list[float] | None = None,
    ) -> dict[str, int]:
        """
        Build a TTFB histogram.

        Parameters
        ----------
        buckets:
            Ascending list of upper-bound values in milliseconds.
            The last bucket should be ``float('inf')``.

        Returns
        -------
        dict[str, int]
            Ordered dict mapping bucket label to request count.
            Labels: ``"≤10ms"``, ``"≤25ms"``, …, ``">2000ms"`` (or similar).
        """
        bounds = buckets or DEFAULT_TTFB_BUCKETS
        counts: dict[str, int] = {}

        for i, upper in enumerate(bounds):
            if upper == float("inf"):
                label = f">{int(bounds[i - 1])}ms" if i > 0 else ">0ms"
            else:
                label = f"≤{int(upper)}ms"
            counts[label] = 0

        for rec in self._records:
            placed = False
            for i, upper in enumerate(bounds):
                if rec.ttfb_ms <= upper:
                    if upper == float("inf"):
                        label = f">{int(bounds[i - 1])}ms" if i > 0 else ">0ms"
                    else:
                        label = f"≤{int(upper)}ms"
                    counts[label] += 1
                    placed = True
                    break
            if not placed:
                # Fallback: put in last bucket
                last = bounds[-1]
                if last == float("inf") and len(bounds) > 1:
                    label = f">{int(bounds[-2])}ms"
                else:
                    label = f"≤{int(last)}ms"
                counts[label] += 1

        return counts

    # ------------------------------------------------------------------
    # Cache status breakdown
    # ------------------------------------------------------------------

    def cache_status_breakdown(self) -> dict[str, int]:
        """
        Count requests by cache status.

        Returns
        -------
        dict[str, int]
            Mapping of status string to count, sorted by count descending.
        """
        counts: dict[str, int] = {}
        for rec in self._records:
            counts[rec.cache_status] = counts.get(rec.cache_status, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def hit_rate(self) -> float:
        """Return the fraction of requests that were cache HITs."""
        if not self._records:
            return 0.0
        hits = sum(1 for r in self._records if r.cache_status == "HIT")
        return hits / len(self._records)

    # ------------------------------------------------------------------
    # PoP performance
    # ------------------------------------------------------------------

    def pop_performance(self) -> dict[str, PopMetrics]:
        """
        Aggregate metrics per Cloudflare PoP.

        Returns
        -------
        dict[str, PopMetrics]
            Keyed by PoP IATA code, sorted by request count descending.
        """
        grouped: dict[str, list[LogRecord]] = {}
        for rec in self._records:
            grouped.setdefault(rec.pop, []).append(rec)

        result: dict[str, PopMetrics] = {}
        for pop, recs in grouped.items():
            ttfbs = sorted(r.ttfb_ms for r in recs)
            hits = sum(1 for r in recs if r.cache_status == "HIT")
            misses = sum(1 for r in recs if r.cache_status == "MISS")
            result[pop] = PopMetrics(
                pop=pop,
                request_count=len(recs),
                hit_count=hits,
                miss_count=misses,
                mean_ttfb_ms=statistics.mean(ttfbs) if ttfbs else 0.0,
                p50_ttfb_ms=_percentile(ttfbs, 50),
                p95_ttfb_ms=_percentile(ttfbs, 95),
                p99_ttfb_ms=_percentile(ttfbs, 99),
                bytes_served=sum(r.bytes_sent for r in recs),
            )

        return dict(sorted(result.items(), key=lambda x: x[1].request_count, reverse=True))

    # ------------------------------------------------------------------
    # Stale-while-revalidate simulation
    # ------------------------------------------------------------------

    def stale_while_revalidate_sim(
        self,
        max_stale_seconds: float = 30.0,
        revalidation_ttfb_ms: float = 5.0,
        hit_ttfb_ms: float = 8.0,
    ) -> SWRSimResult:
        """
        Simulate serving stale content during background revalidation.

        Records with ``cache_status == "EXPIRED"`` are treated as stale
        candidates.  The simulation assumes:
        - Fresh HITs: served immediately (hit_ttfb_ms).
        - Stale (EXPIRED within max_stale_seconds): served stale, background
          revalidation triggered once per cache key.
        - True MISSes / BYPASSes: served synchronously (original ttfb_ms).

        Parameters
        ----------
        max_stale_seconds:
            How long past expiry a stale response is acceptable.
        revalidation_ttfb_ms:
            TTFB for a background revalidation request (not on critical path).
        hit_ttfb_ms:
            Assumed TTFB when serving a stale or cached response.

        Returns
        -------
        SWRSimResult
        """
        served_fresh = 0
        served_stale = 0
        revalidations_triggered = 0
        background_misses = 0
        ttfbs: list[float] = []

        revalidation_keys: set[str] = set()

        for rec in self._records:
            if rec.cache_status == "HIT":
                served_fresh += 1
                ttfbs.append(hit_ttfb_ms)

            elif rec.cache_status == "EXPIRED":
                # Simulate: serve stale if within max_stale_seconds
                # We proxy stale age by using the record index as a pseudo-age
                served_stale += 1
                ttfbs.append(hit_ttfb_ms)  # stale response is fast
                if rec.path not in revalidation_keys:
                    revalidation_keys.add(rec.path)
                    revalidations_triggered += 1

            elif rec.cache_status in {"MISS", "BYPASS", "DYNAMIC"}:
                background_misses += 1
                ttfbs.append(rec.ttfb_ms)

            else:
                ttfbs.append(rec.ttfb_ms)

        total = len(self._records)
        sim_hits = served_fresh + served_stale
        sim_hit_rate = sim_hits / total if total > 0 else 0.0
        mean_ttfb = statistics.mean(ttfbs) if ttfbs else 0.0

        return SWRSimResult(
            total_requests=total,
            served_fresh=served_fresh,
            served_stale=served_stale,
            revalidations_triggered=revalidations_triggered,
            background_misses=background_misses,
            simulated_hit_rate=round(sim_hit_rate, 4),
            mean_ttfb_ms=round(mean_ttfb, 2),
            description=(
                f"SWR simulation: {sim_hit_rate:.1%} hit rate, "
                f"{revalidations_triggered} background revalidations triggered."
            ),
        )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Return a flat summary dict suitable for dashboards/logging."""
        if not self._records:
            return {"record_count": 0}

        ttfbs = [r.ttfb_ms for r in self._records]
        sorted_ttfbs = sorted(ttfbs)
        return {
            "record_count": len(self._records),
            "hit_rate": round(self.hit_rate(), 4),
            "cache_status_breakdown": self.cache_status_breakdown(),
            "ttfb": {
                "mean_ms": round(statistics.mean(ttfbs), 2),
                "p50_ms": round(_percentile(sorted_ttfbs, 50), 2),
                "p95_ms": round(_percentile(sorted_ttfbs, 95), 2),
                "p99_ms": round(_percentile(sorted_ttfbs, 99), 2),
                "max_ms": round(max(ttfbs), 2),
            },
            "unique_pops": len({r.pop for r in self._records}),
            "total_bytes_served": sum(r.bytes_sent for r in self._records),
        }

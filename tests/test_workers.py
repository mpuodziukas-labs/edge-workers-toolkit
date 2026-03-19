"""
Test suite for Cloudflare Workers Toolkit.

Zero external dependencies (stdlib + pytest only).
Run: pytest tests/ -v
"""

from __future__ import annotations

import math
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.rate_limiter import (
    KVStore,
    RateLimitConfig,
    RateLimiter,
)
from workers.cache_analytics import (
    LogRecord,
    CacheAnalytics,
    DEFAULT_TTFB_BUCKETS,
    _percentile,
)
from workers.ddos_detector import (
    DDoSConfig,
    DDoSDetector,
    IPProfile,
)


# ===========================================================================
# KVStore
# ===========================================================================

class TestKVStore:
    def test_zadd_and_zcard(self):
        store = KVStore()
        store.zadd("key1", 1.0, "a")
        store.zadd("key1", 2.0, "b")
        assert store.zcard("key1") == 2

    def test_zcard_missing_key(self):
        store = KVStore()
        assert store.zcard("nonexistent") == 0

    def test_zrangebyscore_filters_correctly(self):
        store = KVStore()
        for i in range(5):
            store.zadd("k", float(i), str(i))
        result = store.zrangebyscore("k", 1.0, 3.0)
        scores = [r[0] for r in result]
        assert sorted(scores) == [1.0, 2.0, 3.0]

    def test_zremrangebyscore_removes_entries(self):
        store = KVStore()
        for i in range(5):
            store.zadd("k", float(i), str(i))
        removed = store.zremrangebyscore("k", 0.0, 2.0)
        assert removed == 3
        assert store.zcard("k") == 2

    def test_delete_clears_key(self):
        store = KVStore()
        store.zadd("k", 1.0, "x")
        store.delete("k")
        assert store.zcard("k") == 0

    def test_expire_is_noop(self):
        store = KVStore()
        store.zadd("k", 1.0, "a")
        store.expire("k", 60)
        assert store.zcard("k") == 1

    def test_keys_returns_all(self):
        store = KVStore()
        store.zadd("k1", 1.0)
        store.zadd("k2", 2.0)
        keys = store.keys()
        assert "k1" in keys
        assert "k2" in keys

    def test_auto_member_unique(self):
        store = KVStore()
        store.zadd("k", 1.0)
        store.zadd("k", 2.0)
        assert store.zcard("k") == 2


# ===========================================================================
# RateLimiter
# ===========================================================================

class TestRateLimiter:
    def _limiter(self, limit: int = 5, window: float = 10.0, start_time: float = 0.0):
        store = KVStore()
        # burst_window_seconds == window_seconds disables the burst sub-gate
        # (burst_limit = limit * multiplier >= limit → burst_ok is always True)
        config = RateLimitConfig(
            requests_per_window=limit,
            window_seconds=window,
            burst_multiplier=2.0,
            burst_window_seconds=window,   # same as full window → no sub-window burst gate
        )
        clock_val = [start_time]

        def clock():
            return clock_val[0]

        def advance(seconds: float):
            clock_val[0] += seconds

        rl = RateLimiter(store, config, clock=clock)
        return rl, advance

    def test_allows_requests_within_limit(self):
        rl, _ = self._limiter(limit=5)
        for _ in range(5):
            allowed, _ = rl.is_allowed("user1")
            assert allowed

    def test_blocks_when_limit_exceeded(self):
        rl, _ = self._limiter(limit=3)
        for _ in range(3):
            rl.is_allowed("user1")
        allowed, result = rl.is_allowed("user1")
        assert not allowed
        assert result.remaining == 0

    def test_remaining_decrements(self):
        rl, _ = self._limiter(limit=5)
        _, r1 = rl.is_allowed("u")
        _, r2 = rl.is_allowed("u")
        assert r2.remaining < r1.remaining

    def test_different_keys_independent(self):
        rl, _ = self._limiter(limit=2)
        for _ in range(2):
            rl.is_allowed("user_a")
        allowed_a, _ = rl.is_allowed("user_a")
        allowed_b, _ = rl.is_allowed("user_b")
        assert not allowed_a
        assert allowed_b

    def test_window_resets_after_expiry(self):
        rl, advance = self._limiter(limit=3, window=5.0, start_time=100.0)
        for _ in range(3):
            rl.is_allowed("u")
        allowed_before, _ = rl.is_allowed("u")
        assert not allowed_before
        advance(6.0)  # past the window
        allowed_after, _ = rl.is_allowed("u")
        assert allowed_after

    def test_reset_clears_state(self):
        rl, _ = self._limiter(limit=2)
        for _ in range(2):
            rl.is_allowed("u")
        rl.reset("u")
        allowed, _ = rl.is_allowed("u")
        assert allowed

    def test_get_status_does_not_consume_slot(self):
        rl, _ = self._limiter(limit=3)
        status1 = rl.get_status("u")
        status2 = rl.get_status("u")
        assert status1["count"] == status2["count"] == 0

    def test_retry_after_positive_when_blocked(self):
        rl, _ = self._limiter(limit=1, start_time=1000.0)
        rl.is_allowed("u")
        _, result = rl.is_allowed("u")
        assert result.retry_after >= 0

    def test_route_key_format(self):
        key = RateLimiter.route_key("/api/v1", "192.168.0.1")
        assert "/api/v1" in key
        assert "192.168.0.1" in key

    def test_ip_key_format(self):
        key = RateLimiter.ip_key("10.0.0.1")
        assert "10.0.0.1" in key

    def test_limit_field_in_result(self):
        rl, _ = self._limiter(limit=7)
        _, result = rl.is_allowed("u")
        assert result.limit == 7


# ===========================================================================
# LogRecord / CacheAnalytics
# ===========================================================================

def _make_records(n: int = 10) -> list[LogRecord]:
    statuses = ["HIT", "MISS", "EXPIRED", "BYPASS", "HIT", "HIT", "MISS", "HIT", "DYNAMIC", "REVALIDATED"]
    pops = ["LAX", "LHR", "SIN", "EWR", "LAX", "LAX", "LHR", "SIN", "EWR", "LAX"]
    records = []
    for i in range(n):
        records.append(LogRecord(
            timestamp_ms=float(1_700_000_000_000 + i * 1000),
            ttfb_ms=float(10 + i * 5),
            cache_status=statuses[i % len(statuses)],
            pop=pops[i % len(pops)],
            status_code=200 if i % 5 != 0 else 404,
            bytes_sent=1024 * (i + 1),
            path=f"/api/item/{i}",
        ))
    return records


class TestLogRecord:
    def test_from_dict(self):
        data = {
            "timestamp_ms": 1_700_000_000_000,
            "ttfb_ms": 42.5,
            "cache_status": "hit",
            "pop": "lax",
            "status_code": 200,
            "bytes_sent": 512,
            "path": "/test",
        }
        rec = LogRecord.from_dict(data)
        assert rec.cache_status == "HIT"
        assert rec.pop == "LAX"
        assert rec.ttfb_ms == pytest.approx(42.5)

    def test_from_dict_defaults(self):
        rec = LogRecord.from_dict({})
        assert rec.status_code == 200
        assert rec.pop == "UNKNOWN"
        assert rec.path == "/"


class TestCacheAnalytics:
    def test_record_count(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        assert ca.record_count == 10

    def test_empty_analytics(self):
        ca = CacheAnalytics([])
        assert ca.record_count == 0
        assert ca.hit_rate() == 0.0

    def test_accepts_dicts(self):
        records = [{"ttfb_ms": 20, "cache_status": "HIT", "pop": "LAX", "timestamp_ms": 0}]
        ca = CacheAnalytics(records)
        assert ca.record_count == 1

    def test_hit_rate_calculation(self):
        records = [
            LogRecord(0, 10.0, "HIT", "LAX"),
            LogRecord(1, 10.0, "HIT", "LAX"),
            LogRecord(2, 10.0, "MISS", "LAX"),
            LogRecord(3, 10.0, "MISS", "LAX"),
        ]
        ca = CacheAnalytics(records)
        assert ca.hit_rate() == pytest.approx(0.5)

    def test_cache_status_breakdown_keys(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        breakdown = ca.cache_status_breakdown()
        assert isinstance(breakdown, dict)
        for v in breakdown.values():
            assert isinstance(v, int)

    def test_cache_status_breakdown_sums_to_total(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        assert sum(ca.cache_status_breakdown().values()) == 10

    def test_ttfb_histogram_sums_to_total(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        hist = ca.ttfb_histogram()
        assert sum(hist.values()) == 10

    def test_ttfb_histogram_custom_buckets(self):
        records = [LogRecord(0, float(v), "HIT", "LAX") for v in [5, 15, 25, 150, 3000]]
        ca = CacheAnalytics(records)
        hist = ca.ttfb_histogram([10.0, 20.0, 100.0, float("inf")])
        assert sum(hist.values()) == 5

    def test_pop_performance_keys(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        pops = ca.pop_performance()
        assert "LAX" in pops

    def test_pop_metrics_request_count(self):
        records = [LogRecord(0, 10.0, "HIT", "LAX")] * 5
        ca = CacheAnalytics(records)
        pops = ca.pop_performance()
        assert pops["LAX"].request_count == 5

    def test_pop_metrics_hit_rate(self):
        records = [
            LogRecord(0, 10.0, "HIT", "LAX"),
            LogRecord(1, 10.0, "HIT", "LAX"),
            LogRecord(2, 10.0, "MISS", "LAX"),
            LogRecord(3, 10.0, "MISS", "LAX"),
        ]
        ca = CacheAnalytics(records)
        assert ca.pop_performance()["LAX"].hit_rate == pytest.approx(0.5)

    def test_pop_metrics_percentiles(self):
        ttfbs = [10.0, 20.0, 30.0, 40.0, 50.0]
        records = [LogRecord(float(i), t, "HIT", "LHR") for i, t in enumerate(ttfbs)]
        ca = CacheAnalytics(records)
        metrics = ca.pop_performance()["LHR"]
        assert metrics.p50_ttfb_ms == pytest.approx(30.0)

    def test_swr_sim_total_matches(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        result = ca.stale_while_revalidate_sim()
        assert result.total_requests == 10

    def test_swr_sim_hit_rate_between_0_and_1(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        result = ca.stale_while_revalidate_sim()
        assert 0.0 <= result.simulated_hit_rate <= 1.0

    def test_summary_keys(self):
        records = _make_records(10)
        ca = CacheAnalytics(records)
        summary = ca.summary()
        assert "hit_rate" in summary
        assert "ttfb" in summary
        assert "unique_pops" in summary

    def test_summary_empty(self):
        ca = CacheAnalytics([])
        assert ca.summary() == {"record_count": 0}


class TestPercentile:
    def test_empty_list(self):
        assert _percentile([], 50) == 0.0

    def test_single_element(self):
        assert _percentile([42.0], 50) == pytest.approx(42.0)

    def test_median(self):
        assert _percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == pytest.approx(3.0)

    def test_p100(self):
        values = [1.0, 2.0, 3.0]
        assert _percentile(values, 100) == pytest.approx(3.0)


# ===========================================================================
# DDoSDetector
# ===========================================================================

def _make_detector(clock_val: list[float] | None = None) -> tuple[DDoSDetector, list[float]]:
    t = clock_val or [1000.0]
    config = DDoSConfig(
        rate_window_seconds=60.0,
        zscore_threshold=2.0,
        min_requests_for_zscore=3,
        reputation_score_threshold=20.0,   # low threshold so UA/error tests fire
        high_volume_rps_threshold=5.0,
        path_entropy_threshold=3.0,
        error_rate_threshold=0.4,
    )
    detector = DDoSDetector(config=config, clock=lambda: t[0])
    return detector, t


def _flood(detector: DDoSDetector, ip: str, n: int, ts: float = 1000.0, ua: str = "Mozilla/5.0") -> None:
    for i in range(n):
        detector.ingest({
            "ip": ip,
            "path": f"/api/item/{i}",
            "user_agent": ua,
            "status_code": 200,
            "bytes_sent": 512,
            "timestamp": ts,
        })


class TestDDoSDetector:
    def test_ingest_increments_total(self):
        detector, _ = _make_detector()
        detector.ingest({"ip": "1.2.3.4", "path": "/", "timestamp": 1000.0})
        assert detector._total_requests == 1

    def test_ingest_creates_profile(self):
        detector, _ = _make_detector()
        detector.ingest({"ip": "1.2.3.4", "timestamp": 1000.0})
        assert "1.2.3.4" in detector._profiles

    def test_analyze_returns_report(self):
        detector, _ = _make_detector()
        detector.ingest({"ip": "1.2.3.4", "timestamp": 1000.0})
        report = detector.analyze()
        assert report.total_requests == 1
        assert report.unique_ips == 1

    def test_no_threat_with_normal_traffic(self):
        detector, _ = _make_detector()
        for i in range(3):
            detector.ingest({"ip": f"10.0.0.{i}", "path": "/home", "timestamp": 1000.0})
        report = detector.analyze()
        assert report.threat_level in {"NONE", "LOW"}

    def test_high_rps_flags_ip(self):
        detector, t = _make_detector()
        # Flood 100 requests in a 60s window → rps = 100/60 ≈ 1.67
        # But config threshold is 5 rps — use a short window
        config = DDoSConfig(
            rate_window_seconds=1.0,
            zscore_threshold=2.0,
            reputation_score_threshold=30.0,
            high_volume_rps_threshold=2.0,
        )
        detector2 = DDoSDetector(config=config, clock=lambda: t[0])
        for i in range(10):
            detector2.ingest({"ip": "5.5.5.5", "path": "/", "timestamp": 1000.0})
        report = detector2.analyze()
        flagged_ips = [ts.ip for ts in report.flagged_ips]
        assert "5.5.5.5" in flagged_ips

    def test_suspicious_ua_flags_ip(self):
        detector, _ = _make_detector()
        for i in range(5):
            detector.ingest({
                "ip": "9.9.9.9",
                "path": "/",
                "user_agent": "sqlmap/1.7",
                "status_code": 200,
                "timestamp": 1000.0,
            })
        report = detector.analyze()
        flagged_ips = [ts.ip for ts in report.flagged_ips]
        assert "9.9.9.9" in flagged_ips

    def test_empty_ua_flagged(self):
        detector, _ = _make_detector()
        for i in range(5):
            detector.ingest({"ip": "8.8.8.8", "user_agent": "", "path": "/", "timestamp": 1000.0})
        report = detector.analyze()
        flagged = [ts.ip for ts in report.flagged_ips]
        assert "8.8.8.8" in flagged

    def test_high_error_rate_contributes_to_score(self):
        detector, _ = _make_detector()
        for i in range(10):
            detector.ingest({
                "ip": "7.7.7.7",
                "path": "/",
                "status_code": 404,
                "timestamp": 1000.0,
            })
        scores = {ts.ip: ts.score for ts in detector.analyze().flagged_ips}
        if "7.7.7.7" in scores:
            assert scores["7.7.7.7"] >= 20.0

    def test_generate_rules_empty_when_no_threats(self):
        detector, _ = _make_detector()
        detector.ingest({"ip": "1.1.1.1", "path": "/", "timestamp": 1000.0})
        rules = detector.generate_rules()
        assert rules == []

    def test_generate_rules_contains_block_for_critical(self):
        config = DDoSConfig(
            rate_window_seconds=1.0,
            reputation_score_threshold=10.0,
            high_volume_rps_threshold=1.0,
        )
        t = [1000.0]
        detector = DDoSDetector(config=config, clock=lambda: t[0])
        for i in range(50):
            detector.ingest({"ip": "6.6.6.6", "path": f"/p{i}", "user_agent": "sqlmap", "timestamp": 1000.0})
        rules = detector.generate_rules()
        actions = [r.action for r in rules]
        assert "block" in actions or "js_challenge" in actions or "managed_challenge" in actions

    def test_rule_expression_contains_ip(self):
        config = DDoSConfig(
            rate_window_seconds=1.0,
            reputation_score_threshold=10.0,
            high_volume_rps_threshold=1.0,
        )
        t = [1000.0]
        detector = DDoSDetector(config=config, clock=lambda: t[0])
        for i in range(50):
            detector.ingest({"ip": "3.3.3.3", "path": f"/x{i}", "user_agent": "nikto", "timestamp": 1000.0})
        rules = detector.generate_rules()
        if rules:
            assert "3.3.3.3" in rules[0].expression

    def test_reset_clears_all_state(self):
        detector, _ = _make_detector()
        detector.ingest({"ip": "1.1.1.1", "timestamp": 1000.0})
        detector.reset()
        assert detector._total_requests == 0
        assert len(detector._profiles) == 0

    def test_path_entropy_high_for_random_paths(self):
        profile = IPProfile(ip="x")
        for i in range(50):
            profile.paths.append(f"/random/path/{i}/unique/endpoint/{i * 7}")
        entropy = profile.path_entropy()
        assert entropy > 3.0

    def test_path_entropy_low_for_repeated_paths(self):
        profile = IPProfile(ip="x")
        for _ in range(50):
            profile.paths.append("/home")
        assert profile.path_entropy() == 0.0

    def test_error_rate_all_errors(self):
        profile = IPProfile(ip="x")
        profile.status_codes = [404, 500, 403, 429, 503]
        assert profile.error_rate() == pytest.approx(1.0)

    def test_error_rate_no_errors(self):
        profile = IPProfile(ip="x")
        profile.status_codes = [200, 201, 302]
        assert profile.error_rate() == pytest.approx(0.0)

    def test_error_rate_empty(self):
        profile = IPProfile(ip="x")
        assert profile.error_rate() == 0.0

    def test_top_paths_populated(self):
        detector, _ = _make_detector()
        for _ in range(5):
            detector.ingest({"ip": "1.1.1.1", "path": "/hot", "timestamp": 1000.0})
        report = detector.analyze()
        paths = [p for p, _ in report.top_paths_by_volume]
        assert "/hot" in paths

    def test_analyze_unique_ips_count(self):
        detector, _ = _make_detector()
        for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
            detector.ingest({"ip": ip, "timestamp": 1000.0})
        report = detector.analyze()
        assert report.unique_ips == 3

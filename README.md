# cloudflare-workers-toolkit

Python toolkit for Cloudflare Workers analysis: KV-backed rate limiting, cache hit-rate analytics, and L7 DDoS detection with Cloudflare Rules Language output.

Built to demonstrate Senior SRE/SWE capabilities at Cloudflare scale:
- Sliding-window rate limiter with burst allowance (Redis-compatible in-process KV)
- TTFB histograms, per-PoP metrics, stale-while-revalidate simulation
- Z-score anomaly detection, IP reputation scoring, path entropy analysis
- Generates valid **Cloudflare Rules Language** expressions for WAF rules
- 60 unit tests — zero external dependencies beyond `pytest`

---

## Modules

### `workers/rate_limiter.py`

Sliding-window rate limiter backed by `KVStore` (Redis-compatible in-process sorted sets):

```python
from workers.rate_limiter import KVStore, RateLimitConfig, RateLimiter

store = KVStore()
config = RateLimitConfig(
    requests_per_window=100,
    window_seconds=60.0,
    burst_multiplier=1.5,
    burst_window_seconds=5.0,
)
limiter = RateLimiter(store, config)

# Per-IP rate limiting
allowed, result = limiter.is_allowed(RateLimiter.ip_key("203.0.113.42"))
if not allowed:
    print(f"Rate limited. Retry after {result.retry_after:.1f}s")

# Per-route rate limiting
allowed, result = limiter.is_allowed(RateLimiter.route_key("/api/v1/chat", "user-abc"))
print(f"Remaining: {result.remaining}/{result.limit}")
```

**Algorithm**: sliding-window log with a burst sub-window gate. The burst gate prevents instantaneous floods while allowing steady traffic up to the full limit.

### `workers/cache_analytics.py`

Analyse Cloudflare Logpush records:

```python
from workers.cache_analytics import LogRecord, CacheAnalytics

records = [LogRecord.from_dict(entry) for entry in logpush_batch]
ca = CacheAnalytics(records)

print(ca.summary())
# {'record_count': 50000, 'hit_rate': 0.847, 'ttfb': {'mean_ms': 12.4, 'p95_ms': 48.2, ...}, ...}

# TTFB histogram
print(ca.ttfb_histogram())
# {'≤10ms': 21034, '≤25ms': 18442, '≤50ms': 7123, ...}

# Per-PoP breakdown
for pop, metrics in ca.pop_performance().items():
    print(f"{pop}: {metrics.hit_rate:.0%} hit rate, p95={metrics.p95_ttfb_ms:.0f}ms")

# Stale-while-revalidate simulation
swr = ca.stale_while_revalidate_sim(max_stale_seconds=30.0)
print(swr.description)
```

### `workers/ddos_detector.py`

Streaming L7 DDoS detector with Cloudflare Rules Language output:

```python
from workers.ddos_detector import DDoSConfig, DDoSDetector

detector = DDoSDetector(config=DDoSConfig(
    rate_window_seconds=60.0,
    zscore_threshold=3.0,
    high_volume_rps_threshold=50.0,
    reputation_score_threshold=70.0,
))

for record in access_log_stream:
    detector.ingest(record)  # keys: ip, path, user_agent, status_code, bytes_sent, timestamp

report = detector.analyze()
print(f"Threat level: {report.threat_level}")  # NONE / LOW / MEDIUM / HIGH / CRITICAL

# Generate Cloudflare WAF rules
for rule in detector.generate_rules():
    print(f"# {rule.description}")
    print(f"Action: {rule.action}")
    print(f"Expression: {rule.expression}")
    # e.g.: (ip.src in {"1.2.3.4" "5.6.7.8"})
```

**Detection methods**:
1. High absolute RPS (configurable threshold)
2. Z-score anomaly vs. population baseline
3. High 4xx/5xx error rate
4. Path entropy (Shannon entropy — detects scanners/fuzzers)
5. Suspicious user-agent patterns (sqlmap, nikto, nmap, masscan, zgrab, nuclei, empty UA, etc.)

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Expected: **60 passed**.

---

## KVStore — Redis Compatibility

`KVStore` implements the sorted-set subset used by the rate limiter:

| KVStore method | Redis equivalent |
|---|---|
| `zadd(key, score, member)` | `ZADD key score member` |
| `zrangebyscore(key, min, max)` | `ZRANGEBYSCORE key min max WITHSCORES` |
| `zremrangebyscore(key, min, max)` | `ZREMRANGEBYSCORE key min max` |
| `zcard(key)` | `ZCARD key` |
| `delete(key)` | `DEL key` |
| `expire(key, ttl)` | `EXPIRE key ttl` (no-op in process) |

Swap `KVStore` for a Redis client adapter to run on actual Cloudflare KV or Upstash Redis.

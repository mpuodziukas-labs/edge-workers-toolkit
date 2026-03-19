"""
Cloudflare DDoS Detector.

Detects Layer-7 DDoS patterns from Workers access log streams and
generates Cloudflare Rules Language mitigation expressions.

Detection methods
-----------------
1. Request-rate anomaly (z-score against rolling baseline)
2. IP reputation scoring (request frequency + error rate + path diversity)
3. L7 pattern matching:
   - Suspicious user-agent strings (known bots, scanners, empties)
   - Path entropy (unusually random paths = scanner/fuzzer)
   - Consistent high-error rate from a single IP
4. Mitigation rule generator → Cloudflare Rules Language output

Public API
----------
DDoSDetector(config)
  .ingest(record)                  → None
  .analyze()                       → AnalysisReport
  .generate_rules()                → list[MitigationRule]
  .reset()                         → None
DDoSConfig                         — configuration dataclass
AnalysisReport                     — dataclass with per-IP threat scores
MitigationRule                     — dataclass with CF Rules Language expression
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DDoSConfig:
    """
    DDoS detector configuration.

    Attributes
    ----------
    rate_window_seconds:
        Rolling window for request-rate baseline computation.
    zscore_threshold:
        Z-score above which an IP's request rate is considered anomalous.
    min_requests_for_zscore:
        Minimum number of requests before z-score analysis fires.
    reputation_score_threshold:
        IP reputation score (0–100) above which an IP is flagged.
    path_entropy_threshold:
        Shannon entropy of path distribution above which fuzzing is suspected.
    suspicious_ua_patterns:
        Compiled regexes to match known malicious user-agents.
    error_rate_threshold:
        Fraction of 4xx/5xx responses above which an IP is flagged.
    high_volume_rps_threshold:
        Absolute requests-per-second above which an IP is always flagged.
    """

    rate_window_seconds: float = 60.0
    zscore_threshold: float = 3.0
    min_requests_for_zscore: int = 10
    reputation_score_threshold: float = 70.0
    path_entropy_threshold: float = 4.0
    error_rate_threshold: float = 0.5
    high_volume_rps_threshold: float = 50.0

    # UA patterns (pre-compiled strings; compiled at init time)
    suspicious_ua_strings: tuple[str, ...] = (
        r"(?i)sqlmap",
        r"(?i)nikto",
        r"(?i)nmap",
        r"(?i)masscan",
        r"(?i)zgrab",
        r"(?i)nuclei",
        r"(?i)python-httpx",
        r"(?i)python-requests",
        r"(?i)go-http-client",
        r"(?i)curl/[0-9]",
        r"(?i)wget/[0-9]",
        r"^$",          # empty UA
        r"^-$",         # dash UA
    )


# ---------------------------------------------------------------------------
# Per-IP state
# ---------------------------------------------------------------------------

@dataclass
class IPProfile:
    """Accumulated statistics for a single IP address."""

    ip: str
    request_timestamps: list[float] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    user_agents: set[str] = field(default_factory=set)
    status_codes: list[int] = field(default_factory=list)
    bytes_received: int = 0

    def request_count(self) -> int:
        return len(self.request_timestamps)

    def rps(self, window: float, now: float | None = None) -> float:
        """Requests per second over the last *window* seconds."""
        if now is None:
            now = time.time()
        recent = [t for t in self.request_timestamps if t >= now - window]
        return len(recent) / window if window > 0 else 0.0

    def error_rate(self) -> float:
        if not self.status_codes:
            return 0.0
        errors = sum(1 for s in self.status_codes if s >= 400)
        return errors / len(self.status_codes)

    def path_entropy(self) -> float:
        """Shannon entropy of the path distribution (higher = more random = suspicious)."""
        if not self.paths:
            return 0.0
        counts: dict[str, int] = {}
        for p in self.paths:
            counts[p] = counts.get(p, 0) + 1
        total = len(self.paths)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def has_suspicious_ua(self, patterns: list[re.Pattern[str]]) -> bool:
        for ua in self.user_agents:
            for pattern in patterns:
                if pattern.search(ua):
                    return True
        return False


# ---------------------------------------------------------------------------
# Threat scoring
# ---------------------------------------------------------------------------

@dataclass
class ThreatScore:
    """Per-IP threat assessment."""

    ip: str
    score: float                  # 0–100
    reasons: list[str]
    flagged: bool
    rps: float
    error_rate: float
    path_entropy: float
    request_count: int


# ---------------------------------------------------------------------------
# Mitigation rule
# ---------------------------------------------------------------------------

@dataclass
class MitigationRule:
    """
    A Cloudflare Rules Language mitigation rule.

    The ``expression`` field contains a valid Cloudflare Rules Language
    expression string that can be pasted directly into a Custom Rule.
    """

    rule_id: str
    description: str
    expression: str
    action: str        # "block", "challenge", "js_challenge", "managed_challenge"
    priority: int      # lower = evaluated first
    ip_addresses: list[str]


# ---------------------------------------------------------------------------
# Analysis report
# ---------------------------------------------------------------------------

@dataclass
class AnalysisReport:
    """Full analysis output from :class:`DDoSDetector`."""

    total_requests: int
    unique_ips: int
    flagged_ips: list[ThreatScore]
    threat_level: str           # "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    top_paths_by_volume: list[tuple[str, int]]
    top_ips_by_rps: list[tuple[str, float]]
    window_seconds: float


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class DDoSDetector:
    """
    Streaming L7 DDoS detector.

    Ingest log records via :meth:`ingest`, then call :meth:`analyze` at any
    time to get current threat assessments.

    Parameters
    ----------
    config:
        :class:`DDoSConfig` instance.
    clock:
        Callable returning current Unix timestamp.  Override in tests.
    """

    def __init__(
        self,
        config: DDoSConfig | None = None,
        clock: Any = None,
    ) -> None:
        self._config = config or DDoSConfig()
        self._clock: Any = clock or time.time
        self._profiles: dict[str, IPProfile] = {}
        self._global_paths: list[str] = []
        self._total_requests: int = 0
        self._ua_patterns: list[re.Pattern[str]] = [
            re.compile(p) for p in self._config.suspicious_ua_strings
        ]

    def ingest(self, record: dict[str, Any]) -> None:
        """
        Add a single log record to the detector state.

        Expected keys: ``ip``, ``path``, ``user_agent``, ``status_code``,
        ``bytes_sent``, ``timestamp`` (optional, defaults to now).
        """
        ip = str(record.get("ip", "0.0.0.0"))
        path = str(record.get("path", "/"))
        ua = str(record.get("user_agent", ""))
        status = int(record.get("status_code", 200))
        size = int(record.get("bytes_sent", 0))
        ts = float(record.get("timestamp", self._clock()))

        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip=ip)

        profile = self._profiles[ip]
        profile.request_timestamps.append(ts)
        profile.paths.append(path)
        profile.user_agents.add(ua)
        profile.status_codes.append(status)
        profile.bytes_received += size

        self._global_paths.append(path)
        self._total_requests += 1

    def _compute_zscore_flags(self) -> dict[str, float]:
        """Compute z-score of each IP's request count vs the population."""
        cfg = self._config
        counts = {
            ip: profile.request_count()
            for ip, profile in self._profiles.items()
        }
        if len(counts) < 2:
            return {}
        values = list(counts.values())
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std = math.sqrt(variance) if variance > 0 else 0.0
        if std == 0:
            return {}
        return {
            ip: (count - mean) / std
            for ip, count in counts.items()
        }

    def _score_ip(
        self,
        profile: IPProfile,
        zscore: float | None,
        now: float | None = None,
    ) -> ThreatScore:
        cfg = self._config
        score = 0.0
        reasons: list[str] = []

        rps = profile.rps(cfg.rate_window_seconds, now=now)
        error_rate = profile.error_rate()
        path_entropy = profile.path_entropy()

        # 1. High absolute RPS
        if rps >= cfg.high_volume_rps_threshold:
            score += 40.0
            reasons.append(f"High RPS: {rps:.1f} req/s (threshold: {cfg.high_volume_rps_threshold})")

        # 2. Z-score anomaly
        if zscore is not None and abs(zscore) >= cfg.zscore_threshold:
            z_contribution = min(30.0, abs(zscore) * 5)
            score += z_contribution
            reasons.append(f"Rate z-score: {zscore:.2f} (threshold: ±{cfg.zscore_threshold})")

        # 3. High error rate
        if error_rate >= cfg.error_rate_threshold and profile.request_count() >= 5:
            score += 20.0
            reasons.append(
                f"High error rate: {error_rate:.0%} (threshold: {cfg.error_rate_threshold:.0%})"
            )

        # 4. Path entropy (scanner/fuzzer pattern)
        if path_entropy >= cfg.path_entropy_threshold:
            score += 15.0
            reasons.append(
                f"High path entropy: {path_entropy:.2f} bits (threshold: {cfg.path_entropy_threshold})"
            )

        # 5. Suspicious user-agent
        if profile.has_suspicious_ua(self._ua_patterns):
            score += 25.0
            suspicious = [
                ua for ua in profile.user_agents
                if any(p.search(ua) for p in self._ua_patterns)
            ]
            reasons.append(f"Suspicious UA: {suspicious[:3]}")

        score = min(100.0, score)

        return ThreatScore(
            ip=profile.ip,
            score=score,
            reasons=reasons,
            flagged=score >= cfg.reputation_score_threshold,
            rps=rps,
            error_rate=error_rate,
            path_entropy=path_entropy,
            request_count=profile.request_count(),
        )

    def analyze(self) -> AnalysisReport:
        """Return a full threat assessment for all ingested traffic."""
        now = self._clock()
        zscores = self._compute_zscore_flags()
        threat_scores = [
            self._score_ip(profile, zscores.get(ip), now=now)
            for ip, profile in self._profiles.items()
        ]
        flagged = [t for t in threat_scores if t.flagged]
        flagged.sort(key=lambda t: t.score, reverse=True)

        # Top paths by volume
        path_counts: dict[str, int] = {}
        for p in self._global_paths:
            path_counts[p] = path_counts.get(p, 0) + 1
        top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Top IPs by RPS
        cfg = self._config
        top_ips = sorted(
            [(ip, profile.rps(cfg.rate_window_seconds, now=now)) for ip, profile in self._profiles.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Determine overall threat level
        max_score = max((t.score for t in threat_scores), default=0.0)
        if max_score >= 80:
            threat_level = "CRITICAL"
        elif max_score >= 60:
            threat_level = "HIGH"
        elif max_score >= 40:
            threat_level = "MEDIUM"
        elif max_score >= 20:
            threat_level = "LOW"
        else:
            threat_level = "NONE"

        return AnalysisReport(
            total_requests=self._total_requests,
            unique_ips=len(self._profiles),
            flagged_ips=flagged,
            threat_level=threat_level,
            top_paths_by_volume=top_paths,
            top_ips_by_rps=top_ips,
            window_seconds=cfg.rate_window_seconds,
        )

    def generate_rules(self) -> list[MitigationRule]:
        """
        Generate Cloudflare Rules Language expressions for flagged IPs.

        Returns
        -------
        list[MitigationRule]
            One rule per threat tier (BLOCK for critical, CHALLENGE for medium).
            IPs are grouped by action to reduce rule count.
        """
        report = self.analyze()
        if not report.flagged_ips:
            return []

        critical_ips = [t.ip for t in report.flagged_ips if t.score >= 80]
        high_ips = [t.ip for t in report.flagged_ips if 60 <= t.score < 80]
        medium_ips = [t.ip for t in report.flagged_ips if 40 <= t.score < 60]

        rules: list[MitigationRule] = []

        def _ip_list_expr(ips: list[str]) -> str:
            quoted = " ".join(f'"{ip}"' for ip in ips)
            return f"(ip.src in {{{quoted}}})"

        rule_id = 1

        if critical_ips:
            rules.append(MitigationRule(
                rule_id=f"ddos-block-{rule_id:04d}",
                description=f"Block {len(critical_ips)} critical-threat IP(s)",
                expression=_ip_list_expr(critical_ips),
                action="block",
                priority=100,
                ip_addresses=critical_ips,
            ))
            rule_id += 1

        if high_ips:
            rules.append(MitigationRule(
                rule_id=f"ddos-challenge-{rule_id:04d}",
                description=f"JS challenge {len(high_ips)} high-threat IP(s)",
                expression=_ip_list_expr(high_ips),
                action="js_challenge",
                priority=200,
                ip_addresses=high_ips,
            ))
            rule_id += 1

        if medium_ips:
            rules.append(MitigationRule(
                rule_id=f"ddos-managed-{rule_id:04d}",
                description=f"Managed challenge {len(medium_ips)} medium-threat IP(s)",
                expression=_ip_list_expr(medium_ips),
                action="managed_challenge",
                priority=300,
                ip_addresses=medium_ips,
            ))

        return rules

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._profiles.clear()
        self._global_paths.clear()
        self._total_requests = 0

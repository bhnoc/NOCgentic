"""
Timing Pattern Detector for Zeek network events.

Detects two AI-agent behavioral signatures:

1. **Context-Reset (Sawtooth)**
   An agent resets its context window repeatedly → inter-request intervals
   follow a sawtooth pattern: short bursts of requests followed by a sudden
   spike (context boundary / model reload), then another burst.
   Detection: coefficient-of-variation threshold + local-max gap ratio.

2. **Agentic Loop**
   A repetitive request sequence with near-constant inter-request timing and
   consistent payload size — classic tight tool-call loop.
   Detection: low timing entropy + autocorrelation of inter-arrival times.

Output: every input event is returned with an added `patterns` list, e.g.:
  ["context_reset", "agentic_loop"]

Additional per-cluster metrics:
  - timing_entropy  (Shannon entropy of IAT histogram, bits)
  - session_duration (seconds)
  - request_count
  - mean_iat / std_iat
  - sawtooth_score   (0-1)
  - loop_score       (0-1)
"""

import math
import statistics
from typing import Optional


# ── Tunable thresholds ────────────────────────────────────────────────────────

# Context-reset detection
SAWTOOTH_GAP_RATIO = 3.5     # spike IAT must be N× the surrounding median
SAWTOOTH_MIN_SPIKES = 1      # at least this many spikes required
SAWTOOTH_MIN_EVENTS = 6      # need enough events to detect the pattern
SAWTOOTH_SCORE_THRESHOLD = 0.50

# Agentic-loop detection
LOOP_ENTROPY_MAX = 1.8       # bits; tight loops have low IAT entropy
LOOP_AUTOCORR_MIN = 0.45     # lag-1 autocorrelation
LOOP_MIN_EVENTS = 5
LOOP_SCORE_THRESHOLD = 0.23
LOOP_HIGH_RATE_THRESHOLD = 3.0  # requests/second; local model loops are very fast


# ── Math helpers ──────────────────────────────────────────────────────────────

def _iat(timestamps: list[float]) -> list[float]:
    """Inter-arrival times (IAT) from a sorted timestamp list."""
    return [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]


def _shannon_entropy(values: list[float], bins: int = 10) -> float:
    """Shannon entropy of a histogram of values (bits)."""
    if len(values) < 2:
        return 0.0
    mn, mx = min(values), max(values)
    if mx == mn:
        return 0.0
    width = (mx - mn) / bins
    counts = [0] * bins
    for v in values:
        idx = min(int((v - mn) / width), bins - 1)
        counts[idx] += 1
    total = len(values)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _lag1_autocorr(values: list[float]) -> float:
    """Pearson lag-1 autocorrelation of a sequence."""
    n = len(values)
    if n < 3:
        return 0.0
    mean = sum(values) / n
    demeaned = [v - mean for v in values]
    num = sum(demeaned[i] * demeaned[i+1] for i in range(n-1))
    denom = sum(d*d for d in demeaned)
    if denom == 0:
        return 0.0
    return num / denom


def _safe_median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid-1] + s[mid]) / 2
    return s[mid]


# ── Sawtooth detector ─────────────────────────────────────────────────────────

def _sawtooth_score(iats: list[float]) -> tuple[float, int]:
    """
    Return (score 0-1, spike_count).

    Strategy:
      - Compute the rolling local median (window=5) for each IAT.
      - A spike is an IAT that is ≥ SAWTOOTH_GAP_RATIO × local_median.
      - Score is based on fraction of spikes and their magnitude.
    """
    n = len(iats)
    if n < SAWTOOTH_MIN_EVENTS - 1:
        return 0.0, 0

    global_median = _safe_median(iats)
    if global_median <= 0:
        return 0.0, 0

    window = 5
    spikes = 0
    magnitude_sum = 0.0

    for i, iat in enumerate(iats):
        lo = max(0, i - window // 2)
        hi = min(n, i + window // 2 + 1)
        window_vals = [iats[j] for j in range(lo, hi) if j != i]
        local_med = _safe_median(window_vals) if window_vals else global_median
        if local_med <= 0:
            continue
        ratio = iat / local_med
        if ratio >= SAWTOOTH_GAP_RATIO:
            spikes += 1
            magnitude_sum += min(ratio / 10.0, 1.0)

    if spikes < SAWTOOTH_MIN_SPIKES:
        return 0.0, spikes

    # Normalize score: more spikes with higher magnitudes → higher score
    spike_fraction = min(spikes / max(n * 0.2, 1), 1.0)
    avg_magnitude = magnitude_sum / spikes if spikes else 0.0
    score = 0.5 * spike_fraction + 0.5 * avg_magnitude
    return min(score, 1.0), spikes


# ── Loop detector ─────────────────────────────────────────────────────────────

def _loop_score(iats: list[float]) -> float:
    """
    Return score 0-1.  High score = repetitive, near-constant timing.

    Three components:
      - entropy_score: low IAT entropy → uniform timing
      - autocorr_score: positive lag-1 autocorrelation
      - rate_score: high request rate (local model loops are very fast)
    """
    n = len(iats)
    if n < LOOP_MIN_EVENTS - 1:
        return 0.0

    entropy = _shannon_entropy(iats)
    autocorr = _lag1_autocorr(iats)

    # Low entropy → uniform timing → loop-like
    entropy_score = max(0.0, 1.0 - entropy / LOOP_ENTROPY_MAX)
    autocorr_score = max(0.0, (autocorr - 0.0) / 1.0)  # already 0-1 mostly

    # High request rate → tight loop (local models can sustain ≥3 req/s)
    mean_iat = sum(iats) / len(iats)
    req_rate = 1.0 / mean_iat if mean_iat > 0 else 0.0
    rate_score = min(req_rate / LOOP_HIGH_RATE_THRESHOLD, 1.0)

    score = 0.40 * entropy_score + 0.25 * autocorr_score + 0.35 * rate_score
    return min(score, 1.0)


# ── Cluster-level metrics ─────────────────────────────────────────────────────

def _cluster_metrics(events: list[dict]) -> dict:
    """Compute per-cluster timing metrics."""
    # Deduplicate timestamps: ssl.log and conn.log often share identical ts
    # for the same connection, producing zero-IAT pairs that corrupt sawtooth.
    timestamps = sorted(set(
        ev["ts"] for ev in events if ev["ts"] is not None
    ))
    n = len(timestamps)
    if n == 0:
        return {"request_count": 0}

    iats = _iat(timestamps)
    session_duration = timestamps[-1] - timestamps[0]
    mean_iat = sum(iats) / len(iats) if iats else 0.0

    try:
        std_iat = statistics.stdev(iats) if len(iats) >= 2 else 0.0
    except statistics.StatisticsError:
        std_iat = 0.0

    entropy = _shannon_entropy(iats) if iats else 0.0
    saw_score, spike_count = _sawtooth_score(iats)
    lp_score = _loop_score(iats)

    return {
        "request_count": n,
        "session_duration": round(session_duration, 4),
        "mean_iat": round(mean_iat, 6),
        "std_iat": round(std_iat, 6),
        "timing_entropy": round(entropy, 4),
        "sawtooth_score": round(saw_score, 4),
        "sawtooth_spike_count": spike_count,
        "loop_score": round(lp_score, 4),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def annotate_events(
    events: list[dict],
    cluster_key: Optional[tuple] = None,
) -> tuple[list[dict], dict]:
    """
    Annotate a list of events (from a single cluster) with pattern labels.

    Args:
        events: Sorted list of normalized event dicts (same src/dst/port).
        cluster_key: (src_host, dst_host, dst_port) for reporting.

    Returns:
        (annotated_events, cluster_report)

        annotated_events: same list with `patterns` and `pattern_scores` added.
        cluster_report: dict with metrics + detected patterns for this cluster.
    """
    metrics = _cluster_metrics(events)
    patterns_detected: list[str] = []

    if metrics["request_count"] >= SAWTOOTH_MIN_EVENTS:
        if metrics.get("sawtooth_score", 0) >= SAWTOOTH_SCORE_THRESHOLD:
            patterns_detected.append("context_reset")

    if metrics["request_count"] >= LOOP_MIN_EVENTS:
        if metrics.get("loop_score", 0) >= LOOP_SCORE_THRESHOLD:
            patterns_detected.append("agentic_loop")

    # Annotate each individual event
    annotated = []
    for ev in events:
        ae = dict(ev)
        ae["patterns"] = patterns_detected.copy()
        ae["pattern_scores"] = {
            "sawtooth": metrics.get("sawtooth_score", 0.0),
            "loop": metrics.get("loop_score", 0.0),
        }
        annotated.append(ae)

    report = {
        "cluster_key": cluster_key,
        "metrics": metrics,
        "patterns": patterns_detected,
    }

    return annotated, report


def annotate_all_clusters(
    clusters: dict[tuple, list[dict]],
) -> tuple[list[dict], list[dict]]:
    """
    Annotate all clusters.

    Args:
        clusters: Output of ZeekParser.cluster()

    Returns:
        (all_annotated_events, cluster_reports)
    """
    all_events: list[dict] = []
    all_reports: list[dict] = []

    for key, events in clusters.items():
        annotated, report = annotate_events(events, cluster_key=key)
        all_events.extend(annotated)
        all_reports.append(report)

    # Sort events by timestamp
    all_events.sort(key=lambda e: e.get("ts") or 0)

    return all_events, all_reports

"""
drift_stats.py — Pure statistical drift detection for NOCgentic self-improving memory.

Ported exactly from virtual_resident driftStats.ts. No I/O, no PG, no LLM.
All functions are pure and unit-testable in isolation.

Constants match VR exactly:
  Z_95 = 1.96   (95% two-sided critical value)
  Z_99 = 2.576  (99% two-sided critical value)
  CUSUM k=0.25, h=5.0
  assess_drift minEffectPct=5, alerts at z>Z_99 AND delta>=5
"""

from __future__ import annotations

import math

# Standard-normal critical values. 1.96 = 95% two-sided, 2.576 = 99%.
Z_95 = 1.96
Z_99 = 2.576


def two_proportion_z_test(
    fails_before: int,
    n_before: int,
    fails_after: int,
    n_after: int,
) -> dict:
    """Two-proportion z-test comparing failure counts.

    Positive z = 'after' degraded (higher failure rate after promotion).

      z = (p̂_after − p̂_before) / √[ p̂(1−p̂)(1/n_before + 1/n_after) ]
      p̂ = (fails_before + fails_after) / (n_before + n_after)   (pooled)

    Returns dict with keys:
      rate_before, rate_after, delta_pct, n_before, n_after, z, valid, invalid_reason

    Validity gate: total n > 20 AND each expected fail/ok count >= 10,
    else valid=False.

    Ported from VR driftStats.ts lines 52-101.
    """
    rate_before = fails_before / n_before if n_before > 0 else 0.0
    rate_after = fails_after / n_after if n_after > 0 else 0.0
    delta_pct = round((rate_after - rate_before) * 100)

    base = {
        "rate_before": rate_before,
        "rate_after": rate_after,
        "delta_pct": delta_pct,
        "n_before": n_before,
        "n_after": n_after,
    }

    if n_before == 0 or n_after == 0:
        return {**base, "z": 0.0, "valid": False, "invalid_reason": "no runs in one of the periods"}

    pooled = (fails_before + fails_after) / (n_before + n_after)
    se = math.sqrt(pooled * (1 - pooled) * (1 / n_before + 1 / n_after))
    # se == 0 when nobody failed in either period (pooled=0) or everyone did
    # (pooled=1): no variance, so no detectable shift.
    z = (rate_after - rate_before) / se if se > 0 else 0.0

    # Validity gate — expected counts under the null hypothesis.
    total_n = n_before + n_after
    exp_fail_before = n_before * pooled
    exp_ok_before = n_before * (1 - pooled)
    exp_fail_after = n_after * pooled
    exp_ok_after = n_after * (1 - pooled)
    MIN_EXPECTED = 10

    invalid_reason: str | None = None
    if total_n <= 20:
        invalid_reason = f"sample too small ({total_n} runs, need > 20)"
    elif (
        exp_fail_before < MIN_EXPECTED
        or exp_ok_before < MIN_EXPECTED
        or exp_fail_after < MIN_EXPECTED
        or exp_ok_after < MIN_EXPECTED
    ):
        invalid_reason = "too few expected failures/successes for a reliable test"

    return {**base, "z": z, "valid": invalid_reason is None, "invalid_reason": invalid_reason}


def wilson_interval(fails: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Returns [low, high] in 0..1, clamped. Reliable at small n and rates near 0/1.
    n==0 returns (0.0, 1.0).

    Ported from VR driftStats.ts lines 109-119.
    """
    if n == 0:
        return (0.0, 1.0)
    phat = fails / n
    z2 = z * z
    denom = 1 + z2 / n
    center = phat + z2 / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)
    low = (center - margin) / denom
    high = (center + margin) / denom
    return (max(0.0, low), min(1.0, high))


def cusum_upper(
    outcomes: list[bool],
    baseline_rate: float,
    k: float = 0.25,
    h: float = 5.0,
) -> dict:
    """One-sided upper CUSUM over an ordered sequence of run outcomes (True=failure).

    Detects a sustained increase in failure rate above baseline_rate.

      S_0 = 0 ;  S_i = max(0, S_{i-1} + (x_i − baseline_rate − k))

    k (slack=0.25) is half the shift to detect quickly.
    h (decision interval=5.0) is the alarm threshold.

    Returns dict with keys: peak (float), triggered (bool), alarm_at (int, -1 if none).

    Ported from VR driftStats.ts lines 141-157.
    """
    s = 0.0
    peak = 0.0
    alarm_at = -1
    for i, outcome in enumerate(outcomes):
        x = 1.0 if outcome else 0.0
        s = max(0.0, s + (x - baseline_rate - k))
        if s > peak:
            peak = s
        if alarm_at == -1 and s > h:
            alarm_at = i
    return {"peak": peak, "triggered": alarm_at != -1, "alarm_at": alarm_at}


def assess_drift(
    fails_before: int,
    n_before: int,
    fails_after: int,
    n_after: int,
    ordered_after_outcomes: list[bool],
    min_effect_pct: int = 5,
    z_crit: float = Z_99,
) -> dict:
    """Combine test + CUSUM into a single verdict for one memory.

    Conservative policy: only 'alert' when degradation is significant at 99%,
    sample is valid, AND effect is >= min_effect_pct pp. CUSUM can raise 'watch'
    on gradual drift even when the window test isn't conclusive yet.

    Returns dict with keys:
      level ('alert'|'watch'|'insufficient_data'|'ok'|'improving'),
      z, delta_pct, drift_score_pct, reason, ci_after_pct (tuple[int,int])

    drift_score_pct: max(0, min(100, delta_pct)) for alert/watch (how much worse),
                     0 for ok/improving/insufficient_data.

    Ported from VR driftStats.ts assessDrift lines 189-264.
    """
    test = two_proportion_z_test(fails_before, n_before, fails_after, n_after)
    ci_low, ci_high = wilson_interval(fails_after, n_after)
    ci_after_pct = (round(ci_low * 100), round(ci_high * 100))
    cusum = cusum_upper(ordered_after_outcomes, test["rate_before"])

    if not test["valid"]:
        return {
            "level": "insufficient_data",
            "z": test["z"],
            "delta_pct": test["delta_pct"],
            "drift_score_pct": 0,
            "reason": test["invalid_reason"] or "insufficient data",
            "ci_after_pct": ci_after_pct,
        }

    significant99 = test["z"] > z_crit
    big_enough = test["delta_pct"] >= min_effect_pct

    if significant99 and big_enough:
        return {
            "level": "alert",
            "z": test["z"],
            "delta_pct": test["delta_pct"],
            "drift_score_pct": max(0, min(100, test["delta_pct"])),
            "reason": (
                f"failure rate rose {test['delta_pct']}pp "
                f"({round(test['rate_before'] * 100)}% → {round(test['rate_after'] * 100)}%, "
                f"z={test['z']:.2f}, n={test['n_after']}) after this memory was applied"
            ),
            "ci_after_pct": ci_after_pct,
        }

    # Statistically significant at 95% but not 99%/effect, or CUSUM caught gradual
    # drift: worth watching, not yet worth an alert.
    if test["z"] > Z_95 or cusum["triggered"]:
        reason = (
            "gradual increase in failures detected after this memory was applied"
            if cusum["triggered"]
            else f"possible degradation ({test['delta_pct']}pp, z={test['z']:.2f}) — watching"
        )
        return {
            "level": "watch",
            "z": test["z"],
            "delta_pct": test["delta_pct"],
            "drift_score_pct": max(0, min(100, test["delta_pct"])),
            "reason": reason,
            "ci_after_pct": ci_after_pct,
        }

    # Symmetric improvement signal: significant DROP in failure rate.
    # Same 99% bar + effect floor as 'alert' so we don't promote on noise.
    significant_drop = test["z"] < -z_crit
    big_drop = test["delta_pct"] <= -min_effect_pct
    if significant_drop and big_drop:
        return {
            "level": "improving",
            "z": test["z"],
            "delta_pct": test["delta_pct"],
            "drift_score_pct": 0,
            "reason": (
                f"failure rate fell {abs(test['delta_pct'])}pp "
                f"({round(test['rate_before'] * 100)}% → {round(test['rate_after'] * 100)}%, "
                f"z={test['z']:.2f}, n={test['n_after']}) after this memory was applied"
            ),
            "ci_after_pct": ci_after_pct,
        }

    return {
        "level": "ok",
        "z": test["z"],
        "delta_pct": test["delta_pct"],
        "drift_score_pct": 0,
        "reason": "no significant change",
        "ci_after_pct": ci_after_pct,
    }


def plan_action(status: str, level: str) -> dict:
    """Decide the single best action for one memory given its drift verdict.

    Only active/candidate memories get actions; draft/retired return None.
    Priority:
      1. retire  — active|candidate + alert
      2. promote — candidate + improving
      3. None    — ok or insufficient_data (no action needed)
      4. adjust_confidence — everything else (watch, active+improving, etc.)

    Returns {"action": "retire"|"promote"|"adjust_confidence"|None, "reason": str}.

    Ported from VR memorySelfImprove.ts planAction (lines 73-108).
    Draft is not retireable per VR (only active/candidate are in-play).
    """
    if status not in {"active", "candidate"}:
        return {
            "action": None,
            "reason": f"status '{status}' is not actionable (only active/candidate)",
        }

    # Harm → retire (active or candidate).
    if level == "alert":
        return {
            "action": "retire",
            "reason": f"drift level 'alert' triggered retirement for {status} memory",
        }

    # Proven winner that isn't active yet → promote.
    if level == "improving" and status == "candidate":
        return {
            "action": "promote",
            "reason": "memory proved beneficial; promoting candidate to active",
        }

    # No action needed for stable/unknown outcomes.
    if level in {"ok", "insufficient_data"}:
        return {"action": None, "reason": f"level '{level}' requires no action"}

    # watch, or active+improving: nudge confidence toward measured effect.
    return {
        "action": "adjust_confidence",
        "reason": f"drift level '{level}' — nudging confidence",
    }

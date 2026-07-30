"""
test_drift_stats.py — Pure unit tests for agents/shared/drift_stats.py.

NO Postgres required. All math is deterministic and testable in isolation.
Tests verify the port from VR driftStats.ts is exact:
  k=0.25, h=5.0 for CUSUM
  Z_95=1.96, Z_99=2.576
  minEffectPct=5 for assess_drift
  plan_action branches match VR memorySelfImprove.ts (draft not retireable)
"""

from __future__ import annotations

import math
import pytest
import sys
from pathlib import Path

# Ensure agents/shared is on the path (conftest does this, but be explicit)
_SHARED = str(Path(__file__).resolve().parents[2] / "agents" / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import drift_stats


# ---------------------------------------------------------------------------
# two_proportion_z_test
# ---------------------------------------------------------------------------

class TestTwoProportionZTest:
    def test_clear_degradation_valid(self):
        """5/100 before, 40/100 after — should be significant and valid."""
        result = drift_stats.two_proportion_z_test(5, 100, 40, 100)
        assert result["valid"] is True
        assert result["z"] > 1.96
        assert result["delta_pct"] == 35  # round((0.40 - 0.05) * 100) = 35
        assert result["rate_before"] == pytest.approx(0.05)
        assert result["rate_after"] == pytest.approx(0.40)

    def test_z_value_approximate(self):
        """Verify z-value math. pooled = (5+40)/200 = 0.225.
        se = sqrt(0.225*0.775*(1/100+1/100)) = sqrt(0.225*0.775*0.02)
        z = (0.40-0.05)/se
        """
        pooled = (5 + 40) / 200
        se = math.sqrt(pooled * (1 - pooled) * (1 / 100 + 1 / 100))
        expected_z = (0.40 - 0.05) / se
        result = drift_stats.two_proportion_z_test(5, 100, 40, 100)
        assert result["z"] == pytest.approx(expected_z, rel=1e-6)

    def test_tiny_sample_invalid(self):
        """n=5+5=10 — well below n>20 gate."""
        result = drift_stats.two_proportion_z_test(2, 5, 3, 5)
        assert result["valid"] is False
        assert result["invalid_reason"] is not None
        assert "sample too small" in result["invalid_reason"]

    def test_no_variance_zero_z(self):
        """0 failures in both periods — pooled=0, se=0, z=0.
        valid=False because expected_fail counts = 0 < MIN_EXPECTED (10).
        """
        result = drift_stats.two_proportion_z_test(0, 50, 0, 50)
        assert result["z"] == 0.0
        assert result["valid"] is False  # expected fails = 0 < 10, so invalid

    def test_no_variance_invalid_due_to_expected_counts(self):
        """All failures: pooled=1, expected_ok=0 < 10 → invalid."""
        result = drift_stats.two_proportion_z_test(50, 50, 50, 50)
        assert result["valid"] is False

    def test_zero_n_before_invalid(self):
        result = drift_stats.two_proportion_z_test(0, 0, 5, 100)
        assert result["valid"] is False
        assert result["invalid_reason"] == "no runs in one of the periods"
        assert result["z"] == 0.0

    def test_zero_n_after_invalid(self):
        result = drift_stats.two_proportion_z_test(5, 100, 0, 0)
        assert result["valid"] is False
        assert result["z"] == 0.0

    def test_negative_delta_improvement(self):
        """40/100 before, 5/100 after — improvement, negative delta."""
        result = drift_stats.two_proportion_z_test(40, 100, 5, 100)
        assert result["delta_pct"] == -35
        assert result["z"] < -1.96
        assert result["valid"] is True

    def test_validity_gate_boundary_n20(self):
        """Exactly n=20: 10+10=20 — should be invalid (need > 20, not >= 20)."""
        result = drift_stats.two_proportion_z_test(1, 10, 1, 10)
        assert result["valid"] is False
        assert "sample too small" in result["invalid_reason"]

    def test_validity_gate_n21_passes_if_counts_ok(self):
        """n=21+21=42; fails proportional enough to pass expected count gate."""
        # pooled ≈ 0.5, each expected count ≈ 10+ → valid
        result = drift_stats.two_proportion_z_test(11, 21, 10, 21)
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# wilson_interval
# ---------------------------------------------------------------------------

class TestWilsonInterval:
    def test_n_zero_returns_full_range(self):
        low, high = drift_stats.wilson_interval(0, 0)
        assert low == 0.0
        assert high == 1.0

    def test_bounds_within_zero_one(self):
        for fails, n in [(0, 100), (100, 100), (50, 100), (1, 5), (0, 1), (1, 1)]:
            low, high = drift_stats.wilson_interval(fails, n)
            assert 0.0 <= low <= 1.0, f"low={low} out of range for fails={fails},n={n}"
            assert 0.0 <= high <= 1.0, f"high={high} out of range for fails={fails},n={n}"
            assert low <= high

    def test_symmetric_at_half(self):
        """50/100 should give interval roughly centered on 0.5."""
        low, high = drift_stats.wilson_interval(50, 100)
        assert low < 0.5 < high
        # Should be roughly symmetric
        assert abs((0.5 - low) - (high - 0.5)) < 0.01

    def test_zero_failures_low_is_zero(self):
        low, high = drift_stats.wilson_interval(0, 100)
        assert low == 0.0
        assert high > 0.0

    def test_all_failures_high_is_one(self):
        low, high = drift_stats.wilson_interval(100, 100)
        assert high == pytest.approx(1.0, abs=1e-10)
        assert low < 1.0

    def test_custom_z(self):
        """Z_99 gives a wider interval than Z_95."""
        lo95, hi95 = drift_stats.wilson_interval(10, 50, z=drift_stats.Z_95)
        lo99, hi99 = drift_stats.wilson_interval(10, 50, z=drift_stats.Z_99)
        assert lo99 < lo95
        assert hi99 > hi95

    def test_formula_matches_vr(self):
        """Spot-check: wilson_interval(40, 100) against manual calculation."""
        fails, n = 40, 100
        z = drift_stats.Z_95
        phat = fails / n
        z2 = z * z
        denom = 1 + z2 / n
        center = phat + z2 / (2 * n)
        margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)
        expected_low = max(0, (center - margin) / denom)
        expected_high = min(1, (center + margin) / denom)
        low, high = drift_stats.wilson_interval(fails, n)
        assert low == pytest.approx(expected_low, rel=1e-9)
        assert high == pytest.approx(expected_high, rel=1e-9)


# ---------------------------------------------------------------------------
# cusum_upper
# ---------------------------------------------------------------------------

class TestCusumUpper:
    def test_all_failures_low_baseline_triggers(self):
        """All failures with low baseline → triggered=True, alarm_at >= 0."""
        outcomes = [True] * 20
        result = drift_stats.cusum_upper(outcomes, baseline_rate=0.05)
        assert result["triggered"] is True
        assert result["alarm_at"] >= 0
        assert result["peak"] > 5.0

    def test_all_successes_does_not_trigger(self):
        """All successes → triggered=False."""
        outcomes = [False] * 50
        result = drift_stats.cusum_upper(outcomes, baseline_rate=0.3)
        assert result["triggered"] is False
        assert result["alarm_at"] == -1

    def test_empty_sequence(self):
        result = drift_stats.cusum_upper([], baseline_rate=0.1)
        assert result["triggered"] is False
        assert result["peak"] == 0.0
        assert result["alarm_at"] == -1

    def test_constants_k_h(self):
        """Default k=0.25, h=5.0 per VR lines 141-157."""
        # With k=0.25, each True with baseline 0 contributes 1-0-0.25=0.75.
        # Need 5/0.75 ≈ 7 consecutive Trues to trigger at baseline=0.
        outcomes_6 = [True] * 6
        outcomes_7 = [True] * 7
        r6 = drift_stats.cusum_upper(outcomes_6, baseline_rate=0.0)
        r7 = drift_stats.cusum_upper(outcomes_7, baseline_rate=0.0)
        # 6 * 0.75 = 4.5 ≤ 5 → not triggered; 7 * 0.75 = 5.25 > 5 → triggered
        assert r6["triggered"] is False
        assert r7["triggered"] is True
        assert r7["alarm_at"] == 6  # 0-indexed, fires on 7th element (index 6)

    def test_mixed_outcomes_accumulate_correctly(self):
        """S resets to 0 on low values, accumulates on high ones."""
        # 5 failures then 5 successes then 5 failures: verify CUSUM resets
        outcomes = [True] * 5 + [False] * 20 + [True] * 30
        result = drift_stats.cusum_upper(outcomes, baseline_rate=0.5)
        # The 30-failure run at baseline 0.5, k=0.25: each adds 0.25
        # After 20+ it should trigger
        assert result["triggered"] is True

    def test_cusum_formula_per_vr(self):
        """Verify the exact formula: S_i = max(0, S_{i-1} + (x_i - baseline - k))."""
        outcomes = [True, False, True, True, False]
        baseline = 0.3
        k = 0.25
        s = 0.0
        peak = 0.0
        alarm_at = -1
        for i, x_bool in enumerate(outcomes):
            x = 1.0 if x_bool else 0.0
            s = max(0.0, s + (x - baseline - k))
            if s > peak:
                peak = s
            if alarm_at == -1 and s > 5.0:
                alarm_at = i
        result = drift_stats.cusum_upper(outcomes, baseline_rate=baseline, k=k, h=5.0)
        assert result["peak"] == pytest.approx(peak, rel=1e-9)
        assert result["triggered"] == (alarm_at != -1)
        assert result["alarm_at"] == alarm_at


# ---------------------------------------------------------------------------
# assess_drift
# ---------------------------------------------------------------------------

class TestAssessDrift:
    def test_strong_degradation_alert(self):
        """5/100 before, 40/100 after → 'alert'."""
        result = drift_stats.assess_drift(5, 100, 40, 100, [True] * 40 + [False] * 60)
        assert result["level"] == "alert"
        assert result["z"] > drift_stats.Z_99
        assert result["delta_pct"] >= 5
        assert result["drift_score_pct"] > 0

    def test_strong_improvement_improving(self):
        """40/100 before, 5/100 after → 'improving'."""
        result = drift_stats.assess_drift(40, 100, 5, 100, [False] * 95 + [True] * 5)
        assert result["level"] == "improving"
        assert result["z"] < -drift_stats.Z_99
        assert result["delta_pct"] <= -5
        assert result["drift_score_pct"] == 0

    def test_tiny_sample_insufficient_data(self):
        """n=5+5 → 'insufficient_data'."""
        result = drift_stats.assess_drift(2, 5, 3, 5, [True, True, True, False, False])
        assert result["level"] == "insufficient_data"
        assert result["drift_score_pct"] == 0

    def test_no_change_ok(self):
        """Same rate before and after → z≈0, but CUSUM may trigger on clustered
        failures. Use a perfectly interleaved sequence to avoid CUSUM."""
        # 15/100 vs 15/100 — z≈0. Spread failures out so CUSUM stays quiet.
        after_outcomes = ([True, False, False, False, False, False] * 16 + [True] * 15)[:100]
        result = drift_stats.assess_drift(15, 100, 15, 100, after_outcomes)
        # z should be ~0 so neither alert/watch/improving — 'ok'
        assert result["level"] == "ok"
        assert result["drift_score_pct"] == 0

    def test_ci_after_pct_is_tuple_of_ints(self):
        result = drift_stats.assess_drift(5, 100, 40, 100, [True] * 40 + [False] * 60)
        ci = result["ci_after_pct"]
        assert isinstance(ci, tuple)
        assert len(ci) == 2
        assert 0 <= ci[0] <= 100
        assert 0 <= ci[1] <= 100
        assert ci[0] <= ci[1]

    def test_reason_is_string(self):
        result = drift_stats.assess_drift(5, 100, 40, 100, [True] * 40 + [False] * 60)
        assert isinstance(result["reason"], str)
        assert len(result["reason"]) > 0

    def test_cusum_watch_triggers(self):
        """Even if z < Z_99, a long run of failures can trigger CUSUM → 'watch'."""
        # Use a case where z is between Z_95 and Z_99 to trigger 'watch'
        # 10/100 before, 20/100 after → not quite alert territory
        result = drift_stats.assess_drift(
            10, 100, 20, 100, [True] * 20 + [False] * 80
        )
        # delta_pct = 10, borderline; may be watch or alert depending on exact z
        # The key property is level is not 'ok' or 'improving'
        assert result["level"] in {"alert", "watch"}


# ---------------------------------------------------------------------------
# plan_action
# ---------------------------------------------------------------------------

class TestPlanAction:
    def test_active_alert_retires(self):
        result = drift_stats.plan_action("active", "alert")
        assert result["action"] == "retire"

    def test_candidate_alert_retires(self):
        result = drift_stats.plan_action("candidate", "alert")
        assert result["action"] == "retire"

    def test_candidate_improving_promotes(self):
        result = drift_stats.plan_action("candidate", "improving")
        assert result["action"] == "promote"

    def test_active_improving_adjust_confidence(self):
        """Already active + improving → adjust_confidence (not promote)."""
        result = drift_stats.plan_action("active", "improving")
        assert result["action"] == "adjust_confidence"

    def test_active_ok_returns_none(self):
        result = drift_stats.plan_action("active", "ok")
        assert result["action"] is None

    def test_candidate_ok_returns_none(self):
        result = drift_stats.plan_action("candidate", "ok")
        assert result["action"] is None

    def test_active_insufficient_data_returns_none(self):
        result = drift_stats.plan_action("active", "insufficient_data")
        assert result["action"] is None

    def test_candidate_watch_adjust_confidence(self):
        result = drift_stats.plan_action("candidate", "watch")
        assert result["action"] == "adjust_confidence"

    def test_active_watch_adjust_confidence(self):
        result = drift_stats.plan_action("active", "watch")
        assert result["action"] == "adjust_confidence"

    def test_draft_alert_returns_none(self):
        """Draft is not retireable per VR — only active/candidate are actionable."""
        result = drift_stats.plan_action("draft", "alert")
        assert result["action"] is None

    def test_retired_alert_returns_none(self):
        """Retired memory — nothing to do."""
        result = drift_stats.plan_action("retired", "alert")
        assert result["action"] is None

    def test_retired_improving_returns_none(self):
        result = drift_stats.plan_action("retired", "improving")
        assert result["action"] is None

    def test_reason_is_string(self):
        for status, level in [
            ("active", "alert"),
            ("candidate", "improving"),
            ("active", "ok"),
            ("candidate", "watch"),
            ("draft", "alert"),
        ]:
            result = drift_stats.plan_action(status, level)
            assert isinstance(result["reason"], str)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_constants():
    assert drift_stats.Z_95 == 1.96
    assert drift_stats.Z_99 == 2.576


# ---------------------------------------------------------------------------
# mem-7 regression gate: improving beats watch when net trend is strongly down
# ---------------------------------------------------------------------------

class TestMem7ImprovingBeforeWatch:
    def test_improving_not_watch_when_early_cluster_then_long_success(self):
        """mem-7 fix: a memory with an early failure cluster followed by a long
        run of successes must be classified as 'improving', not 'watch'.

        Before the fix, CUSUM (triggered by the early cluster) was checked first
        and returned 'watch' even though the net trend was strongly improving.
        After the fix, 'improving' is evaluated before 'watch'.

        Setup:
          before: 200 failures in 200 runs (100% failure rate)
          after:  3 failures then 200 successes (< 1.5% failure rate)
          The z-test will show a massive drop; z << -Z_99, delta_pct << -5.
          The early [False,False,False] cluster is tiny — CUSUM won't trigger on
          only 3 failures at a 1.0 baseline_rate, but even if a pathological
          variant triggered it, 'improving' should win.
        """
        fails_before = 200
        n_before = 200
        # after: 3 failures out of 203 = ~1.5% failure rate
        after_outcomes = [True, True, True] + [False] * 200
        fails_after = sum(1 for x in after_outcomes if x)
        n_after = len(after_outcomes)

        result = drift_stats.assess_drift(
            fails_before, n_before, fails_after, n_after, after_outcomes
        )
        assert result["level"] == "improving", (
            f"Expected 'improving' but got {result['level']!r}. "
            f"z={result['z']:.3f}, delta_pct={result['delta_pct']}. "
            "mem-7 regression: 'improving' must be evaluated before 'watch'."
        )
        assert result["z"] < -drift_stats.Z_99
        assert result["delta_pct"] <= -5

    def test_watch_still_fires_when_not_improving(self):
        """Sanity check: 'watch' still fires when the trend is adverse (not improving)."""
        # 10/100 before, 20/100 after — borderline, watch/alert territory
        result = drift_stats.assess_drift(
            10, 100, 20, 100, [True] * 20 + [False] * 80
        )
        assert result["level"] in {"alert", "watch"}, (
            f"Expected alert or watch but got {result['level']!r}"
        )

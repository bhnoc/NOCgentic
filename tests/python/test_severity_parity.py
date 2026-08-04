"""
Severity-normalization PARITY regression (sweep-4 ql-8 + sweep-5 fc-1).

alert-triage._norm_sev is the source of truth; athena-hunter._normalize_severity
is a hand-maintained mirror that feeds the live /alerts/recent UI feed. This
pair has diverged and regressed TWICE; the highest-value lock-in here.

Two invariants:
  1. PARITY: for every shared input the two functions return the SAME bucket.
  2. UNKNOWN-not-LOW: blank / None / garbage / out-of-range numeric severities
     must map to "unknown" (stays visible for review), NEVER silently to "low".

Both functions are imported from the real agent main.py modules (loaded with
telemetry disabled via conftest); not reimplemented.
"""

from __future__ import annotations

import pytest

from conftest import load_agent_main

_at = load_agent_main("alert-triage", "alert_triage_main")
_ah = load_agent_main("athena-hunter", "athena_hunter_main")

norm_sev = _at._norm_sev            # source of truth
normalize_severity = _ah._normalize_severity  # UI-feed mirror


# Inputs from the task, plus a few extra edge cases.
SHARED_INPUTS = [
    "1", "2", "3",
    "critical", "error", "informational",
    "", "xyz", None, "5",
    "4", "0", "high", "medium", "low",
    "notification", "informational (default)",
    "  CRITICAL  ", "HIGH",
]


@pytest.mark.parametrize("value", SHARED_INPUTS)
def test_norm_sev_parity(value):
    """REVERT-CHECK: if either mapping drifts (e.g. athena-hunter drops the
    NUM_SEV table, or one side maps blank->'low' while the other maps
    blank->'unknown'), the two return values diverge and this FAILS. That
    divergence is exactly the bug that regressed in sweeps 4 and 5."""
    assert norm_sev(value) == normalize_severity(value), (
        f"severity divergence on {value!r}: "
        f"triage={norm_sev(value)!r} vs hunter={normalize_severity(value)!r}"
    )


# "4" is deliberately NOT in this list: it is a real Suricata severity
# (informational), not garbage, and it is 83% of live suricata rows. Asserting it
# bucketed to "unknown" was locking in the bug, because "unknown" scores 3 (==
# medium), which floated the noisiest severity in the data to the top of the
# feed. See test_severity_four_is_informational_not_unknown below.
@pytest.mark.parametrize("garbage", ["", "   ", "xyz", None, "5", "0", "99", "sev-none"])
def test_unknown_not_low(garbage):
    """Blank/garbage/out-of-range severities must bucket to 'unknown', not 'low'.

    REVERT-CHECK: the pre-fix behavior let an unrecognized value fall through
    to 'low' (buried under real lows, dropped from prioritized_alerts[:15]).
    Asserting == 'unknown' and != 'low' catches that regression on both sides.
    """
    assert norm_sev(garbage) == "unknown", f"triage buried {garbage!r}"
    assert normalize_severity(garbage) == "unknown", f"hunter buried {garbage!r}"
    assert norm_sev(garbage) != "low"
    assert normalize_severity(garbage) != "low"


def test_known_numeric_and_word_buckets():
    # Corelight/Suricata numeric convention: 1->high, 2->medium, 3->low, 4->informational.
    for fn in (norm_sev, normalize_severity):
        assert fn("1") == "high"
        assert fn("2") == "medium"
        assert fn("3") == "low"
        assert fn("4") == "informational"
        assert fn("critical") == "critical"
        assert fn("informational") == "informational"
        # Word aliases fold identically on both sides.
        assert fn("error") == "high"
        assert fn("notification") == "low"
        assert fn("informational (default)") == "informational"


def test_severity_four_is_informational_not_unknown():
    """Suricata severity 4 must bucket as informational on BOTH paths.

    REVERT-CHECK for the enum-drift bug. alert_severity='4' is 3.9M of 4.7M live
    suricata rows. While it was absent from NUM_SEV it fell through to the ql-7
    "unknown" branch, which SEVERITY_SCORE gives 3, the same score as medium. The
    single noisiest severity in the data therefore outranked genuine lows in
    prioritized_alerts[:15].

    It also has to agree with the Athena `alerts` view, which is the other route
    to the same rows and maps it with `ELSE 'informational'`. Before the fix a
    severity-4 alert read 'informational' through the view and 'unknown' through
    the raw table, so the label depended on which query path a question took.
    """
    for fn in (norm_sev, normalize_severity):
        assert fn("4") == "informational"
        assert fn("4") != "unknown"
    # Parity with the view's CASE for the whole numeric range it defines.
    view_case = {"1": "high", "2": "medium", "3": "low", "4": "informational"}
    for raw, expected in view_case.items():
        assert norm_sev(raw) == expected, f"drifted from the alerts view on {raw!r}"
        assert normalize_severity(raw) == expected

    # And the score must actually be the lowest, which is the point of the fix.
    assert _at.SEVERITY_SCORE["informational"] < _at.SEVERITY_SCORE["low"]
    assert _at.SEVERITY_SCORE["informational"] < _at.SEVERITY_SCORE["unknown"]

"""
redate_slice.py destructive-path guard regression (sweep-4-fix).

main() runs clear_dst_partition() which DELETES the dt=<target> partition
(Glue + S3) before each INSERT. Two hard stops guard that:
  1. REFUSE if SRC_DT is among the target days (would delete the SOURCE before reading).
  2. REFUSE if BUCKET != the demo bucket (would touch non-demo data).
Both call sys.exit(...) BEFORE any AWS/Glue call, so no flag can override them.

The module constructs boto3 clients at import time, but that makes no network
call, so we import it directly (conftest puts scripts/ on sys.path). We then
monkeypatch the module constants and assert main() exits at the guard, BEFORE
reaching physical_tables() (which we replace with a tripwire that fails the
test if the guard ever lets execution through).
"""

from __future__ import annotations

import pytest

import redate_slice as rs


@pytest.fixture(autouse=True)
def _tripwire(monkeypatch):
    """If a guard is bypassed, main() would reach physical_tables()/AWS. Replace
    those with sentinels that fail loudly, so a bypassed guard can't silently
    'pass' by doing nothing (or worse, hit real AWS)."""
    def _boom(*a, **k):
        raise AssertionError("guard bypassed: reached AWS/table logic")

    monkeypatch.setattr(rs, "physical_tables", _boom)
    monkeypatch.setattr(rs, "clear_dst_partition", _boom)
    monkeypatch.setattr(rs, "q", _boom)
    # main() reads sys.argv; keep it clean.
    monkeypatch.setattr("sys.argv", ["redate_slice.py"])


def test_refuses_when_src_is_a_target_day(monkeypatch):
    """REVERT-CHECK: remove the `if SRC_DT in DST_DTS: sys.exit(...)` guard and
    main() would proceed to clear_dst_partition on the SOURCE partition and
    delete live data. With the guard, main() raises SystemExit before the
    tripwire fires."""
    monkeypatch.setattr(rs, "DST_DTS", [rs.SRC_DT])
    with pytest.raises(SystemExit) as exc:
        rs.main()
    # sys.exit(msg) -> code is the message string; confirm it's the SRC-in-targets guard.
    assert "SRC_DT" in str(exc.value)


def test_refuses_when_bucket_is_not_demo_bucket(monkeypatch):
    """REVERT-CHECK: remove the BUCKET allowlist guard and main() would run
    clear_dst_partition (S3 deletes) against an arbitrary bucket."""
    monkeypatch.setattr(rs, "BUCKET", "some-other-production-bucket")
    with pytest.raises(SystemExit) as exc:
        rs.main()
    assert "BUCKET" in str(exc.value)


def test_default_constants_are_the_safe_demo_values():
    # The shipped defaults must be internally safe: no target day equals SRC, and the
    # demo bucket. DST_DTS derives from today (UTC), so SRC (2026-04-24) can never be in
    # it in practice, but assert it explicitly as the guard's precondition.
    assert rs.SRC_DT not in rs.DST_DTS
    assert len(rs.DST_DTS) >= 1
    assert rs.BUCKET == "blackhat-pope-parquet"

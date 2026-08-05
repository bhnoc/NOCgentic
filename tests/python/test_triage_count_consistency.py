"""
Alert-triage COUNT-CONSISTENCY regression (sweep-6 ct-1..ct-8).

Locks in the fix for two contradictions an operator actually saw on the live app:

  1. "59 alerts" followed by an enumeration of ~4.6 MILLION alerts by severity.
     Cause: `alert_severity_totals` was a whole-table COUNT(*) GROUP BY that
     ignored every query filter (ct-8), sitting in the same payload as
     `total_alerts` (a LIMIT-capped, post-filter row count) with nothing naming
     either population (ct-1/ct-5), while SYSTEM_PROMPT ordered the model to
     cite both (ct-6).

  2. "120 alerts ... comprising 120 informational" printed beside signature hit
     counts of 1,103 and 355. Cause: `source_attack_profile` carries TRUE
     per-source aggregates while `total_alerts` is a sampled fetch (ct-3);
     120 < 1103 is impossible for one population, so the answer read as broken.

The invariants below are about the PAYLOAD the LLM receives and the SQL that
produces it, not about LLM wording, because prompt output is nondeterministic
and the payload is not. If the payload cannot express two contradictory
"alert counts" as the same quantity, the model cannot print them as one.
"""

from __future__ import annotations

import inspect

import pytest

from conftest import load_agent_main

_at = load_agent_main("alert-triage", "alert_triage_main")


# ---------------------------------------------------------------------------
# ct-8 (ROOT CAUSE): the true-total aggregate must be filterable, so it counts
# the same population as the row fetches it is reported next to.
# ---------------------------------------------------------------------------

def test_severity_counts_accepts_the_same_filters_as_the_row_fetches():
    """Pre-fix this took only `hours`, so a filtered query got a whole-table count."""
    params = inspect.signature(_at.athena_alert_severity_counts).parameters
    for p in ("hours", "src_ip", "dst_ip", "severity"):
        assert p in params, (
            f"athena_alert_severity_counts must accept {p!r}: an aggregate that "
            "ignores the query's filters counts a different population than "
            "total/returned-row counts and contradicts them in the same answer"
        )


@pytest.mark.asyncio
async def test_severity_counts_sql_applies_the_ip_filter(monkeypatch):
    """The filter must reach the WHERE clause, not just the signature."""
    seen: dict[str, str] = {}

    async def _fake_query(sql, label="query"):
        seen["sql"] = sql
        return [{"severity": "high", "count": "7"}]

    monkeypatch.setattr(_at, "_athena_query", _fake_query)
    rows, scope = await _at.athena_alert_severity_counts(hours=24, src_ip="10.1.2.3")

    sql = seen["sql"]
    assert "10.1.2.3" in sql, f"src_ip never reached the aggregate's WHERE clause: {sql}"
    assert "GROUP BY severity" in sql
    # The payload must be able to SAY what population it counted.
    assert any("10.1.2.3" in s for s in scope), (
        f"scope must name the filters applied so the payload can state the "
        f"population, got {scope!r}"
    )


@pytest.mark.asyncio
async def test_severity_counts_unfiltered_stays_unfiltered(monkeypatch):
    """A genuinely network-wide question must still get a network-wide count.

    The fix must not over-tighten: "how many alerts today by severity" with no
    IP named still has to count everything, or we trade a too-big number for a
    too-small one.
    """
    seen: dict[str, str] = {}

    async def _fake_query(sql, label="query"):
        seen["sql"] = sql
        return [{"severity": "low", "count": "34829"}]

    monkeypatch.setattr(_at, "_athena_query", _fake_query)
    rows, scope = await _at.athena_alert_severity_counts(hours=24)

    sql = seen["sql"]
    assert "orig_h" not in sql and "alert_name" not in sql, (
        f"an unfiltered counting question must not gain a row filter: {sql}"
    )
    assert scope == ["last 24h"]


# ---------------------------------------------------------------------------
# ct-1/ct-3/ct-5/ct-6: the payload must NAME each count's population, and must
# not ship two differently-scoped counts under one name.
# ---------------------------------------------------------------------------

def test_payload_key_names_state_that_row_counts_are_samples():
    """`total_alerts` asserted a network total it did not have; the name had to go."""
    src = inspect.getsource(_at.triage)
    assert '"alerts_returned_for_analysis"' in src, (
        "the fetched-row count must be named as a retrieval detail, not as "
        "'total_alerts' — the old name is what invited '59 alerts' as a "
        "network-wide claim"
    )
    assert '"severity_breakdown_of_returned_rows"' in src, (
        "the sampled severity split must not share the name 'severity_breakdown' "
        "with the authoritative one"
    )
    assert '"COUNT_SEMANTICS"' in src, (
        "the payload must carry an explicit population map; without it the model "
        "has to infer which counts are comparable, and it infers wrong"
    )


def test_count_semantics_names_every_numeric_population():
    """Every count family in the payload needs a stated denominator."""
    src = inspect.getsource(_at.triage)
    start = src.index('"COUNT_SEMANTICS"')
    block = src[start:start + 3000]
    for key in (
        "alert_severity_totals",              # authoritative aggregate
        "alerts_returned_for_analysis",       # sampled fetch
        "severity_breakdown_of_returned_rows",  # sampled split
        "source_attack_profile",              # per-source aggregate (ct-3)
        "top_talkers",                        # per-host aggregate (ct-9)
    ):
        assert key in block, f"COUNT_SEMANTICS must describe {key}'s population"


def test_authoritative_totals_state_their_population():
    """ct-8's other half: the number must travel with the scope it counted."""
    src = inspect.getsource(_at.triage)
    # Anchor on the payload literal, not the COUNT_SEMANTICS description of the
    # same key (which appears earlier in the source).
    start = src.index('**({"alert_severity_totals": {')
    block = src[start:start + 1500]
    assert '"population"' in block, (
        "alert_severity_totals must state which alerts it counted, or a "
        "filtered aggregate reads as a network-wide total"
    )


def test_prompt_establishes_counting_precedence():
    """ct-6: the prompt must say which count answers 'how many', and that a
    per-source aggregate exceeding the sample is expected, not a contradiction."""
    p = _at.SYSTEM_PROMPT
    assert "COUNT_SEMANTICS" in p, "prompt must point the model at the population map"
    assert "AUTHORITATIVE" in p, "prompt must name one count as authoritative"
    assert "alerts_returned_for_analysis" in p, "prompt must reference the new key names"
    assert "total_alerts" not in p, (
        "prompt still cites the removed key 'total_alerts'; a rule naming a "
        "key that is not in the payload is a rule the model cannot follow"
    )
    # The ct-3 symptom specifically: the model must not try to "fix" 1103 > 120.
    assert "EXCEED" in p or "exceed" in p, (
        "prompt must state that a per-source aggregate may exceed the sampled "
        "count, or the model reconciles them by picking the smaller number"
    )


# ---------------------------------------------------------------------------
# ct-4: the "sampled" label must describe the number it is attached to.
# ---------------------------------------------------------------------------

def test_count_label_distinguishes_filtered_from_capped():
    """"at least 3 (true total higher)" was wrong: 3 was exact within the sample."""
    # _count is a closure inside triage(); assert on its source contract rather
    # than reaching into the frame.
    src = inspect.getsource(_at.triage)
    assert "matching rows found inside a SAMPLE of" in src, (
        "a post-filter count under a capped fetch must be labelled as exact "
        "within the sample, not as a floor on the network"
    )


def test_uncapped_count_passes_through_as_a_plain_number():
    """Regression guard: the fix must not label honest complete counts as sampled."""
    src = inspect.getsource(_at.triage)
    assert "if not is_capped:" in src and "return n" in src, (
        "an under-cap count must still pass through as a true total"
    )


# ---------------------------------------------------------------------------
# ct-2: a merged fetch must not clear the sampled flag.
# ---------------------------------------------------------------------------

def test_signature_merge_preserves_and_ors_the_cap_flag():
    """A capped 100-row signature fetch merged into a 30-row hint fetch used to
    yield a 130-row list reported as a COMPLETE total."""
    src = inspect.getsource(_at.triage)
    assert 'capped["suricata"] = capped["suricata"] or len(result) >= 100' in src, (
        "suricata_signature merge must OR its own cap in, never leave the flag stale"
    )
    assert 'capped["unified"] = capped["unified"] or len(result) >= 100' in src, (
        "alerts_signature merge must OR its own cap in"
    )


# ---------------------------------------------------------------------------
# ct-7: one severity vocabulary across both breakdowns.
# ---------------------------------------------------------------------------

def test_aggregate_severity_keys_are_normalized_to_canonical_buckets():
    """"error: 20000" beside "high: 2" gives an operator no way to know they match."""
    merged = _at._merge_sev_counts([
        {"severity": "1", "count": "10"},        # -> high
        {"severity": "error", "count": "5"},     # -> high (collides with above)
        {"severity": "4", "count": "3900000"},   # -> informational
        {"severity": "critical", "count": "2"},
    ])
    assert set(merged) <= set(_at._severity_breakdown([])), (
        f"aggregate buckets must use the same vocabulary as the row breakdown, "
        f"got {set(merged)}"
    )
    # Normalizing COLLIDES keys; summing is required or a count is silently lost.
    assert merged["high"] == 15, f"collided buckets must SUM, not overwrite: {merged}"
    assert merged["informational"] == 3900000
    assert merged["critical"] == 2


def test_merge_sev_counts_handles_garbage_without_dropping_counts():
    """An unparseable severity must stay visible as 'unknown', never vanish."""
    merged = _at._merge_sev_counts([
        {"severity": "xyz", "count": "9"},
        {"severity": None, "count": "1"},
        {"severity": "high", "count": "0"},
    ])
    assert merged.get("unknown") == 10, f"garbage severities must be retained: {merged}"
    assert sum(merged.values()) == 10


# ---------------------------------------------------------------------------
# The two original symptoms, as end-to-end payload assertions.
# ---------------------------------------------------------------------------

def test_symptom_59_vs_4_6M_cannot_recur_unlabelled():
    """Both numbers may coexist, but never as the same named quantity."""
    src = inspect.getsource(_at.triage)
    # The authoritative aggregate and the sampled fetch must not both be
    # reachable under a name containing "total_alerts".
    assert '"total_alerts":       _count(' not in src, (
        "the sampled fetch must no longer be published as 'total_alerts' in the "
        "LLM payload"
    )


def test_symptom_120_informational_profile_scope_is_stated():
    """ct-3: the per-source profile must declare it counts one source only."""
    src = inspect.getsource(_at.triage)
    start = src.index('"COUNT_SEMANTICS"')
    block = src[start:start + 3000]
    assert "ONE source IP only" in block, (
        "source_attack_profile must declare its per-source scope, or its 1,103 "
        "hits read as contradicting a 120-row sample"
    )

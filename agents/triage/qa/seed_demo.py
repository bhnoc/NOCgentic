#!/usr/bin/env python3
"""Seed a small demo dataset for the level9000 UI (triage queue + glass-box trace).

Writes directly to the store (no Gemini/Athena needed) so the frontend has something
real to render for a screenshot: a few alerts across buckets, and one investigation run
with a full ordered event trace.

Run inside a container that has agents/shared on the path, or locally with PG_DSN set:
  PG_DSN=postgresql://nocgentic:nocgentic@localhost:5432/nocgentic python seed_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make agents/shared importable both locally and in-container.
for cand in (Path(__file__).resolve().parents[2] / "shared", Path("/app/shared")):
    if cand.exists():
        sys.path.insert(0, str(cand))
        break

import store  # noqa: E402


def main() -> None:
    store.init_schema()

    # --- alerts across a couple of buckets ---
    a1 = store.upsert_alert(
        dedup_key="ET MALWARE Cobalt Strike Beacon|10.220.5.13|185.220.101.7",
        severity=1, source_ip="10.220.5.13", dest_ip="185.220.101.7",
        alert_type="malware", signature="ET MALWARE Cobalt Strike Beacon",
        connector_source="suricata_corelight",
    )
    a2 = store.upsert_alert(
        dedup_key="ET SCAN Potential Nmap|10.220.5.40|10.220.0.1",
        severity=3, source_ip="10.220.5.40", dest_ip="10.220.0.1",
        alert_type="recon", signature="ET SCAN Potential Nmap Scan",
        connector_source="suricata_corelight",
    )
    a3 = store.upsert_alert(
        dedup_key="ET POLICY DNS over HTTPS|10.220.6.7|1.1.1.1",
        severity=4, source_ip="10.220.6.7", dest_ip="1.1.1.1",
        alert_type="policy", signature="ET POLICY DNS over HTTPS",
        connector_source="suricata_corelight",
    )

    # Move a2 through the state machine so the queue shows more than one bucket.
    store.transition_alert(a2, "validating", reason="demo: worker started")

    # --- one investigation run with a full ordered glass-box trace ---
    run_id = store.start_run("investigation", {
        "query": "Investigate the Cobalt Strike beacon from 10.220.5.13",
        "window_hours": 24,
    })
    store.emit(run_id, "plan", {"question": "Is 10.220.5.13 beaconing to a C2?"})
    store.emit(run_id, "tool_call", {
        "sql": "SELECT alert_signature, count(*) n FROM suricata_corelight "
               "WHERE dt='2026-07-30' AND id_orig_h='10.220.5.13' GROUP BY 1"})
    store.emit(run_id, "tool_result", {"row_count": 3, "sample": [
        {"alert_signature": "ET MALWARE Cobalt Strike Beacon", "n": 214}]})
    store.emit(run_id, "tool_call", {
        "sql": "SELECT id_resp_h, sum(orig_bytes) tx FROM conn "
               "WHERE dt='2026-07-30' AND id_orig_h='10.220.5.13' GROUP BY 1 ORDER BY tx DESC"})
    store.emit(run_id, "tool_result", {"row_count": 1, "sample": [
        {"id_resp_h": "185.220.101.7", "tx": 4821004}]})
    store.emit(run_id, "verdict", {
        "high_signals": ["ET MALWARE Cobalt Strike Beacon"], "severity": "critical"})
    store.emit(run_id, "synthesis", {"chars": 240})
    store.finish_run(run_id, "completed", {
        "verdict": "threat", "severity": "critical",
        "summary": "Host 10.220.5.13 shows a sustained Cobalt Strike beacon to 185.220.101.7 "
                   "with 214 alerts and 4.8 MB outbound over 24h. Consistent with an active C2 "
                   "channel, not a false positive.",
        "recommendation": "Isolate 10.220.5.13 and hunt for lateral movement from it.",
    })

    # Link the run to the beacon alert via a transition, so the triage detail shows it.
    store.transition_alert(a1, "validating", reason="demo: worker started")
    store.transition_alert(a1, "validated_true_positive",
                           reason="investigator verdict", investigation_run_id=run_id)

    print(f"seeded alerts: {a1[:8]} {a2[:8]} {a3[:8]}")
    print(f"seeded investigation run: {run_id}")


if __name__ == "__main__":
    main()

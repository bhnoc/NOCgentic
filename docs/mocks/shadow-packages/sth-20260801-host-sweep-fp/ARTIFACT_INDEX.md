# Artifact index — {{INV_ID}}

Investigation workspace for Shadow package `sth-20260801-host-sweep-fp`.

Paths below use **tokens**. Operators resolve via `redaction-map.json` (operator-only).

| Path | Purpose |
|------|---------|
| `notes.md` | Full hunter log + disposition |
| `meta.json` | Investigation metadata |
| `raw/triage_ranked.json` | Triage ranking snapshot |
| `raw/cases_browse.json` | Scored cases browse table |
| `cases/{{CASE_PRIMARY}}/incident.json` | Raw incident |
| `cases/{{CASE_PRIMARY}}/extra.json` | Extra / alerts payload |
| `cases/{{CASE_PRIMARY}}/findings.json` | Scorer + hunts + IoCs |
| `issues/host-{{HOST_A}}/identity.json` | Deep host identity |
| `issues/host-{{HOST_A}}/related.json` | Related incidents/alerts |
| `issues/host-{{HOST_A}}/identity_notes.md` | Short host notes |
| `issues/host-{{MAC_A}}/identity.json` | MAC pivot identity |
| `issues/ioc-ip-{{DNS_GOOGLE}}/enrichment.json` | Public DNS enrich |
| `xql/*host-dns-top*` | Top DNS for host |
| `xql/*host-outbound-ports*` | Outbound ports |
| `xql/*host-threats*` | NGFW threats |
| `shadow_export/manifest.json` | Package manifest |
| `shadow_export/path.json` | Learner known-good steps |
| `shadow_export/shadow.json` | Original hunter reasoning (tokens) |
| `shadow_export/redaction-map.json` | **Operator only** — real values |
| `shadow_export/HUNTER_NARRATIVE.md` | After-action story |
| `shadow_export/evidence/*` | Compact evidence slices |
| `shadow_export/CURATOR_REPORT.md` | Privacy review record |

**Do not commit** operator `redaction-map.json` to public branches. Do not serve it to learner UI.

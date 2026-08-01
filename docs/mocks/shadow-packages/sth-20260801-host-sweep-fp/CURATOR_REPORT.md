# Curator report — `sth-20260801-host-sweep-fp`

| Field | Value |
|-------|--------|
| Package | `sth-20260801-host-sweep-fp` |
| Source | `palo_alto/investigations/inv_20260801_132954_1def9f/shadow_export` |
| Destination | `docs/mocks/shadow-packages/sth-20260801-host-sweep-fp` |
| Reviewed | 2026-08-01 |
| Reviewer | nocgentic-curator |
| **Verdict** | **APPROVED — training-safe** (operator map retained separately) |

---

## 1. Copy

- Copied full `shadow_export/` into NOCgentic package path above.

## 2. Redaction-map review

| Token | Kind | Sensitivity | Decision |
|-------|------|-------------|---------|
| `{{CASE_PRIMARY}}` | incident_id | tenant-internal | Keep in map; learner files tokenized |
| `{{HOST_A}}` | RFC1918 IP | network-internal | Map only; scrubbed from learner paths |
| `{{MAC_A}}` | privacy MAC | network-internal | Map only; used as “user” in telemetry (not a person name) |
| `{{HOSTNAME_A}}` | hostname `Mac` | low | Tokenized everywhere learners see it |
| `{{DNS_GOOGLE}}` / `{{DNS_QUAD9}}` / `{{DNS_QUAD9_ALT}}` | public resolvers | public | Tokens for pivot consistency |
| `{{INV_ID}}` | workspace id | tenant-internal | Tokenized in manifest + artifact index |
| `{{FW_NAME}}` | device | infra | Mapped; unused in learner UI |
| `{{ZONE_FROM}}` / `{{ZONE_TO}}` | zones | infra | Tokenized in findings + shadow narrative |

**PII checklist**

- [x] No person names  
- [x] No emails / phones  
- [x] No credentials / keys  
- [x] No badge / HR IDs  
- [x] No PSKs  
- [x] Slack thread timestamps removed from `related_brief.json`  
- [x] Learner files do not embed original IP/MAC/inv id  

**Residual risk:** low–medium re-identification by on-shift staff via DNS mix + timing. Acceptable for internal training; do not publish package publicly without legal review.

## 3. Learner-file fixes applied

| File | Change |
|------|--------|
| `manifest.json` | Tokenized `data_scope` ids; `review_status=approved`; `classification=training-safe` |
| `path.json` | Tokenized `source_artifacts` paths; hostname hint uses `{{HOSTNAME_A}}` |
| `shadow.json` | `general_wifi` → `{{ZONE_FROM}}`; bare hostname → token |
| `HUNTER_NARRATIVE.md` | Zone path uses tokens |
| `ARTIFACT_INDEX.md` | Fully tokenized paths |
| `evidence/findings_brief.json` | Zone fields tokenized |
| `evidence/identity_brief.json` | Hostname tokenized |
| `evidence/related_brief.json` | Thread IDs stripped; secondary cases generic |
| `redaction-map.json` | Curator block, real SHA-256 hashes, policy warning |

## 4. Accepted residuals

| Item | Rationale |
|------|-----------|
| Secondary triage case IDs (`8634`, …) in `triage_top.json` | Opaque tenant integers; no person binding; useful for “queue noise” teaching |
| Org DNS names (Kandji, Slack, Corelight, Apple) | Expected SaaS fingerprint for FP disproof; not personal identifiers |
| `{{CASE_RELATED_n}}` without reverse map entries | Intentionally one-way for learner package |

## 5. Serving rules for mocks / product

1. **Do not** load `redaction-map.json` in browser mocks.  
2. UI may use `display_label` values only if copied into a separate `display-labels.json` without `original`.  
3. Prefer git-ignore or private storage for the operator map on any shared remote.

## 6. Suggested mock title

**Shadow the Hunter — “Host Sweep that wasn’t”**  
FP teaching path: triage → case → agentless identity → DNS/SaaS corroboration → FP disposition.

---

*Curator pass complete.*

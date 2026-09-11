# Threat hunting catalog in the analyst UI

The `threathunt-catalog/` tree (APE-743 research, APE-750 security review) is
served to analysts as the **Playbooks** tab of the BH AI SOC interface and
linked from detection output. This page is the operator view; the code
comments carry the detail.

## What is where

| Piece | Path |
|---|---|
| The catalog (33 markdown entries + README) | `threathunt-catalog/{playbooks,skills,frameworks,community-detections,references}/` |
| Detection → playbook links, one file for both readers | `threathunt-catalog/finding-playbook-map.json` |
| Indexer, search, match | `packages/web-server/src/services/huntCatalog.ts` |
| HTTP routes | `packages/web-server/src/api/catalog.ts` |
| Playbooks tab + alert-popup chips | `packages/web-server/static/huntCatalog.js` |
| zeek-detector `playbooks` field | `agents/zeek-detector/pipeline/findings_generator.py` |
| Tests | `packages/web-server/test/huntCatalog.test.ts`, `test/catalogRoutes.test.ts`, `tests/python/test_zeek_detector.py`, `tests/ui/playbooks.mjs` |

## The boundary that matters

The catalog is **reference material a person reads**. It is never sent to an
LLM: no route under `/api/v1/catalog` reaches the orchestrator or any agent,
and the chat path does not read the catalog. The APE-750 review found the
files clean to store and distribute, and separately flagged that loading them
into a model's context is a different decision. This feature does not make
that decision. If someone proposes retrieval-augmenting an agent with these
documents, that is a new task with Cipher on it, not a flag on this one.

The one hand-off from catalog to chat is the **Hunt this live** button: each
playbook carries a single author-written question in `hunt_queries` (in the
map file) which is submitted exactly as the starter-hint chips are. Those
strings are tested against copies of the orchestrator guardrails
(`huntCatalog.test.ts`), so a chip can not answer with a silent cover. They
have not yet been re-vetted against the live show network the way the starter
pool was; run `python bench/starter_hints_smoke.py --queries-file <file>` with
the sixteen strings before the next event and replace any that come back thin.

## Routes

```
GET /api/v1/catalog                      index: summaries, facets, alert-topic links
GET /api/v1/catalog/search?q=&section=&technique=&source=&limit=
GET /api/v1/catalog/match?behavior=&patterns=a,b&topic=
GET /api/v1/catalog/:id                  one entry with its markdown body
```

All GET, all Zod-validated, all public (same exposure as the tab). The entry
id is a key into the in-memory index, never a filesystem path. A missing tree
makes every route answer 503 rather than an empty catalog.

Search is a small term scorer, not a search engine: id and title matches
outrank technique ids, which outrank data sources, headings and body term
frequency, and hits matching more of the query's terms sort first. It ranks the
right playbook first for the questions analysts actually type ("dns
tunneling", "kerberoasting", "T1558"), and it stays a function over 33
documents with no dependency.

## Indexing

Each file yields: id (`PB-nn` for playbooks, file stem otherwise), section,
title, first prose paragraph as summary, ATT&CK technique and tactic ids, data
sources (`*.log` names plus suricata / pcap / netflow / sigma / elastic
keywords), tools, headings and a term-frequency map. Playbooks read their
`**ATT&CK**` / `**Data Sources**` / `**Tools**` header lines; files without
them are indexed from their prose. Three playbooks (PB-08, PB-09, PB-15) say
"supporting all tactics" and name no technique; they carry an empty list rather
than an invented one.

Adding a file: drop the markdown in the right section directory. Nothing else
to register. The Docker image copies the whole tree.

## Detection links

`finding-playbook-map.json` has three blocks:

- `zeek_detector.patterns` and `.behaviors`: keyed on the detector's
  `detected_patterns` values and `behavior_classification` labels. The
  detector stamps every finding with `playbooks` (patterns first, then
  behaviour, deduped, max 4) and the CISO CSV has the same column.
- `alert_topics`: keyed on the topic labels `alertHints.js` derives from an
  alert's description. The alert popup shows a **Playbooks** row built from
  this map; clicking a chip opens the Playbooks tab on that entry. The vendor
  description is never used directly, for the same reason the hunt chips do
  not use it.
- `hunt_queries`: the per-playbook live question described above.

Tests pin the map to both consumers: every referenced id must exist in the
catalog, every topic label the hint code can produce must have an entry, and
the detector's pattern and behaviour vocabularies must be covered. Change a
label in either producer and the test names the missing key.

## Deep links

`#playbooks` opens the tab; `#playbooks/PB-05` opens that entry. Both are
`replaceState` like `#threat-hunt`, so tab flips do not pile up history.

## Deploy notes

Two-way door: additive routes, a new static file, a new tab, a new optional
field on zeek-detector findings (defaulted, so rows stored before it validate).
Rollback is reverting the commit. `ops/deploy.sh` rsyncs the tree and the
web-server Dockerfile copies `threathunt-catalog/`; no env var is required.
`CATALOG_DIR` overrides the location and `ZEEK_PLAYBOOK_MAP` the detector's
copy of the map, both only for unusual layouts.

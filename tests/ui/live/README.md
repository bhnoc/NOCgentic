# Live UI sweep tools

Headless-Chrome-over-CDP drivers, same no-npm-deps pattern as `tests/ui/*.mjs`,
but pointed at the real production app (`https://ng.bhnoc.com` by default,
override with `QA_BASE`) instead of the local stub server. Read-only: chat
queries and alert-card clicks only, no destructive or admin actions.

Not part of `ops/run-tests.sh` or CI — these hit a live, shared instance and
real LLM calls, so they're a manual sweep tool, not a gate. Run by hand:

```bash
bash tests/ui/live/run.sh                    # golden path: chip -> answer -> hint -> alert popup
CDP_PORT=9224 node tests/ui/live/mobile-and-typed.mjs   # mobile viewport + typed query (needs Chrome already running)
```

`golden-path.mjs` drives what most users actually do: land, click a starter
chip, read the answer, click a Next Steps hint, open an alert card, close it
with Escape.

`mobile-and-typed.mjs` covers the two things the golden path doesn't: a
390px mobile viewport, and typing a question + pressing Enter instead of
clicking a chip.

`hint-chip-timing.mjs` is a diagnostic, not a sweep — it samples the hint-chip
DOM count every 3s after a query settles, because hints populate
asynchronously (up to ~20s after `status: done`) and a driver that checks
once right at settle can wrongly conclude hints never arrived.

`cdp.mjs` is the shared connect/evaluate/check helper both scripts import.

# Prompt eval: v16 final (2026-07-27)

Closed the last two open items (alert-03 routing ambiguity, judge variance) and, in doing
so, found and fixed a deeper measurement problem: the goldens had drifted from the seeded
data. Also shipped a real windowing bug fix (both-ends ts bound) and a more forgiving
redate. Same method throughout: 14 golden scenarios end to end, 3 channels, Gemini judge.

## Full arc

| channel | v1 baseline | v16 |
|---|---|---|
| ACCURACY | 84.5% | 98.8% |
| RELEVANCE (judge) | 0.257 | 0.718 |

Every scenario routes ok; every use case 91-100% accuracy.

## What this pass changed

1. **Rolling window bounded at BOTH ends (real bug).** date_filter and the athena-hunter
   SQL-gen bound had only `ts >= now-24h`. A rolling window is [now-24h, now]; without the
   upper bound, FUTURE-stamped rows leak in. The dev redate seeds today's 00:00-03:00
   block, in the future when queried at 01:00, so a lower-only bound counted it AND
   yesterday's copy: 8.35M vs the true 4.82M. Added `ts <= now` in date_filter, the
   SQL-gen prompt, and the safety-net injection. This would also bite at the real
   conference (any query run while today's capture is still accumulating over-counts).

2. **Redate seeds today + tomorrow, dates auto-derived.** A single midnight-anchored 3h
   block ages out of the 24h window a few hours into the next day. redate_slice now seeds
   today AND tomorrow (DAYS_AHEAD, default 1) with dates computed from today (UTC), so one
   run keeps the demo live ~2 days with no manual day-offset. The both-ends ts bound is
   what makes two seeded days safe (only the in-window day counts).

3. **alert-03 routing accepted as ambiguous.** "Are there Kali boxes?" is both a named
   alert (alert_triage) and a DHCP-hostname hunt (athena_hunter); both reach the DHCP
   host_name='kali' evidence and answer well. Added an acceptable_intents field to the
   golden schema; the routing check passes on expected OR any accepted alternate.

4. **Judge variance: median-of-3 sampling.** A single flash-lite judge swings run-to-run
   even at temperature 0 (a real 0.9 answer scored 0.0 on one call). Each judge now scores
   JUDGE_SAMPLES times (default 3, env-overridable) and takes the MEDIAN, rejecting a lone
   outlier. Stabilized the channel (hunt-04 stopped flapping); a single-judge panel can
   still throw one scenario to 0.0 occasionally (see caveats).

5. **Goldens re-derived from the 3h seed window.** The biggest relevance lift. The goldens
   were written from the original FULL-day 04-24 capture, but the redate seeds only 3h, so
   facts drifted and the judge correctly scored faithful answers as contradicting stale
   ground truth:
   - hunt-04 top-bytes: full-day 172.16.7.12 (~297GB) is not the window leader; rewrote to
     be window-agnostic (a few 10.220.x hosts dominate; exact leader shifts with the
     window; judge on shape not a pinned IP).
   - alert-02: the window has TWO AWS-enum sources (192.168.131.7 AND 192.168.130.120), so
     the app naming both is correct; golden updated.
   - byip-01: 172.16.16.16 is still the benign DNS forwarder (908k conns, 99.9% port 53),
     but as the resolver it RELAYS tunnel/RMM DNS (argotunnel), so it appears on those
     alerts by design; golden now explains the relay so it is not read as malicious.

## Lesson worth keeping

The redate seeds a 3-hour slice, but the goldens (and data-facts.json) were built from the
full 04-24 day. Any fact that depends on volume or ranking (top talkers, counts, "the only
critical") is a slice of that and will drift when the window or seed changes. Facts that are
identity-stable (a specific scan pair, a hostname, a MAC, a signature's existence) do not
drift. When re-seeding with a different window, re-derive the volume/ranking goldens.
Better long-term: derive those goldens from the same rolling window the app queries, or
seed a full day so full-day facts hold.

## Still open (minor)

- **Single-judge residual noise**: median-of-3 damps but does not eliminate the occasional
  one-scenario 0.0 on a Gemini-only panel (byip-02 flapped 0.0 this run, 0.3-0.4 before,
  same answer). Cross-vendor judge or more samples would fix it; deferred per Gemini-only
  scope. Read mid-range relevance as +/- noise; trust accuracy and the large fixes.
- **data-facts.json** still reflects full-day facts; update it if it is used as a reference
  for future golden authoring (it drove the original goldens).
- **Local-model path**: all fixes validated on Gemini only. If the next show uses the local
  model (Qwen3-Coder-30B was the pick), the whole v1->v16 delta needs re-running under it.

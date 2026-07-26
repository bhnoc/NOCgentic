# Prompt eval: v11 final (2026-07-26)

Closing pass. Fixed the athena-hunter count-doubling (task 1) and the last threat-hunt
answer-quality gap (task 2, hunt-03 suspicious-DNS). Re-dated the dev demo data to today so
the eval runs against live in-window data. Same method throughout: 14 golden scenarios end
to end against the live app, 3 channels reported separately, Gemini judge.

## Headline: full arc

| channel | v1 baseline | v11 |
|---|---|---|
| ACCURACY | 84.5% | 98.8% |
| RELEVANCE (judge) | 0.257 | 0.714 |
| SPEED (mean) | 9.4s | 10.8s |

Every scenario routes correctly (0 MISS). Every use case is 95-100% accuracy.

| use case | v1 rel | v11 rel | v11 acc |
|---|---|---|---|
| alert_validation | ~0.00 | 0.63 | 95.8% |
| guardrail | 0.00 | 1.00 | 100% |
| by_mac | 0.00 | 0.90 | 100% |
| by_ip | 0.50 | 0.55 | 100% |
| threat_hunt | 0.40 | 0.63 | 100% |
| network_quality | 1.00 | 1.00 | 100% |

## Task 1: athena-hunter count doubling

The alert-triage path was fixed earlier via the shared date_filter ts-bound, but the
athena-hunter path writes its own dt clause. For "recent"/existence queries it used the
deliberate 2-day rollover prune `dt IN ('today','yesterday')` with NO ts bound, returning
up to ~48h of rows. On the redated dev slice that doubled counts; on real data it sums two
distinct capture days. Proven on the real April week: partition-only returned 143.7M conns
vs 39.2M for a true 24h window (~3.7x over-count).

Fix (keeping the 2-day prune, which is needed for hourly rollover): pass the real epoch
cutoff into the SQL-gen prompt and instruct the model to add `AND ts >= <epoch>` on the
2-day prune, PLUS a deterministic safety net in SQL validation that injects the bound when
the model omits it (guarded to skip JOINs, where a bare `ts` is ambiguous). Verified live:
"how many alerts today" now returns the true 67,941 / 2 critical, not 135,882 / 4.

## Task 2: hunt-03 suspicious-DNS (argotunnel)

hunt-03 missed argotunnel, the golden's key finding, and said "tunneling absent." Two
compounding causes:
1. The DNS-anomaly hunt only did DGA-shape (LENGTH(query)>50 OR NXDOMAIN) on the dns table.
   Tunneling/RMM domains are SHORT and resolve fine; they are flagged by an IDS SIGNATURE
   (argotunnel fired 'ET INFO DNS Query to Cloudflare Tunneling Domain' 10,070x), not by
   query shape, so the hunt never looked at alert_name.
2. After adding the signature query, the LLM wrote it as a row-by-row SELECT, so
   argotunnel's volume was buried among RMM rows.

Fix: expanded the DNS-anomaly pattern to generate BOTH a shape query and a signature query
on alerts (tunnel/argotunnel/DoH/RMM/fast-flux/exfil/p2p), and made it prescriptive that
the signature query MUST be a COUNT aggregate grouped by alert_name and the answer must
LEAD with the highest-count signature. hunt-03 now opens with "10,070 alerts for Cloudflare
tunneling domains (argotunnel.com)." accuracy 66.7 -> 100%, relevance 0.0 -> 0.60.

Bonus: hunt-02 (SSH) was scoring 0.0 intermittently on judge noise; with fresh data it
returns the exact golden pair (192.168.129.6 -> 10.131.12.220, 293 conns). Not a code
change, just confirmed it was never broken.

## Data refresh (redate)

The ts-bound fix exposed that the dev demo slice was frozen at 07-25 while "now" was 07-26,
so a true 24h window correctly found nothing. Re-ran scripts/redate_slice.py (retargeted to
dt=2026-07-26, +93 days) with the write-capable VirtualPOC-users profile; 68/68 tables OK.
Also hardened the driver: it now fails fast and reports a clean no-op (not phantom DATA
LOSS) when run with read-only creds, after an earlier run on the box's read-only instance
role printed 54 false data-loss warnings (nothing was actually deleted; verified intact).

## Still open (minor, answer-quality only)

- **by-MAC vendor**: id_orig_mac_vendor is a dead column; the prompt asks the model to
  derive the vendor from the OUI (00:0c:29 = VMware) but flash-lite does not reliably do
  the OUI mapping and still says "unknown." A small OUI lookup would fix it if it matters.
- **alert-03 (Kali) relevance 0.30**: accuracy 0.833. The Kali hosts are corroborated by
  DHCP host_name='kali' (10.220.25.x); the agent likely is not joining DHCP to the alert.
  Next candidate if another pass is wanted.
- **Judge variance**: Gemini-on-Gemini relevance swings run to run (alert-02 0.30 vs 0.85,
  byip-01/02 0.30 vs 0.80 across v9-v11) while deterministic accuracy is stable. Read
  mid-range relevance as noisy; trust accuracy and the 0.0->high fixes (corroborated by
  accuracy).
- **redate places data at 00:00-03:00 of the target day**: a 24h lookback covers it all day,
  but a "last 3 hours" query late in the day would find nothing. If the demo needs to look
  live in a narrow recent window regardless of time-of-day, shift the source window to sit
  just before "now" rather than at midnight.

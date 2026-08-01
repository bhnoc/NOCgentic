# Curator report — sth-20260801-spike-dns-tp

**Date:** 2026-08-01  
**Source:** `inv_20260801_151132_6816b3` · case 8612  

## Privacy

| Item | Action |
|------|--------|
| Personal mDNS / owner first name | Redacted → tokens |
| Assignee email / pretty name | Operator map only |
| Host IP / MAC | Tokens in learner package; map holds reals |
| Malware domain | Kept as public IoC (or token) |
| Slack workspace names | Sanitized to role labels where needed |

## Disposition attestation

Hunter disposition **malicious_true_positive** with residual uncertainty on live A/HTTP C2. Training package teaches method + human actions, not auto-isolate.

## Contrast

Pairs with `sth-20260801-host-sweep-fp` (FP) for transfer learning.

## Review status

**approved** for mock / training UI (2026-08-01).

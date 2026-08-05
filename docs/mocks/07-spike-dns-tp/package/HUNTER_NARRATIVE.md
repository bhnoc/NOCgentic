# Hunter narrative — Spike DNS that was real

**Package:** `sth-20260801-spike-dns-tp`  
**Event:** Black Hat / NOC training · live Cortex XSIAM  
**Original hunter:** CLI Hunter  

---

## Situation

The open *new* queue was noise: critical Exchange RCE (ZGrab scanners), Large Upload piles, and hunting notebooks. The mission question was:

> What is the most credible **live true positive** right now — and can multi-source evidence support action without reckless isolation?

The answer was not in the top of default “new.” It was **under_investigation**: Spike DNS Malware Traffic on domain **{{DOMAIN_IOC}}**.

---

## Steps taken

### 1. FILTER — triage under noise

Default triage top favored scanners and upload FP class. I pivoted to status / malware-shaped cases and opened **{{CASE_PRIMARY}}** (score ~126 investigate path; medium; Exfiltration; starred).

**Skill:** Critical severity ≠ internal compromise. Volume ≠ exfil.

### 2. READ — open the case

Alerts: host **{{HOST_A}}** → remote **{{DNS_VA}}:53** with external hostname **{{DOMAIN_IOC}}**. Category Exfiltration. Spike counts in the hundreds over 24h windows.

**Skill:** The remote IP is the **venue DNS VA** (OpenDNS/Umbrella), not the malware C2 address. The IoC is the **query name**.

### 3. SCOPE — enrich domain

`enrich domain {{DOMAIN_IOC}}`: **one** internal source, **~697** hits / 72h. Sole-source malware DNS.

**Skill:** Sole-source + high volume elevates priority.

### 4. ID — who is the host?

`host identify --deep`: agentless Mac, mDNS **{{HOSTNAME_A}}**, privacy MAC **{{MAC_A}}**, network **{{VLAN}}**. DNS profile: Slack (incl. NOC workspace), Anthropic, Keybase, VS Code, Apple — **operator-shaped**. Related host inventory empty (case is correlation, not a host-tied alert stack).

**Skill:** Agentless is a **containment constraint**, not “not real.” Confirm owner **privately** — do not turn mDNS into an HR ticket.

### 5. CORROBORATE — volume + TI, accept IPS gap

Domain events: repeated STORY rows host → DNS VA :53 for the IoC name (beacon-shaped). Multi-vendor TI (Unit 42 / VT / Google) flags domain malicious. NGFW threats on host: informational TLS/ECH/PQ style — **no** malware signature on the domain itself.

**Skill:** Detection can be **DNS volume + TI** without an IPS malware hit. Residual uncertainty: sinkhole/NXDOMAIN may mean no live A-record C2 in telemetry.

### 6. DECIDE — TP + human actions

| Field | Value |
|-------|--------|
| Disposition | **malicious_true_positive** |
| Confidence (activity real / hostile-shaped) | ~0.85 |
| Confidence (active C2 with resolved HTTP) | ~0.55 (DNS→resolver only) |
| Severity if hostile | **High** on NOC segment |
| Containment | No auto-isolate (agentless); human ownership |

**Human next steps**

1. Confirm owner of {{OWNER_HINT}} on {{HOST_A}}.  
2. Keep/confirm DNS block or sinkhole for {{DOMAIN_IOC}}.  
3. Label ground-truth TP for the case.  
4. Do not auto-resolve as “known issue” without ownership.

---

## Contrast: Host Sweep FP package

| | Host Sweep FP | Spike DNS TP (this) |
|--|---------------|---------------------|
| Remote | Public DNS resolvers | Venue DNS VA + **malware query name** |
| TI on name | N/A / benign shape | Multi-vendor **malicious** |
| Volume story | DNS looking like “sweep” | Spike to **one** bad domain |
| Disposition | False positive | True positive |

Same method: multi-source, humility, mutations wait. **Opposite answer.**

---

## Lessons for juniors

1. **Filter the loud queue.** TPs hide in under_investigation.  
2. **Read the remote.** DNS VA ≠ C2 IP.  
3. **Sole-source malware DNS is a page-me shape.**  
4. **NOC Mac ≠ free pass** — and ≠ public blame.  
5. **IPS silence ≠ green light** when TI + volume agree.  
6. **Decide with residual uncertainty** and list human actions.

---

*Tokenized for learners. Operator map holds real values.*

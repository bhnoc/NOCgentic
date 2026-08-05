# Memo: Slack threat hunt → MUD config

How to turn a real Slack investigation thread into a playable Threat Hunt
MUD entry — the same path used for **Cleartext MCP, FAKE CORP asset**
(`fakecorp-cleartext-mcp` in `packages/web-server/static/threat-hunt-config.js`).

Contract reference: [`ThreatHunt.d.ts`](./ThreatHunt.d.ts).  
Engine (content-free): `packages/web-server/static/threat-hunt.js`.  
Ship target: push one object onto `window.THREAT_HUNTS` in
`packages/web-server/static/threat-hunt-config.js` (and mirror under
`docs/threat-hunt-mud/` if you keep the handoff bundle in sync).

---

## 1. What you are making

A ~3-minute, click-only drill:

| MUD piece | SOC meaning |
| --- | --- |
| Rooms | Log sources / surfaces (Zeek, DNS, device profile, class traffic) |
| Exits | Pivots (buttons) |
| Inventory | Evidence chips |
| Boss fight | One decision — usually a **BH close code** or containment action |

The game is **data**. You do not change the engine unless you need a new
mechanic. You author a config object.

---

## 2. Harvest the Slack thread (before you invent rooms)

Paste or export the thread. Then fill this worksheet — only from what the
thread actually shows.

### 2.1 Facts table

| Field | What to extract | Example (FAKE CORP hunt) |
| --- | --- | --- |
| Trigger | First signal / what someone noticed | Cleartext HTTP to cloud, many `/…/mcp` paths |
| Source | IP / host as observed | Conference RFC1918 client |
| Dest | Where traffic went | Cloud vendor ranges |
| Artifacts | Paths, UA, headers, DNS names, MDM | 7 MCP paths; write tools advertised; fakecorp.* DNS |
| Questions analysts asked | Demo vs prod? Class? Who owns it? | Class peers? Managed endpoint? |
| Steps they took | Order of pivots in Slack | Wire → DNS → profile → class check → close |
| Outcome | What they closed / did | Close code + why |
| Open unknowns | What they never proved | Do not invent answers for these |

### 2.2 Teaching goal (one sentence)

Write the lesson the player should learn, e.g.:

> Cleartext MCP to a live security stack with write tools is high signal;
> corp-looking DNS/MDM can be “normal for the asset” and still not clear the
> incident; class traffic must be checked before BH Benign.

If you cannot state the lesson, you are not ready to build rooms.

### 2.3 Win condition first

Decide the **correct decision action** before writing narration:

- Close-code hunts (simplified set used in FAKE CORP): **True Positive**,
  **False Positive**, **BH Benign** — exactly one `correct: true`.
- Or containment vocabulary: Acknowledge / Isolate / Allow / Block / Escalate /
  Dismiss.

Every wrong option needs an honest `resultNote` that teaches why it is
plausible but wrong *here*.

**Rule:** the evidence trail must *earn* the win. If True Positive is
correct, class/demo sanctioning must be ruled out in a room — not left
ambiguous in a way that makes BH Benign equally good.

---

## 3. Obfuscate hard (do this before drafting copy)

Assume the Slack thread leaves the building. Scrub before any config text
exists.

| Real | Fiction |
| --- | --- |
| Company / brand | Invented org (`FAKE CORP`) |
| People / Slack handles | Never appear |
| Source IPs | New conference RFC1918 (e.g. `10.44.18.72`) |
| Hostnames / MACs / serials | Invented or omit |
| Product names (browser, MDM, IdP, vendors) | Generic or fictional |
| Real MCP / API paths | Renamed fictional paths |
| Screenshots / DNS lists | Paraphrase; do not paste real FQDNs |

**Hard obfuscation checklist**

- [ ] Grep the draft for real org strings, vendor names, people
- [ ] No “almost real” domains (`fox…` → use `fakecorp.example` style)
- [ ] Alert ids can be invented (`A-4418`); do not reuse prod ticket ids
- [ ] If a detail only identifies a real org and adds no lesson, drop it

---

## 4. Do not assume (epistemic hygiene)

Slack threads are full of leaps. The MUD must not smuggle them in as fact.

| Bad (assumes) | Better (what was observed) |
| --- | --- |
| “Not anonymous VPS infrastructure” | “Open endpoint on the conference network with MDM signals; provenance beyond that is not established here” |
| “Corporate laptop of X” | “Presents as managed FAKE CORP endpoint” |
| “Demo environment” without evidence | Either prove it in a room or leave it out |
| “Registration found no match, so hostile” | Registration may escalate later; if the hunt focuses on class search, **omit reg** and only say what class/SSID samples show |

**Author test:** for every sentence in `narration` / `evidence.detail`, ask
“Could a careful analyst swear this from the logs in this room?” If no,
rewrite or cut.

Wrong turns cost **time**, not truth. Ruled-out leads still get an evidence
chip (“DNS looks corp-normal — does not clear the exposure”).

---

## 5. Design the graph (normal → abnormal → decision)

Aim for **3–6 rooms**, soft timer **180s**, **one** `requiresEvidence` gate
before the decision.

Typical arc (FAKE CORP pattern):

```text
briefing
  → observed / alert surface          (what fired)
  → wire / HTTP / proxy               (what is abnormal on the wire)
  → DNS / identity-looking signals    (what can look “normal”)
  → device / asset profile            (context, not closure)
  → class / SSID / peer search        (sanctioned or not?)
  → decision (close codes / actions)
```

### Room rules

1. **Every non-decision node yields evidence** — no punishing empty rooms.
2. **Normal vs abnormal** should be explicit in copy: what would be fine for
   this asset class, and what still makes the incident.
3. **Class / sanctioned context** is its own room when BH Benign is a
   tempting wrong answer.
4. Gate the decision with `requiresEvidence: n` where `n` is reachable by
   visiting the main path (usually 3–4), not by visiting every side room.

Sketch exits on paper first. Every `exits[].to` must exist in `nodes`.

---

## 6. Write the config

### 6.1 Skeleton

```js
{
  id: 'kebab-case-stable-id',
  meta: {
    title: 'Sentence case title',
    briefing: 'Alert … Pivot … post the correct … Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: { /* see §7 */ },
  startNode: 'observed-logs',
  nodes: { /* … */ },
  endings: {
    win:  { title: '…', narration: '…' },
    lose: { title: 'Wrong close code', narration: '…' }
  }
}
```

### 6.2 Voice

- Third person, present tense
- **No “you”**
- Numbers first, nouns second
- No exclamation marks, no emoji
- Machine values stay machine-readable (IPs, path lists)

### 6.3 Decision node

```js
decision: {
  name: 'Close codes',
  tag: '[decision]',
  narration: 'Evidence is on the table: … One BH close code fits.',
  isDecision: true,
  actions: [
    { id: 'true-positive', label: 'True Positive', correct: true, resultNote: '…' },
    { id: 'false-positive', label: 'False Positive', resultNote: '…' },
    { id: 'bh-benign', label: 'BH Benign', resultNote: '…' }
  ]
}
```

Equal visual weight — the engine never styles the correct answer differently.

### 6.4 Where to ship

1. Replace or append in
   [`packages/web-server/static/threat-hunt-config.js`](../../packages/web-server/static/threat-hunt-config.js)
   (`window.THREAT_HUNTS` array). Today the UI mounts `hunts[0]` — a second
   hunt needs a picker before players can choose it.
2. Mirror into [`threat-hunt-config.js`](./threat-hunt-config.js) for the
   docs bundle if you maintain that copy.
3. Run: `npm test --workspace=@bhnoc/web-server -- threatHuntConfig`

---

## 7. ELI5 glossary (hover tooltips)

Add optional `glossary: { Term: 'Plain explanation.' }` on the hunt.

- Keys are matched **case-insensitively** in briefing, narration, evidence,
  endings, and matching close-code button labels.
- **Longer keys win** (put `BH close code` and `True Positive` in; short
  tokens like `IR` are fine if they do not false-match).
- Tips are ELI5: analogy + why it matters here. One or two sentences.
- Dotted underline = hover/focus for tip. Briefing should mention that.

Author pass: read the briefing aloud as a new hire; every stumble becomes a
glossary key.

---

## 8. Worked path (FAKE CORP cleartext MCP)

What the real thread roughly gave us → what the MUD kept:

| Slack | MUD choice |
| --- | --- |
| Cleartext MCP to a full security tool stack | `observed-logs` + `http-conn`; write access called out |
| Corp DNS / managed device vibes | `dns-logs` + `device-profile` as **context**, not proof of innocence |
| “Is this class / demo?” | `class-context` searches training VLAN / lab SSID peers — **no peers** |
| Registration side quest | **Left out** (can escalate in real ops; not this drill) |
| Real org / products / people | Hard-obfuscated to FAKE CORP + fictional MCP paths |
| Correct close | **True Positive** (live exposure + write tools + not sanctioned class) |

Lesson baked into rooms: corp-normal ≠ close; missing class peers ≠ “ignore”;
cleartext write-capable security MCP on the floor earns TP.

---

## 9. End-to-end checklist

Copy this for each new Slack→MUD hunt:

1. [ ] Worksheet: facts, lesson, win close code/action, unknowns list  
2. [ ] Obfuscation map filled; draft has zero real org/vendor/person strings  
3. [ ] No assumed facts (only what each room can support)  
4. [ ] 3–6 nodes; every non-decision node has evidence  
5. [ ] One evidence gate; decision has exactly one `correct: true`  
6. [ ] Wrong actions have teaching `resultNote`s  
7. [ ] Glossary covers jargon in briefing + nodes  
8. [ ] Voice pass (no “you”, no `!`, numbers first)  
9. [ ] Config in `THREAT_HUNTS`; contract tests green  
10. [ ] Play once cold: can a stranger finish under ~3 minutes and learn the lesson?

---

## 10. Common failure modes

| Failure | Fix |
| --- | --- |
| Player can justify two close codes | Add a room that kills the wrong one with evidence |
| Narration spoils the answer | Keep decision options parallel; teach in `resultNote` |
| Soft OPSEC leak | Harder obfuscation; drop vanity details |
| Glossary misses the briefing | Author glossary from briefing first, then nodes |
| Hunt feels like a novel | Cut rooms; three minutes is the product |
| “Registration / people” side plot | Escalate in real life; omit unless it is the lesson |

---

## 11. File map

| File | Role |
| --- | --- |
| `packages/web-server/static/threat-hunt-config.js` | Live hunt registry |
| `packages/web-server/static/threat-hunt.js` | Engine (glossary annotate + tooltips) |
| `packages/web-server/static/app.css` | `.hunt-term` / `.hunt-glossary-tip` |
| `packages/web-server/test/threatHuntConfig.test.ts` | Contract + glossary shape |
| `docs/threat-hunt-mud/ThreatHunt.d.ts` | Schema |
| `docs/threat-hunt-mud/threat-hunt-mud.md` | Shorter authoring reference |
| This memo | Slack → MUD procedure |

When in doubt: **facts from Slack, fiction for identity, evidence earns the
close, glossary carries the jargon, assumptions stay out of the narration.**

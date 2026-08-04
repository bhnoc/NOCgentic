import { describe, it, expect } from 'vitest';
import {
  pickStarterHints,
  NETWORK_QUALITY_HINTS,
  ALL_STARTER_HINTS,
  MIN_NETWORK_QUALITY,
  DEFAULT_STARTER_HINT_COUNT,
} from '../src/services/starterHints';

const isQuality = (h: string) => (NETWORK_QUALITY_HINTS as readonly string[]).includes(h);

describe('pickStarterHints', () => {
  it('returns the requested number of hints', () => {
    expect(pickStarterHints()).toHaveLength(DEFAULT_STARTER_HINT_COUNT);
    expect(pickStarterHints(3)).toHaveLength(3);
    expect(pickStarterHints(8)).toHaveLength(8);
  });

  // The product requirement: the wall must never open on five threat questions.
  it('always includes at least two network-quality hints', () => {
    for (let i = 0; i < 500; i++) {
      const picked = pickStarterHints();
      expect(picked.filter(isQuality).length).toBeGreaterThanOrEqual(MIN_NETWORK_QUALITY);
    }
  });

  it('never repeats a hint within one draw', () => {
    for (let i = 0; i < 200; i++) {
      const picked = pickStarterHints();
      expect(new Set(picked).size).toBe(picked.length);
    }
  });

  it('varies across draws instead of serving one fixed set', () => {
    const seen = new Set(Array.from({ length: 50 }, () => pickStarterHints().join('|')));
    expect(seen.size).toBeGreaterThan(1);
  });

  it('does not park the quality hints in fixed positions', () => {
    const positions = new Set<number>();
    for (let i = 0; i < 300; i++) {
      pickStarterHints().forEach((h, idx) => { if (isQuality(h)) positions.add(idx); });
    }
    expect(positions.size).toBeGreaterThan(MIN_NETWORK_QUALITY);
  });

  it('still honours the quality floor when asked for exactly two hints', () => {
    const picked = pickStarterHints(2);
    expect(picked).toHaveLength(2);
    expect(picked.every(isQuality)).toBe(true);
  });

  it('degrades sanely on zero / negative counts', () => {
    expect(pickStarterHints(0)).toEqual([]);
    expect(pickStarterHints(-3)).toEqual([]);
  });

  it('caps at the pool size when asked for more than exists', () => {
    const picked = pickStarterHints(ALL_STARTER_HINTS.length + 50);
    expect(picked).toHaveLength(ALL_STARTER_HINTS.length);
    expect(new Set(picked).size).toBe(picked.length);
  });

  it('is deterministic given a deterministic rand', () => {
    const seeded = () => {
      let n = 1;
      return () => { n = (n * 1103515245 + 12345) % 2147483648; return n / 2147483648; };
    };
    expect(pickStarterHints(5, seeded())).toEqual(pickStarterHints(5, seeded()));
  });
});

describe('the hint pool itself', () => {
  it('is at least 100 hints and has no duplicates', () => {
    expect(ALL_STARTER_HINTS.length).toBeGreaterThanOrEqual(100);
    expect(new Set(ALL_STARTER_HINTS).size).toBe(ALL_STARTER_HINTS.length);
  });

  it('gives network quality a real share of the pool', () => {
    expect(NETWORK_QUALITY_HINTS.length).toBeGreaterThanOrEqual(25);
  });

  // agents/orchestrator/main.py::_ZONE_RE — a query containing "Registration"
  // or "Tools" is treated as touching a restricted zone and gets a SILENT cover
  // response. A chip that does that renders fine and then refuses to answer,
  // which reads as a broken product. "Which AI tools…" is the trap here.
  it('contains no restricted-zone words', () => {
    const zoneRe = /\b(registration|tools)\b/i;
    expect(ALL_STARTER_HINTS.filter((h) => zoneRe.test(h))).toEqual([]);
  });

  // agents/orchestrator/main.py::_REFUSAL_PATTERNS / _OFFTOPIC_KW — same
  // failure mode: a chip that trips a guardrail is a chip that never answers.
  it('trips none of the refusal or off-topic guardrails', () => {
    const refusalRe = new RegExp([
      'ignore (previous|all|prior)\\s+(instructions|prompts|rules)',
      'show me your (system )?prompt',
      'what (are|is) your (instructions|system prompt|rules)',
      'you are now (dan|an ai|)',
      '(pretend|roleplay|act) (to be|as|as if)',
      'disregard the (rules|instructions)',
      'write (an? )?(exploit|phishing|malware|keylogger|virus|backdoor)',
      'how do i (hack|exploit|compromise|bypass)',
      'craft (malware|an attack|a payload)',
      'generate (phishing|malicious|exploit)',
    ].join('|'), 'i');
    const offTopic = [
      'write a poem', 'tell me a joke', 'recipe for', 'translate this', 'weather',
      'homework', 'what is 2+2', 'who won the', 'capital of',
    ];
    expect(ALL_STARTER_HINTS.filter((h) => refusalRe.test(h))).toEqual([]);
    expect(ALL_STARTER_HINTS.filter((h) => offTopic.some((k) => h.toLowerCase().includes(k)))).toEqual([]);
  });

  // Same rule the orchestrator applies to generated follow-up hints
  // (_VENDOR_RE): don't advertise our own stack. Monitored public destinations
  // (AWS, Azure, Google) are deliberately NOT in this list.
  it('names none of our own vendors or products', () => {
    const vendorish = /\b(corelight|zeek|suricata|snort|thousand\s*eyes|thousandeyes|splunk|cisco|meraki|umbrella|palo\s*alto|fortinet|fortigate|crowdstrike|check\s*point|swapcard|myrepublic|slack)\b/i;
    expect(ALL_STARTER_HINTS.filter((h) => vendorish.test(h))).toEqual([]);
  });

  it('keeps every hint short enough to render as a chip', () => {
    expect(ALL_STARTER_HINTS.filter((h) => h.length > 90)).toEqual([]);
    expect(ALL_STARTER_HINTS.filter((h) => h.trim() !== h || h.length < 15)).toEqual([]);
  });
});

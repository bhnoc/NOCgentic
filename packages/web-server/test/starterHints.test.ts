import { describe, it, expect } from 'vitest';
import {
  pickStarterHints,
  NETWORK_QUALITY_HINTS,
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
    const picked = pickStarterHints(999);
    expect(new Set(picked).size).toBe(picked.length);
    expect(picked.length).toBeGreaterThanOrEqual(NETWORK_QUALITY_HINTS.length);
  });

  it('is deterministic given a deterministic rand', () => {
    const seeded = () => {
      let n = 1;
      return () => { n = (n * 1103515245 + 12345) % 2147483648; return n / 2147483648; };
    };
    expect(pickStarterHints(5, seeded())).toEqual(pickStarterHints(5, seeded()));
  });

  // Same rule the orchestrator applies to LLM-generated follow-up hints: the
  // UI must not name vendors or products.
  it('names no vendors or products', () => {
    const vendorish = /\b(corelight|zeek|palo\s?alto|cisco|fortinet|crowdstrike|splunk|thousandeyes|arista|juniper|netscout|rsa)\b/i;
    const all = [...NETWORK_QUALITY_HINTS, ...pickStarterHints(999)];
    expect(all.filter((h) => vendorish.test(h))).toEqual([]);
  });
});

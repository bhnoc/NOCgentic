import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { alertCache, scrubString, type RawAlert } from '../src/services/alertCache';

function rawAlert(overrides: Partial<RawAlert> = {}): RawAlert {
  return {
    id: 'alert-abc',
    timestamp: '2026-07-20T00:00:00.000Z',
    severity: 'high',
    source: 'suricata',
    description: 'test alert',
    ...overrides,
  };
}

beforeEach(() => {
  // Drain any leftover queue and unfreeze between tests.
  alertCache.__setAthenaKilledForTest(false);
  while (alertCache.dequeue() !== null) {
    /* drain */
  }
});

describe('scrubString restricted-subnet scrub (sweep-4 lo-1)', () => {
  it('rewrites a restricted octet to the .69 decoy', () => {
    expect(scrubString('10.220.199.5')).toBe('10.220.69.5');
  });

  it('leaves a non-restricted 10.220.x address untouched', () => {
    expect(scrubString('10.220.42.5')).toBe('10.220.42.5');
  });
});

describe('scrubString zone-name scrub matches the orchestrator (drift check)', () => {
  it('scrubs the plural zone name "Tools"', () => {
    expect(scrubString('seen in the Tools zone')).toBe('seen in the internal zone');
  });

  it('scrubs "Registration" case-insensitively', () => {
    expect(scrubString('near the registration desk')).toBe('near the internal desk');
  });

  it('does NOT scrub the singular English word "tool" (e.g. "attack tool")', () => {
    // Drift regression: this copy of ZONE_RE had "Tools?" (optional plural),
    // which over-redacted the singular and diverged from
    // agents/orchestrator/main.py::_ZONE_RE / static/alertHints.js::ZONE_RE,
    // both of which match the plural zone name only.
    expect(scrubString('flagged as an attack tool')).toBe('flagged as an attack tool');
  });
});

describe('alertCache dequeue id-scrub (sweep-4 lo-1)', () => {
  it('scrubs a restricted-subnet IP embedded in the alert id', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'x|10.220.199.5|ts' }));

    const out = alertCache.dequeue();
    expect(out).not.toBeNull();
    // The restricted third octet (199) must not survive in the id.
    expect(out!.id).not.toContain('10.220.199.');
    expect(out!.id).toBe('x|10.220.69.5|ts');
  });

  it('scrubs restricted IPs in srcIp/dstIp too', () => {
    alertCache.__enqueueForTest(
      rawAlert({ srcIp: '10.220.199.5', dstIp: '10.220.150.9' }),
    );

    const out = alertCache.dequeue();
    expect(out!.srcIp).toBe('10.220.69.5');
    expect(out!.dstIp).toBe('10.220.69.9');
  });
});

describe('alertCache kill-freeze (sweep-4 cc-1)', () => {
  it('returns null (feed frozen) when athenaKilled is true', () => {
    alertCache.__enqueueForTest(rawAlert());
    alertCache.__setAthenaKilledForTest(true);

    expect(alertCache.dequeue()).toBeNull();
  });

  it('returns the alert when athenaKilled is false', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'live-1' }));
    alertCache.__setAthenaKilledForTest(false);

    const out = alertCache.dequeue();
    expect(out).not.toBeNull();
    expect(out!.id).toBe('live-1');
  });

  // Changed deliberately: this used to assert the queue survived a kill so the
  // feed could resume where it left off. Queued and emitted alerts ARE live
  // venue data sitting in this process, so "pull the plug" has to drop them —
  // otherwise the switch stops the refills and keeps the disclosures.
  it('drops queued alerts when the switch is thrown', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'queued-1' }));
    alertCache.__setAthenaKilledForTest(true);
    expect(alertCache.dequeue()).toBeNull();

    alertCache.__setAthenaKilledForTest(false);
    expect(alertCache.dequeue()).toBeNull();
  });

  it('drops already-emitted alerts and serves none to new clients', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'emitted-1' }));
    expect(alertCache.dequeue()).not.toBeNull();
    expect(alertCache.recentEmitted()).toHaveLength(1);

    alertCache.__setAthenaKilledForTest(true);
    // Both directions: the buffer is gone, and the accessor refuses anyway.
    expect(alertCache.__emittedCountForTest()).toBe(0);
    expect(alertCache.recentEmitted()).toEqual([]);
  });

  it('reports the kill state on the public status endpoint', () => {
    expect(alertCache.status().killed).toBe(false);
    alertCache.__setAthenaKilledForTest(true);
    expect(alertCache.status().killed).toBe(true);
  });
});

describe('alertCache kill-switch polling is sticky', () => {
  const realFetch = globalThis.fetch;
  const realToken = process.env.ADMIN_BEARER_TOKEN;
  const stubFetch = (impl: () => Promise<unknown>) => {
    globalThis.fetch = impl as unknown as typeof fetch;
  };

  beforeEach(() => {
    // Without a token the poll cannot verify anything and returns early.
    process.env.ADMIN_BEARER_TOKEN = 'test-admin-token';
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    if (realToken === undefined) delete process.env.ADMIN_BEARER_TOKEN;
    else process.env.ADMIN_BEARER_TOKEN = realToken;
    alertCache.__setAthenaKilledForTest(false);
  });

  const okResponse = (killed: boolean) =>
    ({ ok: true, status: 200, json: async () => ({ athena_hunter: killed }) });

  it('freezes on an observed kill and lifts on an observed restore', async () => {
    stubFetch(async () => okResponse(true));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(true);

    stubFetch(async () => okResponse(false));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(false);
  });

  // The regression this replaces: every failure path used to write `false`, so
  // whatever took the orchestrator down also un-pulled the plug.
  it.each([
    ['a transport error', async () => { throw new Error('ECONNREFUSED'); }],
    ['a 500', async () => ({ ok: false, status: 500, json: async () => ({}) })],
    ['a 401', async () => ({ ok: false, status: 401, json: async () => ({}) })],
  ])('stays killed through %s', async (_label, impl) => {
    stubFetch(async () => okResponse(true));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(true);

    stubFetch(impl as () => Promise<unknown>);
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(true);
    expect(alertCache.recentEmitted()).toEqual([]);
  });

  it('reports that the freeze is unwired until a poll succeeds', async () => {
    alertCache.__resetKillVerifiedForTest();
    stubFetch(async () => { throw new Error('orchestrator down since boot'); });
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killSwitchVerified).toBe(false);

    stubFetch(async () => okResponse(false));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killSwitchVerified).toBe(true);
  });

  it('does not freeze a healthy feed just because a check failed', async () => {
    stubFetch(async () => { throw new Error('orchestrator not up yet'); });
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(false);
  });

  it('leaves the state alone when no admin token is configured', async () => {
    stubFetch(async () => okResponse(true));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(true);

    delete process.env.ADMIN_BEARER_TOKEN;
    stubFetch(async () => okResponse(false));
    await alertCache.__refreshKillSwitchForTest();
    expect(alertCache.status().killed).toBe(true);
  });
});

describe('alertCache dequeue enriched fields', () => {
  it('passes through ports, uid, occurrences and maps observedAt from raw timestamp', () => {
    const observed = '2026-07-20T12:34:56.000Z';
    alertCache.__enqueueForTest(
      rawAlert({
        id: 'enriched-1',
        timestamp: observed,
        srcIp: '10.220.42.5',
        dstIp: '8.8.8.8',
        srcPort: 54321,
        dstPort: 443,
        uid: 'CAbCdEf123',
        occurrences: 7,
      }),
    );

    const before = Date.now();
    const out = alertCache.dequeue();
    const after = Date.now();

    expect(out).not.toBeNull();
    expect(out!.srcPort).toBe(54321);
    expect(out!.dstPort).toBe(443);
    expect(out!.uid).toBe('CAbCdEf123');
    expect(out!.occurrences).toBe(7);
    expect(out!.observedAt).toBe(observed);
    // Theatrical emit clock — restamped to approximately now, not Athena time.
    expect(out!.timestamp).not.toBe(observed);
    const emitMs = Date.parse(out!.timestamp);
    expect(emitMs).toBeGreaterThanOrEqual(before - 50);
    expect(emitMs).toBeLessThanOrEqual(after + 50);
  });

  it('scrubs restricted zone names in network', () => {
    alertCache.__enqueueForTest(
      rawAlert({ id: 'net-1', network: 'Registration VLAN' }),
    );

    const out = alertCache.dequeue();
    expect(out!.network).toBe('internal VLAN');
  });

  it('omits empty optional enrichment fields', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'bare-1' }));

    const out = alertCache.dequeue();
    expect(out!.srcPort).toBeUndefined();
    expect(out!.dstPort).toBeUndefined();
    expect(out!.uid).toBeUndefined();
    expect(out!.network).toBeUndefined();
    expect(out!.occurrences).toBeUndefined();
    expect(out!.observedAt).toBe('2026-07-20T00:00:00.000Z');
  });
});

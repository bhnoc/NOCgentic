import { describe, it, expect, beforeEach } from 'vitest';
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

  it('leaves the queue intact while frozen (resumes after unkill)', () => {
    alertCache.__enqueueForTest(rawAlert({ id: 'queued-1' }));
    alertCache.__setAthenaKilledForTest(true);
    expect(alertCache.dequeue()).toBeNull();

    alertCache.__setAthenaKilledForTest(false);
    const out = alertCache.dequeue();
    expect(out!.id).toBe('queued-1');
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

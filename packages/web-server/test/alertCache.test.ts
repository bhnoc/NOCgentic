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

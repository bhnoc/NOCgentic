import { describe, it, expect, beforeEach } from 'vitest';
import {
  bearerMatches,
  classifyEnvelope,
  markSeen,
  resetSeenFindings,
  evictStaleFindings,
  getSeenFindingsSize,
  type ManifoldEnvelope,
} from '../src/api/manifold';

function threat(overrides: Record<string, unknown> = {}): ManifoldEnvelope {
  return {
    id: 'envelope-1',
    type: 'threat.created',
    version: '1',
    occurred_at: '2026-08-03T11:42:17.000000Z',
    data: {
      id: 'finding-1',
      profile_id: 'EXFIL-010',
      title: 'Cloud metadata access',
      severity: 'high',
      trace_id: '8f3c1e02-0000-4000-8000-000000000000',
      ...overrides,
    },
  } as ManifoldEnvelope;
}

beforeEach(() => {
  resetSeenFindings();
});

describe('bearerMatches', () => {
  it('accepts the exact token', () => {
    expect(bearerMatches('Bearer s3cret', 's3cret')).toBe(true);
  });

  it('is case-insensitive on the scheme but not the token', () => {
    expect(bearerMatches('bearer s3cret', 's3cret')).toBe(true);
    expect(bearerMatches('Bearer S3CRET', 's3cret')).toBe(false);
  });

  it('rejects a wrong token, including a prefix of the real one', () => {
    expect(bearerMatches('Bearer wrong', 's3cret')).toBe(false);
    // Length mismatch must not throw (hashing gives both sides 32 bytes).
    expect(bearerMatches('Bearer s3c', 's3cret')).toBe(false);
    expect(bearerMatches('Bearer s3cretlonger', 's3cret')).toBe(false);
  });

  it('rejects a missing or malformed header', () => {
    expect(bearerMatches(undefined, 's3cret')).toBe(false);
    expect(bearerMatches('s3cret', 's3cret')).toBe(false);       // no scheme
    expect(bearerMatches('Basic s3cret', 's3cret')).toBe(false);
    expect(bearerMatches('Bearer   ', 's3cret')).toBe(false);
  });

  it('FAILS CLOSED when no token is configured', () => {
    // An unset MANIFOLD_WEBHOOK_TOKEN must not mean "accept anything" -- this
    // path is exempt from the nginx origin lock, so the token is its only gate.
    expect(bearerMatches('Bearer anything', '')).toBe(false);
    expect(bearerMatches(undefined, '')).toBe(false);
  });
});

describe('classifyEnvelope', () => {
  it('quarantines a high-severity threat carrying a trace', () => {
    const decision = classifyEnvelope(threat());
    expect(decision.action).toBe('quarantine');
    if (decision.action !== 'quarantine') return;
    expect(decision.traceId).toBe('8f3c1e02-0000-4000-8000-000000000000');
    expect(decision.reason).toContain('EXFIL-010');
  });

  it('quarantines critical too', () => {
    expect(classifyEnvelope(threat({ severity: 'critical' })).action).toBe('quarantine');
  });

  it('ignores low and medium severities', () => {
    for (const severity of ['low', 'medium']) {
      const d = classifyEnvelope(threat({ severity }));
      expect(d.action).toBe('ignore');
      if (d.action === 'ignore') expect(d.why).toBe(`severity:${severity}`);
    }
  });

  it('ignores a threat with no trace_id (nothing to contain)', () => {
    const noTrace = threat();
    delete (noTrace.data as Record<string, unknown>).trace_id;
    const d = classifyEnvelope(noTrace);
    expect(d.action).toBe('ignore');
    if (d.action === 'ignore') expect(d.why).toBe('no_trace_id');
  });

  it('ignores non-threat resource types', () => {
    // risk.created is fleet-wide and carries no trace; violation/audit are not
    // subscribed for containment. All are accepted, none contain.
    for (const type of ['risk.created', 'violation.created', 'audit_log.created']) {
      const d = classifyEnvelope({ ...threat(), type } as ManifoldEnvelope);
      expect(d.action).toBe('ignore');
      if (d.action === 'ignore') expect(d.why).toBe(`type:${type}`);
    }
  });

  it('routes on the envelope type, NOT the removed data.finding_type', () => {
    // Manifold dropped data.finding_type; the envelope type is the only
    // discriminator. A stale finding_type must not resurrect containment.
    const stale = { ...threat(), type: 'risk.created' } as ManifoldEnvelope;
    (stale.data as Record<string, unknown>).finding_type = 'threat';
    expect(classifyEnvelope(stale).action).toBe('ignore');
  });

  it('tolerates unknown additive fields', () => {
    // Manifold adds resource fields without bumping version; rejecting them
    // would 400, which it treats as permanent, dropping the finding forever.
    const extended = threat({ some_new_field: { nested: true } });
    (extended as Record<string, unknown>).another_top_level = 'x';
    expect(classifyEnvelope(extended).action).toBe('quarantine');
  });

  it('ignores data that lacks the required id', () => {
    const bad = threat();
    delete (bad.data as Record<string, unknown>).id;
    const d = classifyEnvelope(bad);
    expect(d.action).toBe('ignore');
    if (d.action === 'ignore') expect(d.why).toBe('unparseable_data');
  });

  it('treats severity case-insensitively', () => {
    expect(classifyEnvelope(threat({ severity: 'HIGH' })).action).toBe('quarantine');
  });
});

describe('idempotency on data.id', () => {
  it('is true first time, false on repeat', () => {
    expect(markSeen('finding-1')).toBe(true);
    expect(markSeen('finding-1')).toBe(false);
  });

  it('dedups on data.id even though the envelope id changes per attempt', () => {
    // Documented behaviour: a retry re-sends the same logical finding with a
    // NEW envelope id, so the envelope id is useless as a dedup key.
    expect(markSeen('finding-1')).toBe(true);
    expect(markSeen('finding-1')).toBe(false);
    expect(markSeen('finding-2')).toBe(true);
  });

  it('evicts entries past the TTL so the map cannot grow forever', () => {
    const t0 = Date.now();
    expect(markSeen('old-finding', t0)).toBe(true);
    const beyondTtl = t0 + 25 * 60 * 60 * 1000; // > 24h
    expect(evictStaleFindings(beyondTtl)).toBeGreaterThan(0);
    // Evicted, so it reads as new again.
    expect(markSeen('old-finding', beyondTtl)).toBe(true);
  });

  it('keeps entries inside the TTL', () => {
    const t0 = Date.now();
    markSeen('recent', t0);
    evictStaleFindings(t0 + 60 * 1000);
    expect(markSeen('recent', t0 + 60 * 1000)).toBe(false);
  });

  it('enforces DEDUP_MAX so the map never settles above the cap', () => {
    const t0 = Date.now();
    for (let i = 0; i < 10005; i++) {
      markSeen(`finding-cap-${i}`, t0);
    }
    expect(getSeenFindingsSize()).toBeLessThanOrEqual(10000);
  });
});

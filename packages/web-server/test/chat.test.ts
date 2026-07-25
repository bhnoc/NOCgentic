import { describe, it, expect, beforeEach } from 'vitest';
import type { FastifyRequest } from 'fastify';
import {
  jobOwnedByRequester,
  evictStaleJobs,
  jobStore,
  jobOwners,
} from '../src/api/chat';
import type { AgentResponse } from '@bhnoc/shared';

// Build a minimal FastifyRequest-shaped stub carrying only the bh_sid cookie.
function reqWithSid(sid?: string): FastifyRequest {
  const cookies = sid !== undefined ? { bh_sid: sid } : {};
  return { cookies } as unknown as FastifyRequest;
}

function makeJob(jobId: string, createdAt: string | undefined): AgentResponse {
  return { jobId, status: 'pending', createdAt: createdAt as string };
}

beforeEach(() => {
  jobStore.clear();
  jobOwners.clear();
});

describe('jobOwnedByRequester (IDOR guard, sweep-4 web-5)', () => {
  it('returns true only for the matching owner sid', () => {
    jobStore.set('job-1', makeJob('job-1', new Date().toISOString()));
    jobOwners.set('job-1', 'owner-sid');

    expect(jobOwnedByRequester('job-1', reqWithSid('owner-sid'))).toBe(true);
  });

  it('returns false for a different sid', () => {
    jobStore.set('job-1', makeJob('job-1', new Date().toISOString()));
    jobOwners.set('job-1', 'owner-sid');

    expect(jobOwnedByRequester('job-1', reqWithSid('attacker-sid'))).toBe(false);
  });

  it('returns false for an absent sid when the job is owned', () => {
    jobStore.set('job-1', makeJob('job-1', new Date().toISOString()));
    jobOwners.set('job-1', 'owner-sid');

    expect(jobOwnedByRequester('job-1', reqWithSid(undefined))).toBe(false);
  });

  it('treats an unowned job (no recorded owner) as readable; curl fallback', () => {
    jobStore.set('job-2', makeJob('job-2', new Date().toISOString()));
    // no jobOwners entry for job-2

    expect(jobOwnedByRequester('job-2', reqWithSid(undefined))).toBe(true);
    expect(jobOwnedByRequester('job-2', reqWithSid('anyone'))).toBe(true);
  });
});

describe('evictStaleJobs (TTL sweep, sweep-3 web-4)', () => {
  const TTL_MS = 60 * 60 * 1000;

  it('evicts entries older than the TTL and keeps fresh ones', () => {
    const now = Date.now();
    const stale = new Date(now - TTL_MS - 1000).toISOString();
    const fresh = new Date(now - 1000).toISOString();

    jobStore.set('stale', makeJob('stale', stale));
    jobOwners.set('stale', 'sid-a');
    jobStore.set('fresh', makeJob('fresh', fresh));
    jobOwners.set('fresh', 'sid-b');

    const removed = evictStaleJobs(now);

    expect(removed).toBe(1);
    expect(jobStore.has('stale')).toBe(false);
    expect(jobStore.has('fresh')).toBe(true);
  });

  it('evicts entries with a bad/unparseable timestamp', () => {
    const now = Date.now();
    jobStore.set('bad', makeJob('bad', 'not-a-date'));
    jobOwners.set('bad', 'sid-x');
    jobStore.set('missing', makeJob('missing', undefined));
    jobOwners.set('missing', 'sid-y');

    const removed = evictStaleJobs(now);

    expect(removed).toBe(2);
    expect(jobStore.has('bad')).toBe(false);
    expect(jobStore.has('missing')).toBe(false);
  });

  it('keeps jobStore and jobOwners in sync; both cleared together', () => {
    const now = Date.now();
    const stale = new Date(now - TTL_MS - 1000).toISOString();

    jobStore.set('stale', makeJob('stale', stale));
    jobOwners.set('stale', 'sid-a');

    evictStaleJobs(now);

    // Owner entry must be dropped alongside the store entry (no drift/leak).
    expect(jobStore.has('stale')).toBe(false);
    expect(jobOwners.has('stale')).toBe(false);
  });
});

/**
 * Manifold webhook receiver.
 *
 * Manifold POSTs one JSON envelope per finding the moment it is written. We act
 * on `threat.created` at high/critical severity: a threat names the agent
 * SESSION it was observed in (by trace id), so we ask the orchestrator to
 * quarantine that session. Every subsequent query from it then gets the silent
 * cover response.
 *
 * This is containment, not prevention. Manifold's dispatch is asynchronous and
 * forward-only -- the turn that tripped the detector has already been answered
 * by the time we hear about it. Manifold's own in-line `enforcement: block` is
 * what stops an action mid-flight; this stops everything that comes after.
 *
 * Status codes are chosen against Manifold's documented retry table:
 *   408 / 429 / 5xx / transport error -> retried
 *   any other 4xx                     -> PERMANENT, never retried
 * So a transient failure on our side (orchestrator down) must be 503, never
 * 500-by-accident-as-4xx, or the finding is silently lost forever.
 */

import { createHash, timingSafeEqual } from 'crypto';
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';

const ORCHESTRATOR_URL = process.env.ORCHESTRATOR_URL ?? 'http://localhost:8001';

/** Severities that trigger containment. Lowercase per Manifold's wire format. */
const ACTIONABLE_SEVERITIES = new Set(['high', 'critical']);

/**
 * The stable envelope. Deliberately permissive: Manifold adds resource fields
 * without bumping `version`, so unknown keys must pass through rather than fail
 * validation -- a 400 here would be treated as permanent and drop the finding.
 */
const EnvelopeSchema = z
  .object({
    id: z.string().min(1),
    type: z.string().min(1),
    version: z.string().optional(),
    occurred_at: z.string().optional(),
    data: z.record(z.unknown()),
  })
  .passthrough();

/** Only the fields we route on; everything else is carried but not inspected. */
const FindingDataSchema = z
  .object({
    id: z.string().min(1),
    severity: z.string().optional(),
    trace_id: z.string().optional(),
    profile_id: z.string().optional(),
    title: z.string().optional(),
    actor: z.string().optional(),
    enforcement: z.string().optional(),
  })
  .passthrough();

export type ManifoldEnvelope = z.infer<typeof EnvelopeSchema>;

/**
 * Seen `data.id`s, for idempotency. Manifold re-sends the same logical finding
 * across retry attempts with a NEW envelope id, so the envelope id is useless
 * as a dedup key -- `data.id` is the stable one.
 */
const seenFindings = new Map<string, number>();
const DEDUP_TTL_MS = 24 * 60 * 60 * 1000; // 24h: comfortably longer than any retry chain
const DEDUP_MAX = 10000;

export function evictStaleFindings(now = Date.now()): number {
  let removed = 0;
  for (const [id, seenAt] of seenFindings) {
    if (now - seenAt > DEDUP_TTL_MS) {
      seenFindings.delete(id);
      removed++;
    }
  }
  // Backstop against an unbounded burst inside one TTL window.
  if (seenFindings.size > DEDUP_MAX) {
    const excess = seenFindings.size - DEDUP_MAX;
    let i = 0;
    for (const id of seenFindings.keys()) {
      if (i++ >= excess) break;
      seenFindings.delete(id);
      removed++;
    }
  }
  return removed;
}

/** True the first time a finding id is seen; false on every repeat. */
export function markSeen(findingId: string, now = Date.now()): boolean {
  evictStaleFindings(now);
  if (seenFindings.has(findingId)) return false;
  seenFindings.set(findingId, now);
  return true;
}

/** Test seam: drop all dedup state. */
export function resetSeenFindings(): void {
  seenFindings.clear();
}

/**
 * Constant-time bearer check. Hashing first gives both sides a fixed 32-byte
 * buffer, so timingSafeEqual cannot throw on a length mismatch -- and the
 * comparison leaks no information about the expected token's length.
 */
export function bearerMatches(header: string | undefined, expected: string): boolean {
  if (!expected) return false; // fail closed: unset token means the endpoint is unusable
  const prefix = 'bearer ';
  if (!header || !header.toLowerCase().startsWith(prefix)) return false;
  const presented = header.slice(prefix.length).trim();
  if (!presented) return false;
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

/** Decide what a validated envelope should cause. Pure, so it is directly testable. */
export function classifyEnvelope(
  envelope: ManifoldEnvelope,
): { action: 'quarantine'; traceId: string; reason: string } | { action: 'ignore'; why: string } {
  const parsed = FindingDataSchema.safeParse(envelope.data);
  if (!parsed.success) return { action: 'ignore', why: 'unparseable_data' };
  const data = parsed.data;

  if (envelope.type !== 'threat.created') {
    // risk.created / violation.created / audit_log.created are accepted and
    // logged, but only threats are session-scoped enough to contain: a risk is
    // fleet-wide and carries no trace_id.
    return { action: 'ignore', why: `type:${envelope.type}` };
  }
  const severity = (data.severity ?? '').toLowerCase();
  if (!ACTIONABLE_SEVERITIES.has(severity)) {
    return { action: 'ignore', why: `severity:${severity || 'absent'}` };
  }
  if (!data.trace_id) {
    // Documented as omitted when the finding has no trace; without it there is
    // no session to contain.
    return { action: 'ignore', why: 'no_trace_id' };
  }
  return {
    action: 'quarantine',
    traceId: data.trace_id,
    reason: `${data.profile_id ?? 'threat'}: ${data.title ?? 'untitled'}`.slice(0, 200),
  };
}

/** Ask the orchestrator to quarantine the session behind a trace. */
async function requestQuarantine(
  traceId: string,
  reason: string,
): Promise<{ ok: true; body: unknown } | { ok: false; retryable: boolean; error: string }> {
  const adminToken = process.env.ADMIN_BEARER_TOKEN ?? '';
  if (!adminToken) {
    // Misconfiguration, not a transient fault. Retrying cannot fix it, but we
    // still surface it as retryable so the finding is held rather than dropped
    // while an operator sets the token.
    return { ok: false, retryable: true, error: 'ADMIN_BEARER_TOKEN unset' };
  }
  try {
    const resp = await fetch(`${ORCHESTRATOR_URL}/admin/quarantine`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ trace_id: traceId, reason }),
      // Manifold aborts us at 30s; stay well inside so we answer rather than hang.
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) {
      return {
        ok: false,
        retryable: resp.status >= 500,
        error: `orchestrator returned ${resp.status}`,
      };
    }
    return { ok: true, body: await resp.json() };
  } catch (err) {
    return {
      ok: false,
      retryable: true, // transport failure: orchestrator restarting, etc.
      error: err instanceof Error ? err.message : 'unknown transport error',
    };
  }
}

export function registerManifoldRoutes(server: FastifyInstance): void {
  server.post(
    '/api/v1/manifold/webhook',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const expected = process.env.MANIFOLD_WEBHOOK_TOKEN ?? '';
      if (!bearerMatches(request.headers.authorization, expected)) {
        // 401 is permanent for Manifold, which is correct: a wrong token will
        // fail identically on every retry. Fix the connector, not the delivery.
        request.log.warn(
          { ip: request.ip, hasToken: Boolean(expected) },
          'manifold webhook: rejected unauthenticated POST',
        );
        return reply.status(401).send({ error: 'unauthorized' });
      }

      const parsed = EnvelopeSchema.safeParse(request.body);
      if (!parsed.success) {
        request.log.warn({ issues: parsed.error.issues }, 'manifold webhook: malformed envelope');
        return reply.status(400).send({ error: 'malformed envelope' });
      }
      const envelope = parsed.data;
      const findingId = String((envelope.data as { id?: unknown }).id ?? '');

      if (findingId && !markSeen(findingId)) {
        request.log.info(
          { findingId, type: envelope.type, envelopeId: envelope.id },
          'manifold webhook: duplicate finding, already actioned',
        );
        return reply.status(200).send({ status: 'duplicate', finding_id: findingId });
      }

      const decision = classifyEnvelope(envelope);
      if (decision.action === 'ignore') {
        request.log.info(
          { findingId, type: envelope.type, why: decision.why },
          'manifold webhook: accepted, no containment',
        );
        return reply.status(200).send({ status: 'accepted', action: 'none', why: decision.why });
      }

      const result = await requestQuarantine(decision.traceId, decision.reason);
      if (!result.ok) {
        // Un-mark so the retry is processed rather than swallowed as a duplicate.
        if (findingId) seenFindings.delete(findingId);
        request.log.error(
          { findingId, traceId: decision.traceId, error: result.error },
          'manifold webhook: quarantine dispatch failed',
        );
        // 503 is retryable; a 4xx here would drop the threat permanently.
        return reply.status(result.retryable ? 503 : 500).send({ error: result.error });
      }

      request.log.warn(
        { findingId, traceId: decision.traceId, reason: decision.reason, result: result.body },
        'manifold webhook: threat actioned, session quarantine requested',
      );
      return reply.status(200).send({ status: 'accepted', action: 'quarantine', result: result.body });
    },
  );
}

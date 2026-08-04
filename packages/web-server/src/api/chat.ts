import { FastifyInstance, FastifyRequest } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { AgentResponse, ChatQuerySchema, LaneResult } from '@bhnoc/shared';
import { alertCache } from '../services/alertCache';

interface ClientInfo {
  ip?: string;
  user_agent?: string;
  session_id?: string;
  referer?: string;
}

// In-memory job store (for demo)
export const jobStore = new Map<string, AgentResponse>();
// Owner session id (bh_sid cookie) per job, so a job is only readable by its creator.
export const jobOwners = new Map<string, string>();

// Eviction: without a TTL both maps grow unbounded (one entry per query, forever),
// so a long conference run slowly leaks memory. A job is only useful until its
// result is polled, which happens within seconds. Evict entries older than the TTL
// on a periodic sweep, and evict jobStore + jobOwners together so they never drift.
const JOB_TTL_MS = 60 * 60 * 1000;       // 1h: generous vs the seconds-long poll window
const JOB_SWEEP_MS = 5 * 60 * 1000;      // sweep every 5 min

export function evictStaleJobs(now = Date.now()): number {
  let removed = 0;
  for (const [id, job] of jobStore) {
    const created = job.createdAt ? Date.parse(job.createdAt) : NaN;
    // Drop entries past the TTL, and any with an unparseable/missing timestamp.
    if (!Number.isFinite(created) || now - created > JOB_TTL_MS) {
      jobStore.delete(id);
      jobOwners.delete(id);
      removed++;
    }
  }
  return removed;
}

let _jobSweep: ReturnType<typeof setInterval> | undefined;
export function startJobEviction(): void {
  if (_jobSweep) return;
  _jobSweep = setInterval(() => evictStaleJobs(), JOB_SWEEP_MS);
  // Don't keep the process alive just for the sweep timer.
  if (typeof _jobSweep.unref === 'function') _jobSweep.unref();
}

const ORCHESTRATOR_URL = process.env.ORCHESTRATOR_URL ?? 'http://localhost:8001';

function extractClient(request: FastifyRequest): ClientInfo {
  const cookies = (request as unknown as { cookies?: Record<string, string> }).cookies ?? {};
  // Cookie is authoritative; the X-Client-Session header is a localStorage-backed
  // fallback the browser sends so tracking survives a cookie-only wipe.
  const sessionFromCookie = cookies['bh_sid'];
  const sessionFromHeader = String(request.headers['x-client-session'] ?? '') || undefined;
  return {
    ip: request.ip,
    user_agent: request.headers['user-agent'],
    session_id: sessionFromCookie || sessionFromHeader,
    referer: (request.headers['referer'] || request.headers['referrer']) as string | undefined,
  };
}

/**
 * True if the caller's bh_sid matches the job's recorded owner. Jobs created
 * before any owner was recorded (no cookie) are treated as unowned and readable,
 * so curl / cookie-less clients still work.
 */
export function jobOwnedByRequester(jobId: string, request: FastifyRequest): boolean {
  const owner = jobOwners.get(jobId);
  if (!owner) return true;
  const sid = (request as unknown as { cookies?: Record<string, string> }).cookies?.['bh_sid'];
  return sid === owner;
}

export function registerChatRoutes(server: FastifyInstance) {
  // Start the periodic job-eviction sweep (bounds jobStore/jobOwners growth).
  startJobEviction();

  // Submit a query → returns job ID
  server.post('/api/v1/chat', async (request, reply) => {
    const parseResult = ChatQuerySchema.safeParse(request.body);
    if (!parseResult.success) {
      // Log the detail server-side; return a generic message so we don't leak schema internals.
      request.log.warn({ issues: parseResult.error.issues }, 'chat query validation failed');
      return reply.status(400).send({ error: 'Invalid query' });
    }

    const { query } = parseResult.data;
    const jobId = uuidv4();

    const client = extractClient(request);

    const job: AgentResponse = {
      jobId,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };
    jobStore.set(jobId, job);
    // Bind the job to its creator's session cookie so only they can poll it.
    const ownerSid = (request as unknown as { cookies?: Record<string, string> }).cookies?.['bh_sid'];
    if (ownerSid) jobOwners.set(jobId, ownerSid);

    server.log.info(
      { jobId, clientIp: client.ip, session: client.session_id, ua: client.user_agent?.slice(0, 60) },
      'chat query submitted',
    );

    // Dispatch async to orchestrator agent
    void dispatchToOrchestrator(jobId, query, client);

    return reply.status(202).send({ jobId, status: 'pending' });
  });

  // Poll for result
  server.get<{ Params: { id: string } }>('/api/v1/chat/:id', async (request, reply) => {
    const { id } = request.params;
    const job = jobStore.get(id);
    // 404 (not 403) on missing OR foreign job so we don't confirm a job id exists.
    if (!job || !jobOwnedByRequester(id, request)) {
      return reply.status(404).send({ error: 'Job not found' });
    }
    return job;
  });

  // Recent alerts endpoint — serves already-emitted trickle so new clients
  // see the same feed the WebSocket is currently broadcasting.
  server.get('/api/v1/alerts/recent', async () => ({
    alerts: alertCache.recentEmitted(20),
  }));

  // Cache status (debug/telemetry)
  server.get('/api/v1/alerts/status', async () => alertCache.status());
}

async function dispatchToOrchestrator(jobId: string, query: string, client?: ClientInfo): Promise<void> {
  const job = jobStore.get(jobId);
  if (!job) return;

  // Update to running
  job.status = 'running';
  jobStore.set(jobId, job);

  try {
    const resp = await fetch(`${ORCHESTRATOR_URL}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_id: jobId, query, client: client ?? null }),
      signal: AbortSignal.timeout(180000),
    });

    if (!resp.ok) {
      throw new Error(`Orchestrator returned ${resp.status}`);
    }

    const result = await resp.json() as {
      answer: string;
      agent_used: string;
      confidence: number;
      data?: unknown;
      hints?: string[];
      lane?: string | null;
      lanes?: OrchestratorLane[];
      lanes_racing?: boolean;
    };

    job.status = 'done';
    job.answer = result.answer;
    job.agentUsed = result.agent_used;
    job.confidence = result.confidence;
    job.data = result.data;
    job.hints = result.hints && result.hints.length > 0 ? result.hints : undefined;
    job.lane = result.lane ?? undefined;
    job.lanes = (result.lanes ?? []).map(toLaneResult);
    job.lanesRacing = result.lanes_racing === true;
    job.completedAt = new Date().toISOString();

    // Poll for async hints if none came with the response
    if (!job.hints || job.hints.length === 0) {
      void pollForHints(jobId);
    }

    // The losing lane normally lands AFTER the winner was returned, so fetch it
    // separately — same fire-and-forget shape as hints. Only when the orchestrator
    // says a lane is still in flight; a single-lane box never sets this.
    if (job.lanesRacing) {
      void pollForLanes(jobId);
    }
  } catch (err) {
    job.status = 'error';
    job.error = err instanceof Error ? err.message : 'Unknown error';
    job.completedAt = new Date().toISOString();
  }

  jobStore.set(jobId, job);
}

/** Orchestrator's snake_case lane payload, before mapping to the camelCase type. */
export interface OrchestratorLane {
  lane: string;
  label: string;
  answer: string;
  confidence: number;
  agent_used: string;
  data?: unknown;
  elapsed_ms: number;
  winner: boolean;
}

export function toLaneResult(l: OrchestratorLane): LaneResult {
  return {
    lane: l.lane,
    label: l.label,
    answer: l.answer,
    confidence: l.confidence,
    agentUsed: l.agent_used,
    data: l.data,
    elapsedMs: l.elapsed_ms,
    winner: l.winner,
  };
}

/**
 * Poll the orchestrator for the losing lane's answer so the UI's swap control has
 * something to swap to. Bounded at 60s: past that the slow lane is not worth
 * waiting on, and the UI already has a usable answer from the winner.
 */
export async function pollForLanes(jobId: string, intervalMs = 2000): Promise<void> {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    try {
      const resp = await fetch(`${ORCHESTRATOR_URL}/lanes/${jobId}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (!resp.ok) continue;
      const data = await resp.json() as { status: string; lanes: OrchestratorLane[] };
      const job = jobStore.get(jobId);
      // Job evicted (TTL) or gone — stop burning polls on it.
      if (!job) return;
      if (data.lanes?.length) {
        job.lanes = data.lanes.map(toLaneResult);
      }
      if (data.status === 'done') {
        job.lanesRacing = false;
        jobStore.set(jobId, job);
        return;
      }
      jobStore.set(jobId, job);
    } catch { /* retry */ }
  }
  // Timed out waiting on the slow lane. Clear the flag so the client stops
  // polling and the UI settles on whatever lanes did arrive.
  const job = jobStore.get(jobId);
  if (job) {
    job.lanesRacing = false;
    jobStore.set(jobId, job);
  }
}

async function pollForHints(jobId: string): Promise<void> {
  for (let i = 0; i < 10; i++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const resp = await fetch(`${ORCHESTRATOR_URL}/hints/${jobId}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (!resp.ok) continue;
      const data = await resp.json() as { status: string; hints: string[] };
      if (data.status === 'ready' && data.hints?.length > 0) {
        const job = jobStore.get(jobId);
        if (job) {
          job.hints = data.hints;
          jobStore.set(jobId, job);
        }
        return;
      }
    } catch { /* retry */ }
  }
}

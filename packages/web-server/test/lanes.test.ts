import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { jobStore, pollForLanes, toLaneResult, type OrchestratorLane } from '../src/api/chat';
import type { AgentResponse } from '@bhnoc/shared';

/**
 * Lane-race plumbing on the BFF side.
 *
 * The losing lane lands AFTER the orchestrator has already returned the winner,
 * so the web-server fetches it separately (same shape as async hints). What
 * matters here: the poll stops when it should, it never resurrects an evicted
 * job, and it always clears lanesRacing -- a stuck flag makes the browser poll
 * for the full 60s on every query for a lane that is never coming.
 */

function lane(name: string, over: Partial<OrchestratorLane> = {}): OrchestratorLane {
  return {
    lane: name,
    label: name === 'cloud' ? 'Cloud (Gemini)' : 'Local (AQLight)',
    answer: `answer-${name}`,
    confidence: 0.8,
    agent_used: 'athena-hunter',
    data: { llm_metrics: { model: name === 'cloud' ? 'gemini-3.5-flash-lite' : 'AQLight' } },
    elapsed_ms: name === 'cloud' ? 1200 : 3400,
    winner: name === 'cloud',
    ...over,
  };
}

function racingJob(jobId: string): AgentResponse {
  return {
    jobId,
    status: 'done',
    createdAt: new Date().toISOString(),
    answer: 'answer-cloud',
    lane: 'cloud',
    lanes: [toLaneResult(lane('cloud'))],
    lanesRacing: true,
  };
}

const origFetch = globalThis.fetch;

beforeEach(() => {
  jobStore.clear();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  globalThis.fetch = origFetch;
});

describe('toLaneResult (snake_case -> camelCase boundary)', () => {
  it('maps every field the UI reads', () => {
    const r = toLaneResult(lane('local'));
    expect(r).toMatchObject({
      lane: 'local',
      label: 'Local (AQLight)',
      answer: 'answer-local',
      confidence: 0.8,
      agentUsed: 'athena-hunter',   // was agent_used
      elapsedMs: 3400,              // was elapsed_ms
      winner: false,
    });
  });

  it('preserves llm_metrics inside data so the UI can show the per-lane model', () => {
    const r = toLaneResult(lane('local'));
    expect((r.data as { llm_metrics: { model: string } }).llm_metrics.model)
      .toBe('AQLight');
  });
});

describe('pollForLanes', () => {
  it('records the second lane and stops once the orchestrator says done', async () => {
    jobStore.set('j1', racingJob('j1'));
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'done', lanes: [lane('cloud'), lane('local')] }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const done = pollForLanes('j1', 1);
    await vi.advanceTimersByTimeAsync(10);
    await done;

    const job = jobStore.get('j1')!;
    expect(job.lanes).toHaveLength(2);
    expect(job.lanes!.map(l => l.lane)).toEqual(['cloud', 'local']);
    expect(job.lanesRacing).toBe(false);
    // Stopped on the first "done" rather than burning the full 30 attempts.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps polling while status is racing, then settles', async () => {
    jobStore.set('j2', racingJob('j2'));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'racing', lanes: [lane('cloud')] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'racing', lanes: [lane('cloud')] }) })
      .mockResolvedValue({ ok: true, json: async () => ({ status: 'done', lanes: [lane('cloud'), lane('local')] }) });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const done = pollForLanes('j2', 1);
    await vi.advanceTimersByTimeAsync(20);
    await done;

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(jobStore.get('j2')!.lanes).toHaveLength(2);
    expect(jobStore.get('j2')!.lanesRacing).toBe(false);
  });

  it('clears lanesRacing when the slow lane never arrives', async () => {
    // A lane that hangs past the poll budget must not leave the client polling
    // forever on every subsequent render.
    jobStore.set('j3', racingJob('j3'));
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'racing', lanes: [lane('cloud')] }),
    }) as unknown as typeof fetch;

    const done = pollForLanes('j3', 1);
    await vi.advanceTimersByTimeAsync(100);
    await done;

    expect(jobStore.get('j3')!.lanesRacing).toBe(false);
    expect(jobStore.get('j3')!.lanes).toHaveLength(1);
  });

  it('gives up immediately if the job was evicted, and does not recreate it', async () => {
    // The TTL sweep can evict mid-poll; writing the job back would resurrect an
    // entry the eviction just reclaimed, re-introducing the unbounded growth.
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'done', lanes: [lane('cloud'), lane('local')] }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const done = pollForLanes('gone', 1);
    await vi.advanceTimersByTimeAsync(10);
    await done;

    expect(jobStore.has('gone')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('survives a transient orchestrator error and keeps polling', async () => {
    jobStore.set('j4', racingJob('j4'));
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValue({ ok: true, json: async () => ({ status: 'done', lanes: [lane('cloud'), lane('local')] }) });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const done = pollForLanes('j4', 1);
    await vi.advanceTimersByTimeAsync(20);
    await done;

    expect(jobStore.get('j4')!.lanes).toHaveLength(2);
    expect(jobStore.get('j4')!.lanesRacing).toBe(false);
  });

  it('does not wipe existing lanes when a poll returns an empty list', async () => {
    jobStore.set('j5', racingJob('j5'));
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'done', lanes: [] }),
    }) as unknown as typeof fetch;

    const done = pollForLanes('j5', 1);
    await vi.advanceTimersByTimeAsync(10);
    await done;

    // The winner recorded at response time survives.
    expect(jobStore.get('j5')!.lanes).toHaveLength(1);
    expect(jobStore.get('j5')!.lanesRacing).toBe(false);
  });
});

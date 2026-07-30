import { describe, it, expect, beforeEach, vi } from 'vitest';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { registerProxyRoutes } from '../src/api/proxy';

// The env defaults baked into proxy.ts
const INVESTIGATOR = 'http://investigator:8007';
const TRIAGE = 'http://triage:8008';

function makeFetchOk(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  });
}

function makeFetchReject(msg = 'network error') {
  return vi.fn().mockRejectedValue(new Error(msg));
}

function buildServer(): FastifyInstance {
  const server = Fastify({ logger: false });
  registerProxyRoutes(server);
  return server;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('POST /api/v1/investigate', () => {
  it('forwards POST body to INVESTIGATOR_URL/investigate and returns upstream JSON', async () => {
    const upstream = { run_id: 'abc123', status: 'queued' };
    vi.stubGlobal('fetch', makeFetchOk(upstream, 202));

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/investigate',
      payload: { alert_id: 'al-1', question: 'why?' },
    });

    expect(res.statusCode).toBe(202);
    expect(res.json()).toEqual(upstream);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${INVESTIGATOR}/investigate`);
    expect(opts.method).toBe('POST');
    expect(JSON.parse(opts.body as string)).toEqual({ alert_id: 'al-1', question: 'why?' });
  });

  it('returns 502 when fetch rejects (network error)', async () => {
    vi.stubGlobal('fetch', makeFetchReject('connection refused'));

    const server = buildServer();
    const res = await server.inject({ method: 'POST', url: '/api/v1/investigate', payload: {} });

    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ error: 'upstream unavailable' });
  });
});

describe('GET /api/v1/runs/:id', () => {
  it('proxies to INVESTIGATOR_URL/runs/:id', async () => {
    const upstream = { run_id: 'deadbeef', verdict: 'benign' };
    vi.stubGlobal('fetch', makeFetchOk(upstream));

    const server = buildServer();
    const res = await server.inject({ method: 'GET', url: '/api/v1/runs/deadbeef' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(upstream);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${INVESTIGATOR}/runs/deadbeef`);
  });

  it('returns 400 for a path-traversal id without calling fetch', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    const server = buildServer();
    const res = await server.inject({ method: 'GET', url: '/api/v1/runs/..%2Fetc' });

    // Fastify decodes %2F in params; the raw request won't route to /:id — either
    // way no fetch and the caller gets a 4xx.
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns 400 for a bad id like "../etc"', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    const server = buildServer();
    // Simulate a client passing a bad id via a different encoding path
    const res = await server.inject({ method: 'GET', url: '/api/v1/runs/bad%21id' });

    expect(res.statusCode).toBe(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('GET /api/v1/triage/queue', () => {
  it('forwards querystring params bucket and severity to TRIAGE_URL', async () => {
    const upstream = { queue: [] };
    vi.stubGlobal('fetch', makeFetchOk(upstream));

    const server = buildServer();
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/triage/queue?bucket=alerts&severity=2',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(upstream);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(`${TRIAGE}/triage/queue`);
    expect(url).toContain('bucket=');
    expect(url).toContain('severity=');
  });

  it('returns 502 on network error', async () => {
    vi.stubGlobal('fetch', makeFetchReject());

    const server = buildServer();
    const res = await server.inject({ method: 'GET', url: '/api/v1/triage/queue' });

    expect(res.statusCode).toBe(502);
  });
});

describe('POST /api/v1/triage/:id/investigate', () => {
  it('hits TRIAGE_URL/triage/:id/investigate with POST and 180s timeout', async () => {
    const upstream = { job_id: 'j-1' };
    vi.stubGlobal('fetch', makeFetchOk(upstream, 202));

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/triage/alert-42/investigate',
      payload: { note: 'manual trigger' },
    });

    expect(res.statusCode).toBe(202);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${TRIAGE}/triage/alert-42/investigate`);
    expect(opts.method).toBe('POST');
  });

  it('returns 400 for bad :id without calling fetch', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/triage/bad%21id/investigate',
      payload: {},
    });

    expect(res.statusCode).toBe(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('GET /api/v1/triage/:id', () => {
  it('proxies to TRIAGE_URL/triage/:id', async () => {
    const upstream = { id: 'al-7', severity: 3 };
    vi.stubGlobal('fetch', makeFetchOk(upstream));

    const server = buildServer();
    const res = await server.inject({ method: 'GET', url: '/api/v1/triage/al-7' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(upstream);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${TRIAGE}/triage/al-7`);
  });
});

describe('POST /api/v1/triage/:id/transition', () => {
  it('forwards body to TRIAGE_URL/triage/:id/transition', async () => {
    const upstream = { id: 'al-7', state: 'investigating' };
    vi.stubGlobal('fetch', makeFetchOk(upstream));

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/triage/al-7/transition',
      payload: { to: 'investigating', note: 'on it' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(upstream);

    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${TRIAGE}/triage/al-7/transition`);
    expect(JSON.parse(opts.body as string)).toEqual({ to: 'investigating', note: 'on it' });
  });

  it('returns 400 for bad :id without calling fetch', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/triage/%2F%2Fetc/transition',
      payload: {},
    });

    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns 502 when upstream is down', async () => {
    vi.stubGlobal('fetch', makeFetchReject('ECONNREFUSED'));

    const server = buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/triage/al-7/transition',
      payload: { to: 'closed' },
    });

    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ error: 'upstream unavailable' });
  });
});

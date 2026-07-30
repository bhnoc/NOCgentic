import { FastifyInstance } from 'fastify';

const INVESTIGATOR_URL = process.env.INVESTIGATOR_URL ?? 'http://investigator:8007';
const TRIAGE_URL = process.env.TRIAGE_URL ?? 'http://triage:8008';
// ROOT_CAUSE_URL is reserved for future direct routing; /runs/:id proxies to INVESTIGATOR_URL
// because both services write to the same agent_runs table.
const ROOT_CAUSE_URL = process.env.ROOT_CAUSE_URL ?? 'http://root-cause:8006';

// Matches UUID, hex, and alphanumeric ids up to 128 chars.
const SAFE_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;

interface ProxyResult {
  status: number;
  payload: unknown;
}

async function proxyJson(
  server: FastifyInstance,
  url: string,
  method: string,
  body?: unknown,
  timeoutMs = 15000,
): Promise<ProxyResult> {
  try {
    const resp = await fetch(url, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    let payload: unknown;
    try {
      payload = await resp.json();
    } catch {
      payload = { error: 'upstream returned non-JSON' };
    }
    return { status: resp.status, payload };
  } catch (e) {
    server.log.error({ err: e, url }, 'proxy upstream fetch failed');
    return { status: 502, payload: { error: 'upstream unavailable', detail: String(e) } };
  }
}

export function registerProxyRoutes(server: FastifyInstance): void {
  // POST /api/v1/investigate → investigator /investigate (slow path, 180 s)
  server.post('/api/v1/investigate', async (request, reply) => {
    const { status, payload } = await proxyJson(
      server,
      `${INVESTIGATOR_URL}/investigate`,
      'POST',
      request.body,
      180000,
    );
    return reply.status(status).send(payload);
  });

  // GET /api/v1/runs/:id → investigator /runs/:id
  // Both investigator and root-cause write to the same agent_runs table, so either
  // service can answer; we pick investigator for simplicity.
  server.get<{ Params: { id: string } }>('/api/v1/runs/:id', async (request, reply) => {
    const { id } = request.params;
    if (!SAFE_ID_RE.test(id)) {
      return reply.status(400).send({ error: 'invalid id' });
    }
    const { status, payload } = await proxyJson(
      server,
      `${INVESTIGATOR_URL}/runs/${id}`,
      'GET',
      undefined,
      15000,
    );
    return reply.status(status).send(payload);
  });

  // GET /api/v1/triage/queue → triage /triage/queue (forward bucket + severity querystring)
  server.get<{ Querystring: { bucket?: string; severity?: string } }>(
    '/api/v1/triage/queue',
    async (request, reply) => {
      const { bucket, severity } = request.query;
      const qs = new URLSearchParams();
      if (bucket !== undefined) qs.set('bucket', encodeURIComponent(bucket));
      if (severity !== undefined) qs.set('severity', encodeURIComponent(severity));
      const qStr = qs.toString();
      const url = `${TRIAGE_URL}/triage/queue${qStr ? `?${qStr}` : ''}`;
      const { status, payload } = await proxyJson(server, url, 'GET', undefined, 15000);
      return reply.status(status).send(payload);
    },
  );

  // POST /api/v1/triage/:id/investigate → triage /triage/:id/investigate (slow path, 180 s)
  server.post<{ Params: { id: string } }>(
    '/api/v1/triage/:id/investigate',
    async (request, reply) => {
      const { id } = request.params;
      if (!SAFE_ID_RE.test(id)) {
        return reply.status(400).send({ error: 'invalid id' });
      }
      const { status, payload } = await proxyJson(
        server,
        `${TRIAGE_URL}/triage/${id}/investigate`,
        'POST',
        request.body,
        180000,
      );
      return reply.status(status).send(payload);
    },
  );

  // GET /api/v1/triage/:id → triage /triage/:id
  server.get<{ Params: { id: string } }>('/api/v1/triage/:id', async (request, reply) => {
    const { id } = request.params;
    if (!SAFE_ID_RE.test(id)) {
      return reply.status(400).send({ error: 'invalid id' });
    }
    const { status, payload } = await proxyJson(
      server,
      `${TRIAGE_URL}/triage/${id}`,
      'GET',
      undefined,
      15000,
    );
    return reply.status(status).send(payload);
  });

  // POST /api/v1/triage/:id/transition → triage /triage/:id/transition (body passthrough)
  server.post<{ Params: { id: string } }>(
    '/api/v1/triage/:id/transition',
    async (request, reply) => {
      const { id } = request.params;
      if (!SAFE_ID_RE.test(id)) {
        return reply.status(400).send({ error: 'invalid id' });
      }
      const { status, payload } = await proxyJson(
        server,
        `${TRIAGE_URL}/triage/${id}/transition`,
        'POST',
        request.body,
        15000,
      );
      return reply.status(status).send(payload);
    },
  );
}

// Export for reference in tests / future direct-route usage.
export { ROOT_CAUSE_URL };

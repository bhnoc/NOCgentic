import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import Fastify from 'fastify';
import { registerReportIssueRoutes } from '../src/api/report-issue';

const VALID_JPEG_DATA_URL = 'data:image/jpeg;base64,/9j/4AAQSkZJRg==';

function buildServer() {
  const server = Fastify();
  registerReportIssueRoutes(server);
  return server;
}

describe('POST /api/v1/report-issue', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async () => new Response(JSON.stringify({ status: 'received' }), { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('accepts a note + screenshot and forwards to the orchestrator', async () => {
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: 'chip text overflows the card', image: VALID_JPEG_DATA_URL, view: 'chat' },
    });

    expect(resp.statusCode).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/report-issue');
    const body = JSON.parse(init.body as string);
    expect(body.note).toBe('chip text overflows the card');
    expect(body.image).toBe(VALID_JPEG_DATA_URL);
    expect(body.view).toBe('chat');
  });

  it('accepts a note-only report (screenshot capture failed client-side)', async () => {
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: 'hunt timeline never revealed step 3', view: 'hunt' },
    });

    expect(resp.statusCode).toBe(202);
  });

  it('rejects an empty report (no note, no image)', async () => {
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: '', view: 'chat' },
    });

    expect(resp.statusCode).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an image that is not a data URL', async () => {
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: 'x', image: 'https://evil.example/not-a-data-url' },
    });

    expect(resp.statusCode).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an unknown view value', async () => {
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: 'x', view: 'admin' },
    });

    expect(resp.statusCode).toBe(400);
  });

  it('returns 502 when the orchestrator upload fails', async () => {
    fetchMock.mockImplementation(async () => new Response('boom', { status: 500 }));
    const server = buildServer();
    const resp = await server.inject({
      method: 'POST',
      url: '/api/v1/report-issue',
      payload: { note: 'x', view: 'chat' },
    });

    expect(resp.statusCode).toBe(502);
  });
});

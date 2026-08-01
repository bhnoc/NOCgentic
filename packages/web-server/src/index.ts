import Fastify from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyWebsocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import fastifyCookie from '@fastify/cookie';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { registerChatRoutes } from './api/chat';
import { alertCache } from './services/alertCache';
import {
  SECURITY_HEADERS,
  rateLimitKeyGenerator,
  rateLimitErrorResponse,
} from './security/httpSecurity';

const PORT = parseInt(process.env.PORT ?? '3000', 10);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsClients = new Set<any>();

const SESSION_COOKIE = 'bh_sid';
const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const ALLOWED_WS_ORIGIN = process.env.ALLOWED_ORIGIN ?? 'https://nocgentic.bhnoc.com';

async function main() {
  // trustProxy honors X-Forwarded-For from nginx so request.ip is the real client.
  const server = Fastify({ logger: true, trustProxy: true });

  await server.register(fastifyCookie);

  // Ensure every request carries a stable bh_sid session cookie.
  server.addHook('onRequest', async (req, reply) => {
    const existing = (req as unknown as { cookies: Record<string, string> }).cookies?.[SESSION_COOKIE];
    if (!existing) {
      const sid = uuidv4();
      reply.setCookie(SESSION_COOKIE, sid, {
        path: '/',
        maxAge: SESSION_MAX_AGE,
        httpOnly: true,   // not readable from JS; the client uses its own localStorage id
        sameSite: 'lax',
        secure: true,
      });
      // Make it available to handlers on this same request too.
      (req as unknown as { cookies: Record<string, string> }).cookies[SESSION_COOKIE] = sid;
    }
  });

  // Baseline security headers on every response (hand-rolled; no helmet dep).
  server.addHook('onRequest', async (_req, reply) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      reply.header(name, value);
    }
  });

  // Rate limiting: generous for demo, tight on POST (actual queries)
  await server.register(fastifyRateLimit, {
    max: 120,
    timeWindow: '1 minute',
    // Key on nginx's X-Real-IP, which nginx sets to $remote_addr and OVERWRITES
    // on every request (nginx-ssl.conf). trustProxy makes request.ip come from the
    // client-appendable left-most X-Forwarded-For, so a fresh XFF per request would
    // otherwise mint a new bucket and bypass the limit entirely. X-Real-IP can't be
    // spoofed past the edge. Fall back to request.ip only if the header is absent.
    keyGenerator: rateLimitKeyGenerator,
    allowList: (req) => {
      // Exempt health checks and GET polling endpoints from rate limiting
      if (req.url === '/health') return true;
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/chat/')) return true;
      if (req.url === '/ws') return true;
      return false;
    },
    errorResponseBuilder: rateLimitErrorResponse,
  });

  // WebSocket support
  await server.register(fastifyWebsocket);

  // Static files
  await server.register(fastifyStatic, {
    root: path.join(__dirname, '../static'),
    prefix: '/',
  });

  // Chat API routes
  registerChatRoutes(server);

  // WebSocket endpoint for real-time updates (server pushes the shared alert feed).
  // @fastify/websocket v11 (required by fastify 5) passes the WebSocket DIRECTLY
  // as the first argument. v8 passed a wrapper whose `.socket` held it. Note this
  // does NOT fail typecheck, because wsClients is Set<any> and the old wrapper
  // access typed through: it would have broken at runtime, silently dropping the
  // origin check and the alert feed.
  server.get('/ws', { websocket: true }, (socket, request) => {
    // Reject cross-site WebSocket handshakes. Same-origin and cookie-less clients
    // (curl, no Origin header) are allowed; a foreign Origin is closed with 1008.
    const origin = request.headers.origin;
    if (origin && origin !== ALLOWED_WS_ORIGIN) {
      socket.close(1008, 'origin not allowed');
      return;
    }
    wsClients.add(socket);
    // Inbound messages are ignored: job results are delivered by HTTP polling,
    // not over this socket. This endpoint is broadcast-only (alert feed).
    socket.on('close', () => { wsClients.delete(socket); });
  });

  // Server-level alert trickle: one timer broadcasts the next alert to all
  // connected clients so every tab sees the same live stream.
  const trickleNext = () => {
    const delay = alertCache.pacingMs();
    setTimeout(() => {
      if (wsClients.size > 0) {
        const alert = alertCache.dequeue();
        if (alert) {
          const payload = JSON.stringify({ type: 'alert_feed', alerts: [alert] });
          for (const sock of wsClients) {
            if (sock.readyState === 1) {
              try { sock.send(payload); } catch { /* client gone */ }
            }
          }
        }
      }
      trickleNext();
    }, delay);
  };
  trickleNext();

  // Health check
  server.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

  // Public event-edition branding for the UI. Display only — single source of
  // truth is EVENT_EDITION (nation + year, e.g. "USA 2026"); "Black Hat" is the
  // static wrapper. Never tie system config (S3 prefixes, IAM) to this.
  const EVENT_LABEL = `Black Hat ${(process.env.EVENT_EDITION ?? 'USA 2026').trim()}`;
  server.get('/api/v1/config', async () => ({ eventLabel: EVENT_LABEL }));

  // Start the Athena-backed alert cache refresh loop
  alertCache.start();

  await server.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`BHNOCgentic web server running on port ${PORT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

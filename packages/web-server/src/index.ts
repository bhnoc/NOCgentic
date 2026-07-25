import Fastify from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyWebsocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import fastifyCookie from '@fastify/cookie';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { registerChatRoutes } from './api/chat';
import { alertCache } from './services/alertCache';

const PORT = parseInt(process.env.PORT ?? '3000', 10);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsClients = new Set<any>();

const SESSION_COOKIE = 'bh_sid';
const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const ALLOWED_WS_ORIGIN = process.env.ALLOWED_ORIGIN ?? 'https://aing.bhnoc.com';

// Matches a single well-formed IPv4 or IPv6 address (no lists, no whitespace).
// Used to decide whether a client-appendable X-Real-IP header is trustworthy as
// a rate-limit key (see keyGenerator below).
const SINGLE_IP_RE = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[0-9a-fA-F:]+$/;

// Content-Security-Policy for the served UI. The page uses an inline <style>,
// an inline <script>, and inline onclick handlers, so 'unsafe-inline' is
// required for style-src and script-src (acceptable: the UI is first-party and
// static). Google Fonts is the only external origin (stylesheet + font files).
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "connect-src 'self' ws: wss:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

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
    reply.header('Content-Security-Policy', CSP);
    reply.header('X-Frame-Options', 'DENY');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
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
    keyGenerator: (req) => {
      // Defense-in-depth: nginx OVERWRITES X-Real-IP at the edge, so behind the
      // proxy this is always a single trusted client IP. But a direct hit to the
      // container (bypassing nginx / SSRF) lets an attacker rotate X-Real-IP to
      // mint unlimited buckets. So only trust it when it's a single well-formed
      // IP; a list ("a, b") or garbage falls back to req.ip. The edge remains the
      // primary control -- this just denies the trivial direct-hit bypass.
      const header = req.headers['x-real-ip'];
      const realIp = (Array.isArray(header) ? header[0] : header)?.trim();
      const isSingleIp = !!realIp && SINGLE_IP_RE.test(realIp);
      return isSingleIp ? realIp : req.ip;
    },
    allowList: (req) => {
      // Exempt health checks and GET polling endpoints from rate limiting
      if (req.url === '/health') return true;
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/chat/')) return true;
      if (req.url === '/ws') return true;
      return false;
    },
    // Must carry statusCode: @fastify/rate-limit hands this object to Fastify's
    // error path, and without an explicit statusCode Fastify defaults it to 500
    // (which breaks client backoff and trips the ">1% API error rate" alarm).
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please wait before sending more queries.',
    }),
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
  server.get('/ws', { websocket: true }, (connection, request) => {
    // Reject cross-site WebSocket handshakes. Same-origin and cookie-less clients
    // (curl, no Origin header) are allowed; a foreign Origin is closed with 1008.
    const origin = request.headers.origin;
    if (origin && origin !== ALLOWED_WS_ORIGIN) {
      connection.socket.close(1008, 'origin not allowed');
      return;
    }
    wsClients.add(connection.socket);
    // Inbound messages are ignored: job results are delivered by HTTP polling,
    // not over this socket. This endpoint is broadcast-only (alert feed).
    connection.socket.on('close', () => { wsClients.delete(connection.socket); });
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

  // Start the Athena-backed alert cache refresh loop
  alertCache.start();

  await server.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`BHNOCgentic web server running on port ${PORT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

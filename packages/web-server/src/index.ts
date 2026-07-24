import Fastify from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyWebsocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import fastifyCookie from '@fastify/cookie';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { registerChatRoutes, jobStore } from './api/chat';
import { alertCache } from './services/alertCache';

const PORT = parseInt(process.env.PORT ?? '3000', 10);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const wsClients = new Set<any>();

const SESSION_COOKIE = 'bh_sid';
const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

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
        httpOnly: false,  // readable so debug tooling can surface it if needed
        sameSite: 'lax',
        secure: true,
      });
      // Make it available to handlers on this same request too.
      (req as unknown as { cookies: Record<string, string> }).cookies[SESSION_COOKIE] = sid;
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
    keyGenerator: (req) => {
      const realIp = req.headers['x-real-ip'];
      return (Array.isArray(realIp) ? realIp[0] : realIp) || req.ip;
    },
    allowList: (req) => {
      // Exempt health checks and GET polling endpoints from rate limiting
      if (req.url === '/health') return true;
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/chat/')) return true;
      if (req.url === '/ws') return true;
      return false;
    },
    errorResponseBuilder: () => ({
      error: 'Rate limit exceeded. Please wait before sending more queries.',
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

  // WebSocket endpoint for real-time updates
  server.get('/ws', { websocket: true }, (connection) => {
    wsClients.add(connection.socket);
    connection.socket.on('message', (message: Buffer) => {
      const text = message.toString();
      try {
        const msg = JSON.parse(text) as { type: string; jobId?: string };
        if (msg.type === 'subscribe' && msg.jobId) {
          // Client subscribes to job updates
          const job = jobStore.get(msg.jobId);
          if (job) {
            connection.socket.send(JSON.stringify({ type: 'job_update', job }));
          }
        }
      } catch {
        // Ignore malformed messages
      }
    });
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

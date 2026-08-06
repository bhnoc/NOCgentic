import { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

// Screenshots are base64 data URLs; a 1x 1920x1080 JPEG at q0.7 lands well under
// this, but retina/4K captures can be several MB of base64. Bounded generously
// above the default Fastify bodyLimit (which this route overrides) so a normal
// screenshot never gets rejected, without accepting an unbounded upload.
const MAX_IMAGE_DATA_URL_LEN = 8_000_000;
const MAX_NOTE_LEN = 1000;

const ReportIssueSchema = z.object({
  note: z.string().max(MAX_NOTE_LEN).default(''),
  image: z
    .string()
    .max(MAX_IMAGE_DATA_URL_LEN)
    .regex(/^data:image\/(png|jpeg);base64,/, 'image must be a png/jpeg data URL')
    .optional(),
  view: z.enum(['chat', 'hunt']).default('chat'),
  path: z.string().max(200).optional(),
});

const ORCHESTRATOR_URL = process.env.ORCHESTRATOR_URL ?? 'http://localhost:8001';

function extractClient(request: FastifyRequest) {
  const cookies = (request as unknown as { cookies?: Record<string, string> }).cookies ?? {};
  const sessionFromCookie = cookies['bh_sid'];
  const sessionFromHeader = String(request.headers['x-client-session'] ?? '') || undefined;
  return {
    ip: request.ip,
    user_agent: request.headers['user-agent'],
    session_id: sessionFromCookie || sessionFromHeader,
    referer: (request.headers['referer'] || request.headers['referrer']) as string | undefined,
  };
}

export function registerReportIssueRoutes(server: FastifyInstance) {
  server.post(
    '/api/v1/report-issue',
    // Default Fastify bodyLimit (1MB) is too small for a screenshot data URL.
    // Own rate-limit bucket, tighter than the shared 120/min: unlike a cheap
    // GET, each call carries up to an ~8MB body and triggers an S3 write.
    {
      bodyLimit: MAX_IMAGE_DATA_URL_LEN + 100_000,
      config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const parseResult = ReportIssueSchema.safeParse(request.body);
      if (!parseResult.success) {
        request.log.warn({ issues: parseResult.error.issues }, 'report-issue validation failed');
        return reply.status(400).send({ error: 'Invalid report' });
      }

      const { note, image, view, path } = parseResult.data;
      if (!note && !image) {
        return reply.status(400).send({ error: 'Empty report' });
      }

      const client = extractClient(request);

      try {
        const resp = await fetch(`${ORCHESTRATOR_URL}/report-issue`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ note, image, view, path, client }),
          signal: AbortSignal.timeout(20000),
        });

        if (!resp.ok) {
          throw new Error(`orchestrator returned ${resp.status}`);
        }

        return reply.status(202).send({ status: 'received' });
      } catch (err) {
        request.log.warn({ err: err instanceof Error ? err.message : err }, 'report-issue upload failed');
        return reply.status(502).send({ error: 'Could not deliver report' });
      }
    },
  );
}

/**
 * /api/v1/catalog — the threat hunting catalog for the Playbooks tab and the
 * alert popup. Read-only, no auth beyond what the rest of the UI has: it is
 * the same public reference material the analyst can open from the tab.
 *
 *   GET /api/v1/catalog              index: summaries, facets, alert-topic links
 *   GET /api/v1/catalog/search       ?q=&section=&technique=&source=&limit=
 *   GET /api/v1/catalog/match        ?behavior=&patterns=a,b&topic=
 *   GET /api/v1/catalog/:id          one entry with its markdown body
 *
 * Nothing here reaches an agent or a model (see services/huntCatalog.ts).
 */
import { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import {
  CATALOG_SECTIONS,
  facets,
  getCatalog,
  playbooksForFinding,
  searchCatalog,
  toSummary,
} from '../services/huntCatalog';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const TECH_RE = /^T\d{4}(?:\.\d{3})?$/i;

const SearchQuery = z.object({
  q: z.string().trim().max(200).optional(),
  section: z.enum(CATALOG_SECTIONS).optional(),
  technique: z.string().trim().regex(TECH_RE).optional(),
  source: z.string().trim().min(1).max(40).regex(/^[A-Za-z0-9._ -]+$/).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
});

const MatchQuery = z.object({
  behavior: z.string().trim().min(1).max(40).regex(/^[a-z0-9-]+$/i).optional(),
  patterns: z.string().trim().max(200).optional(),
  topic: z.string().trim().min(1).max(40).regex(/^[A-Za-z0-9 -]+$/).optional(),
});

const IdParams = z.object({ id: z.string().regex(ID_RE) });

function unavailable(reply: FastifyReply) {
  return reply.code(503).send({ error: 'hunt catalog unavailable' });
}

export function registerCatalogRoutes(server: FastifyInstance) {
  server.get('/api/v1/catalog', async (_req, reply) => {
    const cat = getCatalog();
    if (!cat) return unavailable(reply);
    return {
      loadedAt: cat.loadedAt,
      count: cat.entries.length,
      facets: facets(cat),
      links: { alertTopics: cat.map.alert_topics },
      entries: cat.entries.map(toSummary),
    };
  });

  server.get('/api/v1/catalog/search', async (req, reply) => {
    const cat = getCatalog();
    if (!cat) return unavailable(reply);
    const parsed = SearchQuery.safeParse(req.query ?? {});
    if (!parsed.success) {
      return reply.code(400).send({ error: 'invalid search', issues: parsed.error.issues.map((i) => i.message) });
    }
    const hits = searchCatalog(cat, parsed.data);
    return { query: parsed.data, total: hits.length, hits };
  });

  server.get('/api/v1/catalog/match', async (req, reply) => {
    const cat = getCatalog();
    if (!cat) return unavailable(reply);
    const parsed = MatchQuery.safeParse(req.query ?? {});
    if (!parsed.success) {
      return reply.code(400).send({ error: 'invalid match', issues: parsed.error.issues.map((i) => i.message) });
    }
    const patterns = (parsed.data.patterns ?? '')
      .split(',')
      .map((p) => p.trim())
      .filter((p) => /^[a-z0-9_-]{1,40}$/i.test(p));
    const playbooks = playbooksForFinding(cat, {
      behavior: parsed.data.behavior,
      patterns,
      topic: parsed.data.topic,
    });
    return { playbooks };
  });

  server.get('/api/v1/catalog/:id', async (req, reply) => {
    const cat = getCatalog();
    if (!cat) return unavailable(reply);
    const parsed = IdParams.safeParse(req.params ?? {});
    if (!parsed.success) return reply.code(400).send({ error: 'invalid id' });
    const entry = cat.byId.get(parsed.data.id) ?? cat.byId.get(parsed.data.id.toUpperCase());
    if (!entry) return reply.code(404).send({ error: 'not found' });
    return { ...toSummary(entry), body: entry.body };
  });
}

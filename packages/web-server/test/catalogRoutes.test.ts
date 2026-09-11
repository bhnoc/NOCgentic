import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { registerCatalogRoutes } from '../src/api/catalog';
import { resetCatalogCache } from '../src/services/huntCatalog';

let server: FastifyInstance;

beforeAll(async () => {
  resetCatalogCache();
  server = Fastify();
  registerCatalogRoutes(server);
  await server.ready();
});

afterAll(async () => {
  await server.close();
});

describe('GET /api/v1/catalog', () => {
  it('returns summaries, facets and the alert-topic links without bodies', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/catalog' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.count).toBe(33);
    expect(body.entries).toHaveLength(33);
    expect(body.entries[0]).not.toHaveProperty('body');
    expect(body.entries[0]).not.toHaveProperty('terms');
    expect(body.facets.sections[0]).toEqual({ id: 'playbooks', count: 16 });
    expect(body.links.alertTopics['port scan']).toEqual(['PB-12']);
  });
});

describe('GET /api/v1/catalog/search', () => {
  it('searches by keyword', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/catalog/search?q=kerberoasting' });
    expect(res.statusCode).toBe(200);
    expect(res.json().hits[0].id).toBe('PB-05');
  });

  it('rejects a malformed technique or an out-of-range limit', async () => {
    expect((await server.inject({ url: '/api/v1/catalog/search?technique=DROP' })).statusCode).toBe(400);
    expect((await server.inject({ url: '/api/v1/catalog/search?limit=999' })).statusCode).toBe(400);
    expect((await server.inject({ url: '/api/v1/catalog/search?section=secrets' })).statusCode).toBe(400);
    expect((await server.inject({ url: '/api/v1/catalog/search?source=%3Cscript%3E' })).statusCode).toBe(400);
  });

  it('caps the query length', async () => {
    const res = await server.inject({ url: '/api/v1/catalog/search?q=' + 'a'.repeat(201) });
    expect(res.statusCode).toBe(400);
  });
});

describe('GET /api/v1/catalog/match', () => {
  it('maps zeek-detector output to playbooks', async () => {
    const res = await server.inject({
      url: '/api/v1/catalog/match?behavior=agentic-orchestration&patterns=agentic_loop,context_reset',
    });
    expect(res.statusCode).toBe(200);
    const ids = res.json().playbooks.map((p: { id: string }) => p.id);
    expect(ids).toContain('PB-01');
    expect(ids.length).toBeLessThanOrEqual(4);
  });

  it('maps an alert topic and drops junk pattern tokens', async () => {
    const res = await server.inject({ url: '/api/v1/catalog/match?topic=lateral%20movement&patterns=..%2F,agentic_loop' });
    expect(res.statusCode).toBe(200);
    const ids = res.json().playbooks.map((p: { id: string }) => p.id);
    expect(ids[0]).toBe('PB-01'); // agentic_loop survived, "../" did not
    expect(ids).toContain('PB-03');
  });

  it('rejects a topic with characters outside the label alphabet', async () => {
    expect((await server.inject({ url: '/api/v1/catalog/match?topic=%3Cb%3E' })).statusCode).toBe(400);
  });
});

describe('GET /api/v1/catalog/:id', () => {
  it('returns the entry with its markdown body', async () => {
    const res = await server.inject({ url: '/api/v1/catalog/PB-01' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe('PB-01');
    expect(body.body).toMatch(/^# PB-01/);
    expect(body.huntQuery).toBeTruthy();
  });

  it('accepts a lowercase playbook id', async () => {
    expect((await server.inject({ url: '/api/v1/catalog/pb-03' })).json().id).toBe('PB-03');
  });

  it('404s unknown ids and never reads a path from the request', async () => {
    expect((await server.inject({ url: '/api/v1/catalog/PB-99' })).statusCode).toBe(404);
    expect((await server.inject({ url: '/api/v1/catalog/README' })).statusCode).toBe(404);
    expect((await server.inject({ url: '/api/v1/catalog/..%2F..%2Fpackage.json' })).statusCode).toBe(400);
    expect((await server.inject({ url: '/api/v1/catalog/' + 'x'.repeat(81) })).statusCode).toBe(400);
  });
});

describe('static/huntCatalog.js', () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(here, '../static/huntCatalog.js'), 'utf8');
  type Sandbox = {
    HuntCatalog: {
      renderMarkdown: (md: string) => string;
      playbookIdsForTopic: (t: string) => string[];
      buildAlertPlaybookLinks: (a: unknown) => Array<{ id: string; title: string; short: string }>;
      _state: { index: unknown };
    };
    alertTopic?: (d: string) => string;
  };
  const sandbox: Sandbox = Object.create(null);
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  new Function('globalThis', source)(sandbox);
  const { renderMarkdown } = sandbox.HuntCatalog;

  it('escapes HTML in every construct', () => {
    const html = renderMarkdown([
      '# <script>alert(1)</script>',
      '',
      'para <img src=x onerror=alert(1)> **bold <b>** `code <i>`',
      '',
      '| h <b> | x |',
      '|---|---|',
      '| c <b> | y |',
      '',
      '- item <b>',
      '',
      '```',
      '<script>',
      '```',
    ].join('\n'));
    expect(html).not.toMatch(/<script|<img|<i>|<b>/);
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('<strong>bold &lt;b&gt;</strong>');
    expect(html).toContain('<code>code &lt;i&gt;</code>');
    expect(html).toContain('<th>h &lt;b&gt;</th>');
    expect(html).toContain('<li>item &lt;b&gt;</li>');
    expect(html).toContain('<pre><code>&lt;script&gt;</code></pre>');
  });

  it('renders headings, tables, lists, fences and safe links; drops unsafe links', () => {
    const html = renderMarkdown([
      '## Steps',
      '1. one',
      '2. two',
      '',
      'See [docs](https://zeek.org/x) and [bad](javascript:alert(1)) and [rel](../x.md).',
      '',
      '```bash',
      'zeek -r a.pcap',
      '```',
    ].join('\n'));
    expect(html).toContain('<h3>Steps</h3>');
    expect(html).toContain('<ol><li>one</li><li>two</li></ol>');
    expect(html).toContain('<a href="https://zeek.org/x" target="_blank" rel="noopener noreferrer">docs</a>');
    expect(html).not.toContain('javascript:');
    expect(html).toContain('bad');
    expect(html).not.toContain('href="../x.md"');
    expect(html).toContain('<pre data-lang="bash"><code>zeek -r a.pcap</code></pre>');
  });

  it('builds alert playbook chips from the topic map once the index is loaded', () => {
    sandbox.alertTopic = (d: string) => (/scan/i.test(d) ? 'port scan' : '');
    expect(sandbox.HuntCatalog.buildAlertPlaybookLinks({ description: 'Port scan' })).toEqual([]);
    sandbox.HuntCatalog._state.index = {
      links: { alertTopics: { 'port scan': ['PB-12', 'PB-99'] } },
      entries: [{ id: 'PB-12', title: 'PB-12: Port Scan', shortTitle: 'Port Scan' }],
    };
    expect(sandbox.HuntCatalog.playbookIdsForTopic('PORT SCAN')).toEqual(['PB-12', 'PB-99']);
    expect(sandbox.HuntCatalog.buildAlertPlaybookLinks({ description: 'Port scan' })).toEqual([
      { id: 'PB-12', title: 'PB-12: Port Scan', short: 'Port Scan' },
    ]);
    expect(sandbox.HuntCatalog.buildAlertPlaybookLinks({ description: 'nothing' })).toEqual([]);
  });
});

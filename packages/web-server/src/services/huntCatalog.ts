/**
 * Threat hunting catalog: the markdown tree under threathunt-catalog/ indexed
 * in memory so analysts can search it by keyword, ATT&CK technique or data
 * source, and so detection output (alert feed topics, zeek-detector findings)
 * can point at the playbook that hunts it.
 *
 * The catalog is reference material served to the analyst. It is never sent to
 * an LLM: nothing here touches the orchestrator or any agent. That is a
 * deliberate boundary (APE-750 dual-use review): the documents describe attack
 * mechanics in enough detail to detect them, and the safe place for that is a
 * page a person reads, not a model's context.
 *
 * Every file is read once at first use and held whole. 34 files / ~400 KB is
 * small enough that a real search engine would be a dependency for nothing.
 * Lookups by id go through the in-memory map, never the filesystem, so a
 * request can not name a path.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

export const CATALOG_SECTIONS = [
  'playbooks',
  'skills',
  'frameworks',
  'community-detections',
  'references',
] as const;
export type CatalogSection = (typeof CATALOG_SECTIONS)[number];

export const SECTION_LABELS: Record<CatalogSection, string> = {
  playbooks: 'Playbooks',
  skills: 'Skills',
  frameworks: 'Frameworks',
  'community-detections': 'Community detections',
  references: 'References',
};

/** How many playbooks a single finding or alert links to, most relevant first. */
export const MAX_LINKED_PLAYBOOKS = 4;
export const MAX_QUERY_TERMS = 8;
export const SNIPPET_RADIUS = 90;

export interface CatalogSummary {
  id: string;
  section: CatalogSection;
  title: string;
  /** Title with the "PB-01: " prefix removed; what a chip shows. */
  shortTitle: string;
  summary: string;
  techniques: string[];
  tactics: string[];
  dataSources: string[];
  tools: string[];
  headings: string[];
  path: string;
  wordCount: number;
  /** A guardrail-safe question to ask the live platform, from finding-playbook-map.json. */
  huntQuery?: string;
}

export interface CatalogEntry extends CatalogSummary {
  body: string;
  /** @internal lowercase body term frequencies for ranking */
  terms: Map<string, number>;
  /** @internal lowercased searchable strings */
  lower: { title: string; headings: string; tools: string; body: string };
}

export interface SearchHit extends CatalogSummary {
  score: number;
  matched: string[];
  snippet: string;
}

export interface SearchOptions {
  q?: string;
  section?: string;
  technique?: string;
  source?: string;
  limit?: number;
}

export interface FindingPlaybookMap {
  version: number;
  zeek_detector: {
    patterns: Record<string, string[]>;
    behaviors: Record<string, string[]>;
  };
  alert_topics: Record<string, string[]>;
  hunt_queries: Record<string, string>;
}

export interface MatchOptions {
  behavior?: string;
  patterns?: string[];
  topic?: string;
}

export interface HuntCatalog {
  dir: string;
  loadedAt: string;
  entries: CatalogEntry[];
  byId: Map<string, CatalogEntry>;
  map: FindingPlaybookMap;
}

export const MAP_FILENAME = 'finding-playbook-map.json';

// ---------------------------------------------------------------------------
// Parsing

const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
const TACTIC_RE = /\bTA\d{4}\b/g;
const LOG_RE = /\b([a-z0-9_]+\.log)\b/g;
const HEADER_LINE_RE = /^\*\*([A-Za-z&' ]+)\*\*:\s*(.+)$/;

const SOURCE_KEYWORDS: Array<[RegExp, string]> = [
  [/\bsuricata\b|\beve\.json\b/i, 'suricata'],
  [/\bpcap\b/i, 'pcap'],
  [/\bnetflow\b/i, 'netflow'],
  [/\bpassive dns\b/i, 'passive-dns'],
  [/\bthreat intel(?:ligence)?\b/i, 'threat-intel'],
  [/\bsigma\b/i, 'sigma'],
  [/\bes\|ql\b|\bkql\b|\belastic\b/i, 'elastic'],
];

const STOPWORDS = new Set([
  'a', 'an', 'the', 'of', 'in', 'for', 'and', 'or', 'to', 'how', 'do', 'i', 'is',
  'are', 'what', 'with', 'on', 'my', 'me', 'this', 'that', 'it', 'be', 'can',
]);

export function tokenize(text: string): string[] {
  return String(text ?? '')
    .toLowerCase()
    .match(/[a-z0-9][a-z0-9._-]*[a-z0-9]|[a-z0-9]/g) ?? [];
}

function uniqueSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort();
}

function extractSources(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(LOG_RE)) out.add(m[1].toLowerCase());
  for (const [re, label] of SOURCE_KEYWORDS) if (re.test(text)) out.add(label);
  return Array.from(out).sort();
}

function entryId(section: CatalogSection, stem: string): string {
  if (section === 'playbooks') {
    const m = /^(PB-\d{2})/i.exec(stem);
    if (m) return m[1].toUpperCase();
  }
  return stem;
}

function shortTitle(title: string): string {
  return title.replace(/^PB-\d{2}:\s*/i, '').trim();
}

/** First prose paragraph after the header block; what a result card shows. */
function firstParagraph(lines: string[]): string {
  let inCode = false;
  const buf: string[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('```')) { inCode = !inCode; continue; }
    if (inCode) continue;
    const isProse = line
      && !line.startsWith('#')
      && !line.startsWith('|')
      && !line.startsWith('-')
      && !line.startsWith('*')
      && !line.startsWith('>')
      && !/^\d+\./.test(line)
      && !HEADER_LINE_RE.test(line);
    if (isProse) buf.push(line);
    else if (buf.length) break;
  }
  const text = buf.join(' ').replace(/\s+/g, ' ');
  return text.length > 260 ? text.slice(0, 257).replace(/\s+\S*$/, '') + '…' : text;
}

export function parseCatalogFile(section: CatalogSection, relPath: string, markdown: string): CatalogEntry {
  const lines = markdown.split(/\r?\n/);
  const stem = path.basename(relPath, '.md');
  const titleLine = lines.find((l) => /^#\s+/.test(l));
  const title = (titleLine ? titleLine.replace(/^#\s+/, '') : stem).trim();

  const header: Record<string, string> = {};
  for (const line of lines.slice(0, 12)) {
    const m = HEADER_LINE_RE.exec(line.trim());
    if (m) header[m[1].toLowerCase()] = m[2].trim();
  }

  const attck = header['att&ck'] ?? '';
  const headerTechniques = uniqueSorted(attck.match(TECH_RE) ?? []);
  const techniques = headerTechniques.length ? headerTechniques : uniqueSorted(markdown.match(TECH_RE) ?? []);
  const tactics = uniqueSorted(markdown.match(TACTIC_RE) ?? []);

  const sourceLine = header['data sources'];
  const dataSources = sourceLine ? extractSources(sourceLine) : extractSources(markdown);
  const tools = (header['tools'] ?? '')
    .split(/,|;/)
    .map((t) => t.trim())
    .filter(Boolean);

  const headings = lines
    .filter((l) => /^#{2,4}\s+/.test(l))
    .map((l) => l.replace(/^#{2,4}\s+/, '').trim());

  const terms = new Map<string, number>();
  for (const t of tokenize(markdown)) terms.set(t, (terms.get(t) ?? 0) + 1);

  return {
    id: entryId(section, stem),
    section,
    title,
    shortTitle: shortTitle(title),
    summary: firstParagraph(lines),
    techniques,
    tactics,
    dataSources,
    tools,
    headings,
    path: relPath,
    wordCount: tokenize(markdown).length,
    body: markdown,
    terms,
    lower: {
      title: title.toLowerCase(),
      headings: headings.join('\n').toLowerCase(),
      tools: tools.join('\n').toLowerCase(),
      body: markdown.toLowerCase(),
    },
  };
}

// ---------------------------------------------------------------------------
// Loading

export function defaultCatalogDir(): string {
  // dist/services or src/services → repo root; the Dockerfile copies the tree
  // to the same relative spot (/app/threathunt-catalog).
  return process.env.CATALOG_DIR || path.resolve(__dirname, '../../../../threathunt-catalog');
}

function readMap(dir: string): FindingPlaybookMap {
  const raw = JSON.parse(readFileSync(path.join(dir, MAP_FILENAME), 'utf8')) as Partial<FindingPlaybookMap>;
  return {
    version: Number(raw.version ?? 0),
    zeek_detector: {
      patterns: raw.zeek_detector?.patterns ?? {},
      behaviors: raw.zeek_detector?.behaviors ?? {},
    },
    alert_topics: raw.alert_topics ?? {},
    hunt_queries: raw.hunt_queries ?? {},
  };
}

/** Every playbook id the map references; a test asserts each one exists. */
export function mapReferencedIds(map: FindingPlaybookMap): string[] {
  const ids = new Set<string>();
  for (const list of Object.values(map.zeek_detector.patterns)) list.forEach((i) => ids.add(i));
  for (const list of Object.values(map.zeek_detector.behaviors)) list.forEach((i) => ids.add(i));
  for (const list of Object.values(map.alert_topics)) list.forEach((i) => ids.add(i));
  Object.keys(map.hunt_queries).forEach((i) => ids.add(i));
  return Array.from(ids).sort();
}

export function loadCatalog(dir: string = defaultCatalogDir()): HuntCatalog {
  const entries: CatalogEntry[] = [];
  for (const section of CATALOG_SECTIONS) {
    const sectionDir = path.join(dir, section);
    let names: string[];
    try {
      names = readdirSync(sectionDir).filter((n) => n.endsWith('.md')).sort();
    } catch {
      continue; // a section can be absent; an empty catalog is reported by the caller
    }
    for (const name of names) {
      const full = path.join(sectionDir, name);
      if (!statSync(full).isFile()) continue;
      entries.push(parseCatalogFile(section, `${section}/${name}`, readFileSync(full, 'utf8')));
    }
  }
  if (entries.length === 0) {
    throw new Error(`hunt catalog: no markdown found under ${dir}`);
  }
  const map = readMap(dir);
  const byId = new Map<string, CatalogEntry>();
  for (const e of entries) {
    if (byId.has(e.id)) throw new Error(`hunt catalog: duplicate id ${e.id} (${e.path})`);
    byId.set(e.id, e);
  }
  for (const [id, q] of Object.entries(map.hunt_queries)) {
    const e = byId.get(id);
    if (e) e.huntQuery = q;
  }
  return { dir, loadedAt: new Date().toISOString(), entries, byId, map };
}

let cached: HuntCatalog | null | undefined;

/** Lazy singleton. Returns null (and logs once) when the tree is missing. */
export function getCatalog(): HuntCatalog | null {
  if (cached !== undefined) return cached;
  try {
    cached = loadCatalog();
  } catch (err) {
    cached = null;
    console.error('[huntCatalog] unavailable:', err instanceof Error ? err.message : err);
  }
  return cached;
}

/** Test hook. */
export function resetCatalogCache(): void {
  cached = undefined;
}

// ---------------------------------------------------------------------------
// Public shapes

export function toSummary(e: CatalogEntry): CatalogSummary {
  return {
    id: e.id,
    section: e.section,
    title: e.title,
    shortTitle: e.shortTitle,
    summary: e.summary,
    techniques: e.techniques,
    tactics: e.tactics,
    dataSources: e.dataSources,
    tools: e.tools,
    headings: e.headings,
    path: e.path,
    wordCount: e.wordCount,
    ...(e.huntQuery ? { huntQuery: e.huntQuery } : {}),
  };
}

export interface FacetCount { id: string; count: number }

export function facets(cat: HuntCatalog): { sections: FacetCount[]; dataSources: FacetCount[]; techniques: FacetCount[] } {
  const sections = new Map<string, number>();
  const sources = new Map<string, number>();
  const techniques = new Map<string, number>();
  for (const e of cat.entries) {
    sections.set(e.section, (sections.get(e.section) ?? 0) + 1);
    for (const s of e.dataSources) sources.set(s, (sources.get(s) ?? 0) + 1);
    for (const t of e.techniques) techniques.set(t, (techniques.get(t) ?? 0) + 1);
  }
  const toList = (m: Map<string, number>) =>
    Array.from(m, ([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  return {
    sections: CATALOG_SECTIONS.filter((s) => sections.has(s)).map((s) => ({ id: s, count: sections.get(s)! })),
    dataSources: toList(sources),
    techniques: toList(techniques),
  };
}

// ---------------------------------------------------------------------------
// Search

const TECH_TERM_RE = /^t\d{4}(?:\.\d{3})?$/;

function techniqueMatches(entryTech: string, wanted: string): boolean {
  const t = entryTech.toUpperCase();
  const w = wanted.toUpperCase();
  return t === w || t.startsWith(w + '.') || w.startsWith(t + '.');
}

function applyFilters(entries: CatalogEntry[], opts: SearchOptions): CatalogEntry[] {
  let out = entries;
  if (opts.section) out = out.filter((e) => e.section === opts.section);
  if (opts.technique) {
    const want = opts.technique.trim();
    out = out.filter((e) => e.techniques.some((t) => techniqueMatches(t, want)));
  }
  if (opts.source) {
    const want = opts.source.trim().toLowerCase();
    out = out.filter((e) => e.dataSources.some((s) => s === want || s.includes(want)));
  }
  return out;
}

function queryTerms(q: string): string[] {
  const all = tokenize(q);
  const kept = all.filter((t) => !STOPWORDS.has(t));
  return (kept.length ? kept : all).slice(0, MAX_QUERY_TERMS);
}

function scoreEntry(e: CatalogEntry, terms: string[], phrase: string): { score: number; matched: string[] } {
  let score = 0;
  const matched: string[] = [];
  for (const term of terms) {
    let s = 0;
    if (e.id.toLowerCase() === term) s += 25;
    if (e.lower.title.includes(term)) s += 12;
    if (TECH_TERM_RE.test(term)) {
      const up = term.toUpperCase();
      if (e.techniques.some((t) => t.toUpperCase() === up)) s += 15;
      else if (e.techniques.some((t) => techniqueMatches(t, up))) s += 10;
    }
    if (e.dataSources.some((d) => d === term || d === `${term}.log`)) s += 8;
    if (e.lower.tools.includes(term)) s += 6;
    if (e.lower.headings.includes(term)) s += 4;
    const tf = e.terms.get(term) ?? 0;
    if (tf > 0) s += Math.min(tf, 12) * 0.75;
    if (s > 0) {
      matched.push(term);
      score += s;
    }
  }
  if (terms.length >= 2 && phrase) {
    if (e.lower.title.includes(phrase)) score += 20;
    else if (e.lower.body.includes(phrase)) score += 8;
  }
  return { score, matched };
}

function stripInline(text: string): string {
  return text
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\*\*([^*]*)\*\*/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\|/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** A short window of prose around the first matching term; empty when none. */
export function snippetFor(e: CatalogEntry, terms: string[]): string {
  if (terms.length === 0) return e.summary;
  let inCode = false;
  for (const raw of e.body.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('```')) { inCode = !inCode; continue; }
    if (inCode || !line || line.startsWith('#')) continue;
    const lower = line.toLowerCase();
    for (const term of terms) {
      const at = lower.indexOf(term);
      if (at === -1) continue;
      const clean = stripInline(line);
      const cleanAt = Math.max(0, clean.toLowerCase().indexOf(term));
      const start = Math.max(0, cleanAt - SNIPPET_RADIUS);
      const end = Math.min(clean.length, cleanAt + term.length + SNIPPET_RADIUS);
      return (start > 0 ? '…' : '') + clean.slice(start, end) + (end < clean.length ? '…' : '');
    }
  }
  return e.summary;
}

export function searchCatalog(cat: HuntCatalog, opts: SearchOptions = {}): SearchHit[] {
  const limit = Math.max(1, Math.min(50, Math.floor(opts.limit ?? 20)));
  const pool = applyFilters(cat.entries, opts);
  const q = (opts.q ?? '').trim();
  const terms = q ? queryTerms(q) : [];

  if (terms.length === 0) {
    return pool.slice(0, limit).map((e) => ({ ...toSummary(e), score: 0, matched: [], snippet: e.summary }));
  }

  const phrase = terms.join(' ');
  const scored = pool
    .map((e) => ({ e, ...scoreEntry(e, terms, phrase) }))
    .filter((s) => s.matched.length > 0)
    .sort((a, b) => b.matched.length - a.matched.length || b.score - a.score || a.e.title.localeCompare(b.e.title));

  return scored.slice(0, limit).map(({ e, score, matched }) => ({
    ...toSummary(e),
    score: Math.round(score * 100) / 100,
    matched,
    snippet: snippetFor(e, matched),
  }));
}

// ---------------------------------------------------------------------------
// Detection → playbook links

function topicKey(map: Record<string, string[]>, topic: string): string | undefined {
  const want = topic.trim().toLowerCase();
  return Object.keys(map).find((k) => k.toLowerCase() === want);
}

/**
 * Playbooks for one detection, in relevance order, capped. Patterns first
 * (the most specific evidence), then the behaviour label, then the alert-feed
 * topic. Unknown keys contribute nothing rather than failing.
 */
export function playbooksForFinding(cat: HuntCatalog, opts: MatchOptions): CatalogSummary[] {
  const ids: string[] = [];
  const zd = cat.map.zeek_detector;
  for (const p of opts.patterns ?? []) ids.push(...(zd.patterns[p.trim()] ?? []));
  if (opts.behavior) ids.push(...(zd.behaviors[opts.behavior.trim()] ?? []));
  if (opts.topic) {
    const key = topicKey(cat.map.alert_topics, opts.topic);
    if (key) ids.push(...cat.map.alert_topics[key]);
  }
  const out: CatalogSummary[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) continue;
    const e = cat.byId.get(id);
    if (!e) continue;
    seen.add(id);
    out.push(toSummary(e));
    if (out.length >= MAX_LINKED_PLAYBOOKS) break;
  }
  return out;
}

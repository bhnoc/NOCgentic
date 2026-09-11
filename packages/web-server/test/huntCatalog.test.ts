import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  CATALOG_SECTIONS,
  MAX_LINKED_PLAYBOOKS,
  defaultCatalogDir,
  facets,
  loadCatalog,
  mapReferencedIds,
  parseCatalogFile,
  playbooksForFinding,
  searchCatalog,
  tokenize,
} from '../src/services/huntCatalog';

const here = path.dirname(fileURLToPath(import.meta.url));
const cat = loadCatalog(defaultCatalogDir());

// Copies of the orchestrator's guardrail regexes (agents/orchestrator/main.py),
// the same set starterHints.test.ts and alertHints.js carry. A hunt query in
// finding-playbook-map.json is clicked and sent as a real question, so one
// that trips a guardrail answers with a silent cover. Loosen in lockstep.
const ZONE_RE = /\b(registration hypervisors|registration|tool mgmt|opendns\/umbrella dns virtual appliances|umbrella dns virtual appliances|tools)\b/i;
const VENDOR_RE = /\b(palo\s*alto|paloalto|pan-os|corelight|zeek|suricata|snort|thousand\s*eyes|thousandeyes|splunk|cisco|fortinet|fortigate|crowdstrike|checkpoint|check\s*point|partner)\b/i;
const REFUSAL_RE = new RegExp([
  'ignore (previous|all|prior)\\s+(instructions|prompts|rules)',
  'show me your (system )?prompt',
  'what (are|is) your (instructions|system prompt|rules)',
  'you are now (dan|an ai|)',
  '(pretend|roleplay|act) (to be|as|as if)',
  'disregard the (rules|instructions)',
  'write (an? )?(exploit|phishing|malware|keylogger|virus|backdoor)',
  'how do i (hack|exploit|compromise|bypass)',
  'craft (malware|an attack|a payload)',
  'generate (phishing|malicious|exploit)',
].join('|'), 'i');
const OFFTOPIC_KW = ['write a poem', 'tell me a joke', 'recipe for', 'translate this', 'weather', 'homework', 'what is 2+2', 'who won the', 'capital of'];
const RESTRICTED_IP_RE = /\b10\.220\.(12|13|14|15|150|152|153|154|199)\.\d{1,3}\b/;

describe('loadCatalog', () => {
  // 34 files on disk; the root README.md is the tree's own index, not an entry.
  it('indexes the vendored tree: 33 entries across the five sections', () => {
    expect(cat.entries).toHaveLength(33);
    const bySection = new Map<string, number>();
    for (const e of cat.entries) bySection.set(e.section, (bySection.get(e.section) ?? 0) + 1);
    expect(bySection.get('playbooks')).toBe(16);
    expect(bySection.get('skills')).toBe(5);
    expect(bySection.get('frameworks')).toBe(4);
    expect(bySection.get('community-detections')).toBe(4);
    expect(bySection.get('references')).toBe(4);
    for (const s of CATALOG_SECTIONS) expect(bySection.has(s)).toBe(true);
  });

  it('gives playbooks their PB-nn id and everything else its file stem', () => {
    const pb = cat.byId.get('PB-01')!;
    expect(pb.title).toBe('PB-01: C2 Beaconing Detection');
    expect(pb.shortTitle).toBe('C2 Beaconing Detection');
    expect(pb.path).toBe('playbooks/PB-01-c2-beaconing.md');
    expect(cat.byId.get('01-zeek-skills')!.section).toBe('skills');
    expect(cat.byId.get('mitre-attck-network-mapping')!.section).toBe('frameworks');
  });

  it('reads the playbook header block for techniques, data sources and tools', () => {
    const pb = cat.byId.get('PB-02')!;
    expect(pb.techniques).toEqual(['T1048.003', 'T1071.004', 'T1568.002']);
    expect(pb.dataSources).toEqual(expect.arrayContaining(['dns.log', 'suricata', 'pcap']));
    expect(pb.tools).toContain('RITA');
    expect(pb.summary.length).toBeGreaterThan(40);
    expect(pb.summary).not.toMatch(/^#|^\*\*/);
  });

  it('falls back to body-derived techniques when the header has none', () => {
    // No header line at all: the 44-technique Sigma listing is indexed from prose.
    const sigma = cat.byId.get('sigma-network-rules')!;
    expect(sigma.techniques.length).toBeGreaterThan(20);
    // PB-08 / PB-09 / PB-15 say "Supporting all tactics" and name no id anywhere;
    // an honest empty list beats inventing one.
    for (const id of ['PB-08', 'PB-09', 'PB-15']) expect(cat.byId.get(id)!.techniques).toEqual([]);
  });

  it('holds the body in memory so lookups never touch the filesystem by request', () => {
    const pb = cat.byId.get('PB-01')!;
    expect(pb.body.startsWith('# PB-01')).toBe(true);
    expect(pb.wordCount).toBeGreaterThan(200);
    expect(cat.byId.has('../README')).toBe(false);
  });

  it('throws on an empty directory rather than serving an empty catalog', () => {
    expect(() => loadCatalog(path.join(here, 'no-such-dir'))).toThrow(/no markdown/);
  });
});

describe('parseCatalogFile', () => {
  it('extracts tactics, log names and keyword sources from prose', () => {
    const md = [
      '# Sample',
      '',
      'Look in conn.log and http.log for TA0011 traffic, then replay the PCAP through Suricata.',
      'Technique T1071.001 is the usual suspect.',
      '',
      '## Steps',
      '```',
      'zeek -r x.pcap',
      '```',
    ].join('\n');
    const e = parseCatalogFile('references', 'references/sample.md', md);
    expect(e.id).toBe('sample');
    expect(e.tactics).toEqual(['TA0011']);
    expect(e.techniques).toEqual(['T1071.001']);
    expect(e.dataSources).toEqual(['conn.log', 'http.log', 'pcap', 'suricata']);
    expect(e.headings).toEqual(['Steps']);
    expect(e.summary).toMatch(/^Look in conn\.log/);
  });

  it('tokenizes with dotted and hyphenated terms intact', () => {
    expect(tokenize('Zeek conn.log, JA3/JA4 and pass-the-hash T1550.002')).toEqual([
      'zeek', 'conn.log', 'ja3', 'ja4', 'and', 'pass-the-hash', 't1550.002',
    ]);
  });
});

describe('searchCatalog', () => {
  it('ranks the beaconing playbook first for "beaconing"', () => {
    const hits = searchCatalog(cat, { q: 'beaconing' });
    expect(hits[0].id).toBe('PB-01');
    expect(hits[0].matched).toEqual(['beaconing']);
    expect(hits[0].snippet.toLowerCase()).toContain('beacon');
  });

  it('finds entries by ATT&CK technique id, parent matching sub-technique', () => {
    const exact = searchCatalog(cat, { q: 'T1558.003' });
    expect(exact.map((h) => h.id)).toContain('PB-05');
    const parent = searchCatalog(cat, { technique: 'T1558' });
    expect(parent.map((h) => h.id)).toContain('PB-05');
    const sub = searchCatalog(cat, { technique: 'T1071.004' });
    expect(sub.map((h) => h.id)).toContain('PB-02');
    // A playbook that lists the parent T1071 is also a hit for the sub-technique.
    expect(sub.map((h) => h.id)).toContain('PB-01');
  });

  it('filters by data source and section', () => {
    const krb = searchCatalog(cat, { source: 'kerberos.log', limit: 50 });
    expect(krb.length).toBeGreaterThan(0);
    expect(krb.every((h) => h.dataSources.includes('kerberos.log'))).toBe(true);
    const skills = searchCatalog(cat, { section: 'skills', limit: 50 });
    expect(skills).toHaveLength(5);
    expect(skills.every((h) => h.section === 'skills')).toBe(true);
  });

  it('lists in catalog order with no query, and respects the limit', () => {
    const all = searchCatalog(cat, { limit: 50 });
    expect(all).toHaveLength(33);
    expect(all[0].section).toBe('playbooks');
    expect(searchCatalog(cat, { limit: 3 })).toHaveLength(3);
    expect(searchCatalog(cat, { limit: 500 })).toHaveLength(33);
  });

  it('prefers entries matching more of the query terms', () => {
    const hits = searchCatalog(cat, { q: 'kerberos golden ticket' });
    expect(hits[0].id).toBe('PB-05');
    expect(hits[0].matched.length).toBe(3);
  });

  it('returns nothing for a query with no matching term, never throws on junk', () => {
    expect(searchCatalog(cat, { q: 'zzqxv' })).toEqual([]);
    expect(searchCatalog(cat, { q: '!!! ??? ***' })).toHaveLength(20);
    expect(searchCatalog(cat, { q: 'the of and' }).length).toBeGreaterThan(0);
  });

  it('never returns the body in a hit', () => {
    const hit = searchCatalog(cat, { q: 'dns' })[0] as unknown as Record<string, unknown>;
    expect(hit.body).toBeUndefined();
    expect(hit.terms).toBeUndefined();
  });
});

describe('facets', () => {
  it('counts sections in canonical order and sources by frequency', () => {
    const f = facets(cat);
    expect(f.sections.map((s) => s.id)).toEqual([...CATALOG_SECTIONS]);
    expect(f.dataSources[0].count).toBeGreaterThanOrEqual(f.dataSources[1].count);
    expect(f.dataSources.map((s) => s.id)).toContain('conn.log');
    expect(f.techniques.length).toBeGreaterThan(40);
  });
});

describe('finding-playbook-map.json', () => {
  it('references only playbooks that exist', () => {
    for (const id of mapReferencedIds(cat.map)) {
      expect(cat.byId.has(id), `map references missing ${id}`).toBe(true);
    }
  });

  it('gives every playbook a hunt query and no other section one', () => {
    for (const e of cat.entries) {
      if (e.section === 'playbooks') expect(e.huntQuery, e.id).toBeTruthy();
      else expect(e.huntQuery).toBeUndefined();
    }
  });

  it('covers every alert topic label alertHints.js can produce', () => {
    const src = readFileSync(path.join(here, '../static/alertHints.js'), 'utf8');
    const labels = Array.from(src.matchAll(/label:\s*'([^']+)'/g), (m) => m[1]);
    expect(labels.length).toBeGreaterThan(5);
    for (const label of labels) expect(cat.map.alert_topics, label).toHaveProperty(label);
  });

  it('covers every zeek-detector pattern and behaviour label', () => {
    expect(Object.keys(cat.map.zeek_detector.patterns).sort()).toEqual(['agentic_loop', 'context_reset']);
    expect(Object.keys(cat.map.zeek_detector.behaviors).sort()).toEqual(['agentic-orchestration', 'data-retrieval', 'unknown']);
  });

  // The rule the starter-hint pool lives under: a chip that answers with a
  // cover is worse than no chip.
  it('hunt queries pass the orchestrator guardrails', () => {
    for (const [id, q] of Object.entries(cat.map.hunt_queries)) {
      expect(q, id).not.toMatch(ZONE_RE);
      expect(q, id).not.toMatch(VENDOR_RE);
      expect(q, id).not.toMatch(REFUSAL_RE);
      expect(q, id).not.toMatch(RESTRICTED_IP_RE);
      for (const kw of OFFTOPIC_KW) expect(q.toLowerCase(), id).not.toContain(kw);
      expect(q.length).toBeLessThanOrEqual(160);
      expect(q.trim().endsWith('?')).toBe(true);
    }
  });
});

describe('playbooksForFinding', () => {
  it('links a zeek-detector agentic finding to the beaconing playbook first', () => {
    const pbs = playbooksForFinding(cat, {
      behavior: 'agentic-orchestration',
      patterns: ['context_reset', 'agentic_loop'],
    });
    expect(pbs.length).toBeGreaterThan(0);
    expect(pbs.length).toBeLessThanOrEqual(MAX_LINKED_PLAYBOOKS);
    expect(pbs.map((p) => p.id)).toContain('PB-01');
    expect(new Set(pbs.map((p) => p.id)).size).toBe(pbs.length);
    // Patterns carry the most specific evidence, so they order the list.
    expect(pbs[0].id).toBe('PB-04');
  });

  it('links an alert-feed topic, case-insensitively', () => {
    expect(playbooksForFinding(cat, { topic: 'port scan' }).map((p) => p.id)).toEqual(['PB-12']);
    expect(playbooksForFinding(cat, { topic: 'C2 BEACON' }).map((p) => p.id)).toEqual(['PB-01', 'PB-10']);
  });

  it('ignores unknown keys instead of failing', () => {
    expect(playbooksForFinding(cat, { behavior: 'nope', patterns: ['x'], topic: 'y' })).toEqual([]);
    expect(playbooksForFinding(cat, {})).toEqual([]);
  });

  it('returns summaries with hunt queries, not bodies', () => {
    const [pb] = playbooksForFinding(cat, { topic: 'malware' });
    expect(pb.huntQuery).toBeTruthy();
    expect((pb as unknown as Record<string, unknown>).body).toBeUndefined();
  });
});

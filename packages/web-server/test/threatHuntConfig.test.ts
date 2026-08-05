import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

// The "MUD as code" contract (docs/threat-hunt-mud/ThreatHunt.d.ts): the
// engine in static/threat-hunt.js is content-free and trusts this shape, so
// a malformed hunt config is the only way the game can break. Validate every
// registered hunt against the contract.

interface HuntEvidence { id: string; label: string; detail: string; hint?: string[] }
interface HuntLogBlock { id?: string; title: string; lines: string[] }
interface HuntExit { to: string; label: string; requiresEvidence?: number }
interface HuntAction { id: string; label: string; correct?: boolean; resultNote: string }
interface HuntNode {
  name: string; tag: string; narration: string;
  evidence?: HuntEvidence[]; logs?: HuntLogBlock[]; exits?: HuntExit[];
  isDecision?: boolean; actions?: HuntAction[];
}
interface HuntTimelineEvent {
  id: string; t: string; label: string;
  nodes?: string[]; hint?: string[]; tone?: string;
}
interface HuntConfig {
  id: string;
  meta: { title: string; briefing: string; targetSeconds: number };
  glossary?: Record<string, string>;
  timeline?: HuntTimelineEvent[];
  ui?: Record<string, string>;
  startNode: string;
  nodes: Record<string, HuntNode>;
  endings: Record<string, { title: string; narration: string } | undefined>;
}

// Chrome-copy keys the engine accepts in config.ui (threat-hunt.js DEFAULT_UI).
const UI_KEYS = [
  'openingTag', 'openingLine', 'briefingHint', 'noEvidence', 'evidenceHint', 'leaveButton',
  'logsTitle', 'logsQuerying', 'logsLoadingTitle', 'logsLoadingMeta',
  'timelineTitle', 'timelineHint', 'timelineUnobserved', 'timelineClickPrompt', 'timelineEmpty',
];

interface HuntApp {
  id: string;
  kind: string;
  title: string;
  subtitle?: string;
  blurb?: string;
  url: string;
  badge?: string;
}

function loadRegistry(): HuntConfig[] {
  const file = path.join(__dirname, '../static/threat-hunt-config.js');
  const src = readFileSync(file, 'utf8');
  const window: { THREAT_HUNTS?: HuntConfig[]; THREAT_HUNT_APPS?: HuntApp[] } = {};
  new Function('window', src)(window);
  if (!window.THREAT_HUNTS) throw new Error('threat-hunt-config.js did not set window.THREAT_HUNTS');
  return window.THREAT_HUNTS;
}

function loadApps(): HuntApp[] {
  const file = path.join(__dirname, '../static/threat-hunt-config.js');
  const src = readFileSync(file, 'utf8');
  const window: { THREAT_HUNT_APPS?: HuntApp[] } = {};
  new Function('window', src)(window);
  return window.THREAT_HUNT_APPS ?? [];
}

const hunts = loadRegistry();
const huntApps = loadApps();

describe('threat hunt registry', () => {
  it('registers at least one hunt with a stable id', () => {
    expect(hunts.length).toBeGreaterThan(0);
    for (const hunt of hunts) expect(hunt.id).toMatch(/^[a-z0-9-]+$/);
  });

  it('registers the Gemini Enterprise Threat Intelligence app (not a MUD graph)', () => {
    const app = huntApps.find(a => a.id === 'gemini-threat-intelligence');
    expect(app).toBeDefined();
    expect(app!.kind).toBe('gemini-enterprise');
    expect(app!.badge).toMatch(/Gemini Enterprise/i);
    expect(app!.url).toMatch(/^https:\/\/remix-remix-nocgentic-gemini-threat-intelligence-/);
    expect(app!.url).toMatch(/\.run\.app\/?$/);
    // Must stay out of the MUD registry so contract/playthrough suites stay graph-shaped.
    expect(hunts.some(h => h.id === app!.id)).toBe(false);
  });

  it('ships fakecorp-cleartext-mcp with True Positive as the correct close code', () => {
    const hunt = hunts.find(h => h.id === 'fakecorp-cleartext-mcp');
    expect(hunt).toBeDefined();
    expect(hunt!.startNode).toBe('observed-logs');
    for (const key of [
      'observed-logs', 'http-conn', 'dns-logs', 'device-profile', 'class-context', 'decision'
    ]) {
      expect(hunt!.nodes[key], key).toBeDefined();
    }
    const correct = (hunt!.nodes.decision.actions ?? []).filter(a => a.correct);
    expect(correct).toHaveLength(1);
    expect(correct[0].id).toBe('true-positive');
    expect(correct[0].label).toBe('True Positive');
  });

  it('grounds every timeline event in real nodes and log lines', () => {
    for (const hunt of hunts) {
      for (const e of hunt.timeline ?? []) {
        const ctx = `${hunt.id}/${e.id}`;
        expect(e.t, ctx).toMatch(/^\d{1,2}:\d{2}(:\d{2})?$/);
        expect(e.label.length, ctx).toBeGreaterThan(0);
        // No tip-off copy on the strip either.
        expect(e.label.toLowerCase(), ctx).not.toContain('smoking gun');
        const nodes = e.nodes ?? [];
        expect(nodes.length, ctx).toBeGreaterThan(0);
        for (const n of nodes) expect(hunt.nodes[n], `${ctx}: node ${n}`).toBeDefined();
        const blob = nodes
          .flatMap(n => (hunt.nodes[n].logs ?? []).flatMap(l => l.lines))
          .join('\n');
        for (const h of e.hint ?? []) {
          expect(blob.includes(h), `${ctx}: "${h}"`).toBe(true);
        }
      }
    }
    // The MCP hunt ships an incident timeline.
    const mcp = hunts.find(h => h.id === 'fakecorp-cleartext-mcp');
    expect((mcp!.timeline ?? []).length).toBeGreaterThanOrEqual(4);
  });

  it('grounds every evidence hint verbatim in its node log lines', () => {
    let hinted = 0;
    for (const hunt of hunts) {
      for (const [key, node] of Object.entries(hunt.nodes)) {
        const blob = (node.logs ?? []).flatMap(l => l.lines).join('\n');
        for (const ev of node.evidence ?? []) {
          for (const h of ev.hint ?? []) {
            hinted++;
            expect(h.length, `${hunt.id}/${key}/${ev.id}`).toBeGreaterThan(0);
            expect(blob.includes(h), `${hunt.id}/${key}/${ev.id}: "${h}"`).toBe(true);
          }
        }
      }
    }
    // Full-length hunts ship hints on evidence-bearing rooms (MCP alone has 5).
    expect(hinted).toBeGreaterThanOrEqual(5);
  });

  it('ships logs on every evidence-bearing room so chips open captures (no View logs bar)', () => {
    for (const hunt of hunts) {
      for (const [key, node] of Object.entries(hunt.nodes)) {
        if (node.isDecision) continue;
        if ((node.evidence ?? []).length === 0) continue;
        const logs = node.logs ?? [];
        expect(logs.length, `${hunt.id}/${key}`).toBeGreaterThan(0);
        expect(logs[0].lines.length, `${hunt.id}/${key}`).toBeGreaterThan(2);
      }
      expect((hunt.timeline ?? []).length, hunt.id).toBeGreaterThanOrEqual(3);
    }
  });

  it('ships obfuscated Corelight log captures on fakecorp-cleartext-mcp rooms', () => {
    const hunt = hunts.find(h => h.id === 'fakecorp-cleartext-mcp');
    expect(hunt).toBeDefined();
    for (const key of ['observed-logs', 'http-conn', 'dns-logs', 'device-profile', 'class-context']) {
      const logs = hunt!.nodes[key].logs ?? [];
      expect(logs.length, key).toBeGreaterThan(0);
      expect(logs[0].title.length, key).toBeGreaterThan(0);
      expect(logs[0].lines.length, key).toBeGreaterThan(2);
      const blob = logs.map(l => l.lines.join('\n')).join('\n').toLowerCase();
      expect(blob.includes('10.220.107'), key).toBe(false);
      expect(blob.includes('mcpk_[redacted]') || blob.includes('10.44.18.72') || key === 'class-context' || key === 'device-profile', key).toBe(true);
    }
  });

  it('puts a cleartext-MCP HINT block in http-conn logs (bearer on :80 + path set)', () => {
    const hunt = hunts.find(h => h.id === 'fakecorp-cleartext-mcp');
    const logs = hunt!.nodes['http-conn'].logs ?? [];
    const blob = logs.map(l => l.lines.join('\n')).join('\n');
    const titles = logs.map(l => l.title).join('\n');
    expect(titles).toMatch(/HINT/i);
    expect(blob).toMatch(/id\.resp_p=80|"id\.resp_p":80/);
    expect(blob).toMatch(/Bearer mcpk_\[REDACTED\]/);
    for (const path of [
      '/vaultwatch/mcp', '/talon/mcp', '/redline-intel/mcp', '/graph-ti/mcp',
      '/pulsefeed/mcp', '/badgeauth/mcp', '/notekeep/mcp',
    ]) {
      expect(blob.includes(path), path).toBe(true);
    }
    // Soft label only — do not shout SMOKING GUN.
    expect((blob + '\n' + titles).toLowerCase()).not.toContain('smoking gun');
  });

  it('ships northlab-cleartext-siem-login with BH Benign as the correct close code', () => {
    const hunt = hunts.find(h => h.id === 'northlab-cleartext-siem-login');
    expect(hunt).toBeDefined();
    expect(hunt!.startNode).toBe('observed-logs');
    for (const key of [
      'observed-logs', 'http-login', 'dest-context', 'class-peers', 'decision'
    ]) {
      expect(hunt!.nodes[key], key).toBeDefined();
    }
    const correct = (hunt!.nodes.decision.actions ?? []).filter(a => a.correct);
    expect(correct).toHaveLength(1);
    expect(correct[0].id).toBe('bh-benign');
    expect(correct[0].label).toBe('BH Benign');
  });

  it('ships obfuscated Corelight log captures on northlab-cleartext-siem-login rooms', () => {
    const hunt = hunts.find(h => h.id === 'northlab-cleartext-siem-login');
    expect(hunt).toBeDefined();
    for (const key of ['observed-logs', 'http-login', 'dest-context', 'class-peers']) {
      const logs = hunt!.nodes[key].logs ?? [];
      expect(logs.length, key).toBeGreaterThan(0);
      expect(logs[0].title.length, key).toBeGreaterThan(0);
      expect(logs[0].lines.length, key).toBeGreaterThan(2);
      const blob = logs.map(l => l.lines.join('\n')).join('\n').toLowerCase();
      expect(blob.includes('10.220.57'), key).toBe(false);
      expect(blob.includes('splunk'), key).toBe(false);
      expect(
        blob.includes('10.44.22.11') || blob.includes('203.0.113.40') || blob.includes('logdeck'),
        key,
      ).toBe(true);
    }
    expect((hunt!.timeline ?? []).length).toBeGreaterThanOrEqual(4);
  });

  it('puts a cleartext-SIEM HINT block in http-login logs (creds on :8001 + path set)', () => {
    const hunt = hunts.find(h => h.id === 'northlab-cleartext-siem-login');
    const logs = hunt!.nodes['http-login'].logs ?? [];
    const blob = logs.map(l => l.lines.join('\n')).join('\n');
    const titles = logs.map(l => l.title).join('\n');
    expect(titles).toMatch(/HINT/i);
    expect(blob).toMatch(/id\.resp_p=8001|"id\.resp_p":8001/);
    expect(blob).toContain('password=[REDACTED]');
    expect(blob).toContain('/en-GB/account/login');
    expect(blob).toContain('/en-GB/logdeckd/__raw/services/appsbrowser/account:login');
    expect((blob + '\n' + titles).toLowerCase()).not.toContain('smoking gun');
  });

  it('ships batch-2 hunts with the expected close codes', () => {
    const expected: Record<string, string> = {
      'fakecorp-supplychain-dns': 'true-positive',
      'northlab-singleton-c2': 'true-positive',
      'stagecast-license-pii-http': 'bh-benign',
      'noc-log4j-sensor-test': 'bh-benign',
      'rivertide-azure-background': 'bh-benign',
    };
    expect(hunts.length).toBeGreaterThanOrEqual(7);
    for (const [id, closeId] of Object.entries(expected)) {
      const hunt = hunts.find(h => h.id === id);
      expect(hunt, id).toBeDefined();
      const correct = (hunt!.nodes.decision.actions ?? []).filter(a => a.correct);
      expect(correct, id).toHaveLength(1);
      expect(correct[0].id, id).toBe(closeId);
    }
  });

  it('keeps authored hunt copy free of known real Slack identifiers', () => {
    const blob = JSON.stringify(hunts).toLowerCase();
    const banned = [
      'checkmarx', 'teampcp', 'litellm', 'sfrclak', 'pepsico', 'pwcinternal',
      'httpforever', 'safeactivation', 'worksodsirius', 'phiplips', 'ghabovethec',
      'falconforce', 'informafestivals', 'bytespider', 'mend.io', 'ihs.gov',
      // Product / path leftovers from live threads (fiction map must win).
      'recorded-future', 'google-secops', 'silentpush', 'opencti',
      'httpforever.com', '10.220.107', '10.220.57', '138.197',
      'splunk', 'ekoparty', 'veronica', 'cvut', 'corala',
    ];
    for (const term of banned) {
      expect(blob.includes(term), term).toBe(false);
    }
  });

  it('ships only fiction addressing — no live public cloud IPs or azure.com tenants', () => {
    const blob = JSON.stringify(hunts);
    expect(blob.includes('52.14.88')).toBe(false);
    expect(blob.toLowerCase().includes('azure.com')).toBe(false);
    expect(blob).not.toMatch(/Bearer\s+mcpk_(?!\[REDACTED\])/);
    // Allow password=[REDACTED] only — never live password values.
    expect(blob).not.toMatch(/password\s*=\s*(?!\[REDACTED\])[^\s"\\,]{3,}/i);
    // Public IPv4 must be RFC 5737 documentation ranges only (or absent).
    // Conference fiction uses 10.44.0.0/16. Loopback must not appear — use a
    // fiction hostname in JNDI/test payloads instead.
    const ips = blob.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
    for (const ip of ips) {
      const [a, b, c] = ip.split('.').map(Number);
      const conf = a === 10 && b === 44;
      const testNet =
        (a === 192 && b === 0 && c === 2) ||
        (a === 198 && b === 51 && c === 100) ||
        (a === 203 && b === 0 && c === 113);
      expect(conf || testNet, `non-fiction IP ${ip}`).toBe(true);
    }
    expect(blob.includes('127.0.0.1')).toBe(false);
    // Emails only on invented .example tenants.
    for (const email of blob.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) ?? []) {
      expect(email.endsWith('.example'), email).toBe(true);
    }
  });
});

describe.each(hunts.map(h => [h.id, h] as const))('hunt contract: %s', (_id, hunt) => {
  it('has briefing meta and a soft time target', () => {
    expect(hunt.meta.title.length).toBeGreaterThan(0);
    expect(hunt.meta.briefing.length).toBeGreaterThan(0);
    expect(hunt.meta.targetSeconds).toBeGreaterThan(0);
  });

  it('startNode exists and every exit resolves to a node', () => {
    expect(hunt.nodes[hunt.startNode]).toBeDefined();
    for (const [nodeId, node] of Object.entries(hunt.nodes)) {
      for (const exit of node.exits ?? []) {
        expect(hunt.nodes[exit.to], `exit "${exit.label}" from ${nodeId}`).toBeDefined();
        expect(exit.label.length).toBeGreaterThan(0);
      }
    }
  });

  it('a decision node is reachable from startNode', () => {
    const seen = new Set<string>();
    const queue = [hunt.startNode];
    while (queue.length) {
      const id = queue.shift()!;
      if (seen.has(id)) continue;
      seen.add(id);
      for (const exit of hunt.nodes[id].exits ?? []) queue.push(exit.to);
    }
    const reachableDecision = [...seen].some(id => hunt.nodes[id].isDecision);
    expect(reachableDecision).toBe(true);
  });

  it('decision nodes carry actions with exactly one correct choice; others carry exits', () => {
    for (const [nodeId, node] of Object.entries(hunt.nodes)) {
      if (node.isDecision) {
        const actions = node.actions ?? [];
        expect(actions.length, `decision node ${nodeId}`).toBeGreaterThan(1);
        expect(actions.filter(a => a.correct).length, `decision node ${nodeId}`).toBe(1);
        for (const action of actions) expect(action.resultNote.length).toBeGreaterThan(0);
      } else {
        expect((node.exits ?? []).length, `node ${nodeId} needs exits`).toBeGreaterThan(0);
      }
    }
  });

  it('every non-decision node yields evidence (no punishing dead ends)', () => {
    for (const [nodeId, node] of Object.entries(hunt.nodes)) {
      if (node.isDecision) continue;
      expect((node.evidence ?? []).length, `node ${nodeId}`).toBeGreaterThan(0);
    }
  });

  it('evidence ids are unique and requiresEvidence gates are attainable', () => {
    const ids = Object.values(hunt.nodes).flatMap(n => (n.evidence ?? []).map(e => e.id));
    expect(new Set(ids).size).toBe(ids.length);
    for (const node of Object.values(hunt.nodes)) {
      for (const exit of node.exits ?? []) {
        if (exit.requiresEvidence) expect(exit.requiresEvidence).toBeLessThanOrEqual(ids.length);
      }
    }
  });

  it('win and lose endings are authored', () => {
    for (const key of ['win', 'lose'] as const) {
      const ending = hunt.endings[key];
      expect(ending, `${key} ending`).toBeDefined();
      expect(ending!.title.length).toBeGreaterThan(0);
      expect(ending!.narration.length).toBeGreaterThan(0);
    }
  });

  it('ui overrides only use keys the engine renders', () => {
    for (const [key, value] of Object.entries(hunt.ui ?? {})) {
      expect(UI_KEYS, `unknown ui key "${key}"`).toContain(key);
      expect(value.trim().length, `ui.${key}`).toBeGreaterThan(0);
    }
  });

  it('glossary entries are non-empty when present', () => {
    if (!hunt.glossary) return;
    const entries = Object.entries(hunt.glossary);
    expect(entries.length).toBeGreaterThan(0);
    for (const [term, tip] of entries) {
      expect(term.trim().length, `glossary key`).toBeGreaterThan(0);
      expect(tip.trim().length, `glossary tip for ${term}`).toBeGreaterThan(0);
    }
  });
});

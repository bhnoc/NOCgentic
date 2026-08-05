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
  'openingTag', 'openingLine', 'briefingHint', 'noEvidence',
  'logsButton', 'logsTitle', 'logsQuerying', 'logsLoadingTitle', 'logsLoadingMeta',
  'timelineTitle', 'timelineHint', 'timelineUnobserved', 'timelineClickPrompt', 'timelineEmpty',
];

function loadRegistry(): HuntConfig[] {
  const file = path.join(__dirname, '../static/threat-hunt-config.js');
  const src = readFileSync(file, 'utf8');
  const window: { THREAT_HUNTS?: HuntConfig[] } = {};
  new Function('window', src)(window);
  if (!window.THREAT_HUNTS) throw new Error('threat-hunt-config.js did not set window.THREAT_HUNTS');
  return window.THREAT_HUNTS;
}

const hunts = loadRegistry();

describe('threat hunt registry', () => {
  it('registers at least one hunt with a stable id', () => {
    expect(hunts.length).toBeGreaterThan(0);
    for (const hunt of hunts) expect(hunt.id).toMatch(/^[a-z0-9-]+$/);
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
    // The MCP hunt ships hints on all five evidence-bearing rooms.
    expect(hinted).toBeGreaterThanOrEqual(5);
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
    ];
    for (const term of banned) {
      expect(blob.includes(term), term).toBe(false);
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

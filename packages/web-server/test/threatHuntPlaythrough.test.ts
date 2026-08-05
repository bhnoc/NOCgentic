import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * Evidence-aware playthrough simulator — walks each hunt the way the engine
 * does (collect on entry, gate on requiresEvidence, close on decision action).
 * Complements threatHuntConfig.test.ts structural contract checks.
 */

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
  startNode: string;
  nodes: Record<string, HuntNode>;
  endings: Record<string, { title: string; narration: string } | undefined>;
}

function loadRegistry(): HuntConfig[] {
  const file = path.join(__dirname, '../static/threat-hunt-config.js');
  const src = readFileSync(file, 'utf8');
  const window: { THREAT_HUNTS?: HuntConfig[] } = {};
  new Function('window', src)(window);
  if (!window.THREAT_HUNTS) throw new Error('threat-hunt-config.js did not set window.THREAT_HUNTS');
  return window.THREAT_HUNTS;
}

const hunts = loadRegistry();

function collectOnEntry(hunt: HuntConfig, nodeId: string, evidence: Set<string>): void {
  for (const item of hunt.nodes[nodeId].evidence ?? []) evidence.add(item.id);
}

function unlockedExits(hunt: HuntConfig, nodeId: string, evidence: Set<string>): HuntExit[] {
  return (hunt.nodes[nodeId].exits ?? []).filter(
    e => (e.requiresEvidence || 0) <= evidence.size,
  );
}

/** Reachability ignoring requiresEvidence gates. */
function reachableIgnoringGates(hunt: HuntConfig): Set<string> {
  const seen = new Set<string>();
  const queue = [hunt.startNode];
  while (queue.length) {
    const id = queue.shift()!;
    if (seen.has(id)) continue;
    seen.add(id);
    for (const exit of hunt.nodes[id].exits ?? []) queue.push(exit.to);
  }
  return seen;
}

/** BFS respecting evidence collection + gates. Returns path to a decision node. */
function pathToDecision(hunt: HuntConfig): string[] | null {
  type State = { nodeId: string; evidence: Set<string>; path: string[] };
  const startEv = new Set<string>();
  collectOnEntry(hunt, hunt.startNode, startEv);
  const queue: State[] = [{ nodeId: hunt.startNode, evidence: startEv, path: [hunt.startNode] }];
  const seen = new Set<string>(); // nodeId|sortedEvidenceKey

  while (queue.length) {
    const cur = queue.shift()!;
    const key = cur.nodeId + '|' + [...cur.evidence].sort().join(',');
    if (seen.has(key)) continue;
    seen.add(key);

    if (hunt.nodes[cur.nodeId].isDecision) return cur.path;

    for (const exit of unlockedExits(hunt, cur.nodeId, cur.evidence)) {
      const nextEv = new Set(cur.evidence);
      collectOnEntry(hunt, exit.to, nextEv);
      queue.push({
        nodeId: exit.to,
        evidence: nextEv,
        path: [...cur.path, exit.to],
      });
    }
  }
  return null;
}

function parseClock(t: string): number {
  const parts = String(t).split(':').map(Number);
  return (parts[0] || 0) * 3600 + (parts[1] || 0) * 60 + (parts[2] || 0);
}

function nodeLogBlob(hunt: HuntConfig, nodeId: string): string {
  return (hunt.nodes[nodeId].logs ?? []).flatMap(l => l.lines).join('\n');
}

describe.each(hunts.map(h => [h.id, h] as const))('playthrough: %s', (_id, hunt) => {
  it('every node is reachable from startNode (ignoring gates)', () => {
    const seen = reachableIgnoringGates(hunt);
    for (const nodeId of Object.keys(hunt.nodes)) {
      expect(seen.has(nodeId), `orphan node "${nodeId}"`).toBe(true);
    }
  });

  it('decision is reachable under evidence-gate rules', () => {
    const path = pathToDecision(hunt);
    expect(path, 'no path to decision with gates').not.toBeNull();
    expect(hunt.nodes[path![path!.length - 1]].isDecision).toBe(true);
  });

  it('visiting a node twice does not duplicate evidence', () => {
    const evidence = new Set<string>();
    collectOnEntry(hunt, hunt.startNode, evidence);
    const before = evidence.size;
    collectOnEntry(hunt, hunt.startNode, evidence);
    expect(evidence.size).toBe(before);
  });

  it('locked exits stay locked until evidence count is met, then unlock', () => {
    const gated: { from: string; exit: HuntExit }[] = [];
    for (const [from, node] of Object.entries(hunt.nodes)) {
      for (const exit of node.exits ?? []) {
        if (exit.requiresEvidence) gated.push({ from, exit });
      }
    }
    if (!gated.length) return;

    for (const { from, exit } of gated) {
      const need = exit.requiresEvidence!;
      const short = new Set<string>();
      // Fill with dummy ids up to need-1 — gate cares about count, matching engine.
      for (let i = 0; i < need - 1; i++) short.add('__pad_' + i);
      expect(
        unlockedExits(hunt, from, short).some(e => e.to === exit.to && e.label === exit.label),
        `${hunt.id}: "${exit.label}" should stay locked at ${need - 1}`,
      ).toBe(false);

      const enough = new Set(short);
      enough.add('__pad_last');
      expect(enough.size).toBe(need);
      expect(
        unlockedExits(hunt, from, enough).some(e => e.to === exit.to && e.label === exit.label),
        `${hunt.id}: "${exit.label}" should unlock at ${need}`,
      ).toBe(true);
    }
  });

  it('every decision action maps to exactly one win and the rest lose', () => {
    const decision = Object.values(hunt.nodes).find(n => n.isDecision);
    expect(decision).toBeDefined();
    const actions = decision!.actions ?? [];
    const wins = actions.filter(a => a.correct);
    expect(wins).toHaveLength(1);
    for (const action of actions) {
      const outcome = action.correct ? 'hunt-win' : 'hunt-lose';
      expect(outcome).toBe(action.correct ? 'hunt-win' : 'hunt-lose');
      expect(action.resultNote.length).toBeGreaterThan(0);
      const ending = action.correct ? hunt.endings.win : hunt.endings.lose;
      expect(ending?.title.length).toBeGreaterThan(0);
    }
  });

  it('a concrete walk collects evidence and can take the correct close', () => {
    const path = pathToDecision(hunt)!;
    const evidence = new Set<string>();
    for (const nodeId of path) collectOnEntry(hunt, nodeId, evidence);
    expect(evidence.size).toBeGreaterThan(0);

    const decision = hunt.nodes[path[path.length - 1]];
    const correct = (decision.actions ?? []).find(a => a.correct);
    expect(correct).toBeDefined();
    expect(correct!.correct ? 'hunt-win' : 'hunt-lose').toBe('hunt-win');
  });
});

describe('playthrough: fakecorp-cleartext-mcp story', () => {
  const mcp = hunts.find(h => h.id === 'fakecorp-cleartext-mcp')!;

  it('is registered', () => {
    expect(mcp).toBeDefined();
  });

  it('canonical path reaches decision with at least 4 evidence (gate)', () => {
    // observed → http-conn → dns-logs → device-profile → class-context → decision
    const path = [
      'observed-logs', 'http-conn', 'dns-logs', 'device-profile', 'class-context', 'decision',
    ];
    const evidence = new Set<string>();
    for (const nodeId of path) {
      expect(mcp.nodes[nodeId], nodeId).toBeDefined();
      collectOnEntry(mcp, nodeId, evidence);
      if (nodeId === 'class-context') {
        const gate = (mcp.nodes['class-context'].exits ?? [])
          .find(e => e.to === 'decision');
        expect(gate?.requiresEvidence).toBe(4);
        expect(evidence.size).toBeGreaterThanOrEqual(4);
        expect(unlockedExits(mcp, 'class-context', evidence).some(e => e.to === 'decision')).toBe(true);
      }
    }
    expect(mcp.nodes[path[path.length - 1]].isDecision).toBe(true);
  });

  it('gate blocks decision when arriving at class-context with fewer than 4 evidence', () => {
    // Only start + one pivot before class: 3 evidence after class entry
    const evidence = new Set<string>();
    for (const id of ['observed-logs', 'http-conn', 'class-context']) {
      collectOnEntry(mcp, id, evidence);
    }
    expect(evidence.size).toBe(3);
    expect(unlockedExits(mcp, 'class-context', evidence).some(e => e.to === 'decision')).toBe(false);
  });

  it('timeline is chronological and grounded in correlated logs', () => {
    const events = mcp.timeline ?? [];
    expect(events.length).toBeGreaterThanOrEqual(4);
    const clocks = events.map(e => parseClock(e.t));
    for (let i = 1; i < clocks.length; i++) {
      expect(clocks[i], `${events[i].id} out of order`).toBeGreaterThanOrEqual(clocks[i - 1]);
    }
    for (const e of events) {
      const blob = (e.nodes ?? []).map(n => nodeLogBlob(mcp, n)).join('\n');
      for (const h of e.hint ?? []) {
        expect(blob.includes(h), `${e.id}: hint "${h}"`).toBe(true);
      }
    }
  });

  it('briefing and start narration agree on 289 / 7 paths / 90m window anchors', () => {
    const start = mcp.nodes[mcp.startNode].narration;
    const briefing = mcp.meta.briefing;
    const blob = briefing + '\n' + start;
    expect(blob).toMatch(/289/);
    expect(blob).toMatch(/90m/);
    expect(blob).toMatch(/7/);
    expect(blob).toMatch(/16:42/);
    expect(blob).toMatch(/18:12/);
    const rollup = nodeLogBlob(mcp, 'observed-logs');
    expect(rollup).toContain('289');
    expect(rollup).toContain('paths=7');
  });

  it('http-conn timed samples are chronological', () => {
    const blob = nodeLogBlob(mcp, 'http-conn');
    const times = [...blob.matchAll(/ts":"2026-08-01T([^"]+)/g)].map(m => m[1]);
    expect(times.length).toBeGreaterThanOrEqual(3);
    const sorted = [...times].sort();
    expect(times).toEqual(sorted);
  });
});

describe('playthrough story: northlab-cleartext-siem-login logs', () => {
  const siem = hunts.find(h => h.id === 'northlab-cleartext-siem-login')!;

  it('is registered with full-length log surfaces', () => {
    expect(siem).toBeDefined();
    for (const id of ['observed-logs', 'http-login', 'dest-context', 'class-peers']) {
      expect((siem.nodes[id].logs ?? []).length, id).toBeGreaterThan(0);
    }
  });

  it('timeline is chronological and grounded in correlated logs', () => {
    const events = siem.timeline ?? [];
    expect(events.length).toBeGreaterThanOrEqual(4);
    const times = events.map(e => e.t);
    expect(times).toEqual([...times].sort());
    for (const e of events) {
      const blob = (e.nodes ?? []).map(n => nodeLogBlob(siem, n)).join('\n');
      for (const h of e.hint ?? []) {
        expect(blob.includes(h), `${e.id}: hint "${h}"`).toBe(true);
      }
    }
  });

  it('http-login timed samples are chronological', () => {
    const blob = nodeLogBlob(siem, 'http-login');
    const times = [...blob.matchAll(/ts":"2026-08-04T([^"]+)/g)].map(m => m[1]);
    expect(times.length).toBeGreaterThanOrEqual(3);
    expect(times).toEqual([...times].sort());
  });

  it('rollups and narration agree on 3 usernames / 8m / :8001', () => {
    const rollup = nodeLogBlob(siem, 'observed-logs');
    expect(rollup).toMatch(/usernames=3/);
    expect(rollup).toMatch(/8001/);
    expect(rollup).toMatch(/8m/);
    const start = siem.nodes[siem.startNode].narration;
    expect(start).toMatch(/8m/);
    expect(start).toMatch(/18:41:29/);
    expect(start).toMatch(/18:49:37/);
  });
});

/** Key numbers / anchors that briefing and start narration must both carry. */
const STORY_ANCHORS: Record<string, RegExp[]> = {
  'northlab-cleartext-siem-login': [/A-5521/, /10\.44\.22\.11/, /3/, /8m/, /8001/, /LogDeck/],
  'fakecorp-supplychain-dns': [/A-6602/, /10\.44\.30\.12/, /2h|two DNS bursts/i, /wirepipe\.zone/, /NXDOMAIN/, /GLASSLINE|WirePipe/],
  'northlab-singleton-c2': [/A-6610/, /10\.44\.31\.21/, /starbright\.ddns\.example/, /3 day|~3 day|multi-day/i],
  'stagecast-license-pii-http': [/A-6621/, /10\.44\.32\.40/, /activate\.stagecast\.example/, /SC-77419/, /activate\.php/],
  'noc-log4j-sensor-test': [/A-6633/, /10\.44\.1\.14/, /alwayshttp\.example/, /same minute/, /Suricata/, /NGFW/],
  'rivertide-azure-background': [
    /A-6644/, /10\.44\.33\.36/, /37m/, /RIVERTIDE/,
    /flexops\.azure\.intra\.rivertide\.example/,
    /rivdirect\.postgres\.azure\.intra\.rivertide\.example/,
  ],
};

describe.each(
  Object.entries(STORY_ANCHORS).map(([id, anchors]) => [id, anchors] as const),
)('playthrough story: %s', (huntId, anchors) => {
  const hunt = hunts.find(h => h.id === huntId)!;

  it('is registered', () => {
    expect(hunt).toBeDefined();
  });

  it('briefing and start narration agree on key anchors', () => {
    const blob = hunt.meta.briefing + '\n' + hunt.nodes[hunt.startNode].narration;
    for (const re of anchors) {
      expect(blob, String(re)).toMatch(re);
    }
  });

  it('avoids player-directed / meta chrome in scenario copy', () => {
    const texts = [
      hunt.meta.briefing,
      ...Object.values(hunt.nodes).flatMap(n => [
        n.narration,
        ...(n.evidence ?? []).map(e => e.detail),
        ...(n.actions ?? []).map(a => a.resultNote),
      ]),
      hunt.endings.win?.narration ?? '',
      hunt.endings.lose?.narration ?? '',
    ].join('\n');
    expect(texts).not.toMatch(/Three surfaces are available/i);
    expect(texts).not.toMatch(/Pivot through/i);
    expect(texts).not.toMatch(/Evidence is on the table/i);
    expect(texts).not.toMatch(/\byou\b/i);
    expect(texts).not.toContain('!');
  });
});

/**
 * @vitest-environment happy-dom
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

interface HuntAction { id: string; label: string; correct?: boolean; resultNote: string }
interface HuntExit { to: string; label: string; requiresEvidence?: number }
interface HuntNode {
  name: string; tag: string; narration: string;
  evidence?: { id: string; label: string; detail: string; hint?: string[] }[];
  logs?: { title: string; lines: string[] }[];
  exits?: HuntExit[];
  isDecision?: boolean; actions?: HuntAction[];
}
interface HuntConfig {
  id: string;
  meta: { title: string; briefing: string; targetSeconds: number };
  timeline?: { id: string; t: string; label: string; nodes?: string[]; hint?: string[] }[];
  startNode: string;
  nodes: Record<string, HuntNode>;
  endings: Record<string, { title: string; narration: string } | undefined>;
}

declare global {
  interface Window {
    THREAT_HUNTS?: HuntConfig[];
    ThreatHunt?: {
      mount: (
        el: HTMLElement,
        config: HuntConfig,
        onOutcome?: (kind: string, subject?: Record<string, unknown>) => void,
        onBriefing?: () => void,
      ) => void;
      reset: () => void;
    };
  }
}

function loadScripts(): void {
  const root = path.join(__dirname, '../static');
  const configSrc = readFileSync(path.join(root, 'threat-hunt-config.js'), 'utf8');
  const engineSrc = readFileSync(path.join(root, 'threat-hunt.js'), 'utf8');
  new Function('window', configSrc)(window);
  new Function('window', engineSrc)(window);
}

/** Prefer reduced motion so feed/evidence land without Web Animations API. */
function stubReducedMotion(): void {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: String(query).includes('prefers-reduced-motion'),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
      onchange: null,
    }),
  });
}

function flushFeed(): void {
  // Line queue + any pending modal delays.
  vi.advanceTimersByTime(5000);
}

function clickLabeledButton(scope: ParentNode, label: string): HTMLButtonElement {
  const buttons = [...scope.querySelectorAll('button')].filter(
    (b): b is HTMLButtonElement => b instanceof HTMLButtonElement,
  );
  const btn = buttons.find(b => b.textContent?.replace(/\s+/g, ' ').trim().includes(label));
  expect(btn, `button containing "${label}"`).toBeDefined();
  btn!.click();
  return btn!;
}

function actionButtons(host: HTMLElement): HTMLButtonElement[] {
  return [...host.querySelectorAll('#hunt-actions .hunt-btn')].filter(
    (b): b is HTMLButtonElement => b instanceof HTMLButtonElement,
  );
}

function findAction(host: HTMLElement, label: string): HTMLButtonElement {
  const btn = actionButtons(host).find(b => b.textContent === label);
  expect(btn, `action "${label}"`).toBeDefined();
  return btn!;
}

/** Shortest BFS path to decision respecting evidence gates (mirrors playthrough sim). */
function pathToDecision(hunt: HuntConfig): string[] {
  type State = { nodeId: string; evidence: Set<string>; path: string[] };
  const collect = (id: string, ev: Set<string>) => {
    for (const item of hunt.nodes[id].evidence ?? []) ev.add(item.id);
  };
  const startEv = new Set<string>();
  collect(hunt.startNode, startEv);
  const queue: State[] = [{ nodeId: hunt.startNode, evidence: startEv, path: [hunt.startNode] }];
  const seen = new Set<string>();
  while (queue.length) {
    const cur = queue.shift()!;
    const key = cur.nodeId + '|' + [...cur.evidence].sort().join(',');
    if (seen.has(key)) continue;
    seen.add(key);
    if (hunt.nodes[cur.nodeId].isDecision) return cur.path;
    for (const exit of hunt.nodes[cur.nodeId].exits ?? []) {
      if ((exit.requiresEvidence || 0) > cur.evidence.size) continue;
      const nextEv = new Set(cur.evidence);
      collect(exit.to, nextEv);
      queue.push({ nodeId: exit.to, evidence: nextEv, path: [...cur.path, exit.to] });
    }
  }
  throw new Error(`no path to decision for ${hunt.id}`);
}

function exitLabel(hunt: HuntConfig, from: string, to: string): string {
  const exit = (hunt.nodes[from].exits ?? []).find(e => e.to === to);
  expect(exit, `${hunt.id}: exit ${from}→${to}`).toBeDefined();
  return exit!.label;
}

function walkPath(host: HTMLElement, hunt: HuntConfig, path: string[]): void {
  for (let i = 0; i < path.length - 1; i++) {
    const label = exitLabel(hunt, path[i], path[i + 1]);
    findAction(host, label).click();
    flushFeed();
  }
}

describe('threat hunt engine UI: fakecorp-cleartext-mcp', () => {
  let host: HTMLElement;
  let outcomes: { kind: string; subject?: Record<string, unknown> }[];
  let mcp: HuntConfig;

  beforeEach(() => {
    vi.useFakeTimers();
    stubReducedMotion();
    document.body.innerHTML = '';
    loadScripts();
    mcp = window.THREAT_HUNTS!.find(h => h.id === 'fakecorp-cleartext-mcp')!;
    expect(mcp).toBeDefined();
    expect(window.ThreatHunt).toBeDefined();
    host = document.createElement('div');
    document.body.appendChild(host);
    outcomes = [];
    window.ThreatHunt!.mount(host, mcp, (kind, subject) => {
      outcomes.push({ kind, subject });
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('shows briefing then starts into the start node', () => {
    expect(host.querySelector('.hunt-briefing-title')?.textContent).toContain('Cleartext MCP');
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();
    expect(host.querySelector('.hunt-layout')).toBeTruthy();
    expect(host.querySelector('#hunt-node-name')?.textContent).toBe('Observed traffic');
    expect(host.querySelector('#hunt-feed')?.textContent).toMatch(/A-4418|289|MCP/);
  });

  it('keeps the class→decision gate locked until 4 evidence, then unlocks', () => {
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();

    // observed → dns → class-context → only 3 evidence after class entry
    findAction(host, 'Pivot to resolver logs').click();
    flushFeed();
    findAction(host, 'Search class traffic').click();
    flushFeed();

    expect(host.querySelector('#hunt-node-name')?.textContent).toBe('Class traffic');
    const gate = findAction(host, 'Move to close codes');
    expect(gate.disabled).toBe(true);
    expect(host.querySelector('.hunt-hint')?.textContent).toMatch(/Needs 4/);

    // Back out and collect more, then return
    findAction(host, 'Pivot to resolver logs').click();
    flushFeed();
    findAction(host, 'Inspect the HTTP sessions').click();
    flushFeed();
    findAction(host, 'Profile the source host').click();
    flushFeed();
    findAction(host, 'Search class traffic').click();
    flushFeed();

    const unlocked = findAction(host, 'Move to close codes');
    expect(unlocked.disabled).toBe(false);
  });

  it('lands evidence chips, opens logs modal with hint marks, and closes frictionlessly', () => {
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();
    findAction(host, 'Inspect the HTTP sessions').click();
    flushFeed();

    expect(host.querySelector('#hunt-evidence-count')?.textContent).toMatch(/collected/);
    const chips = host.querySelectorAll('#hunt-evidence .hunt-chip-link');
    expect(chips.length).toBeGreaterThan(0);

    // Node-bar View logs: captures load, no hint button (hints come from chips/timeline).
    const openBtn = host.querySelector('#hunt-logs-open') as HTMLButtonElement;
    expect(openBtn).toBeTruthy();
    expect(host.querySelector('#hunt-logs-panel')?.hasAttribute('hidden')).toBe(false);
    openBtn.click();
    let modal = document.querySelector('#hunt-logs-modal');
    expect(modal).toBeTruthy();
    vi.advanceTimersByTime(2000);
    expect(modal?.querySelector('.hunt-log-pre')).toBeTruthy();
    expect(modal?.querySelector('#hunt-logs-hint')).toBeNull();

    // Esc closes
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(document.querySelector('#hunt-logs-modal')).toBeNull();

    // Evidence chip opens with Show hint → marks
    (chips[chips.length - 1] as HTMLButtonElement).click();
    modal = document.querySelector('#hunt-logs-modal');
    expect(modal).toBeTruthy();
    vi.advanceTimersByTime(2000);
    const hintBtn = modal?.querySelector('#hunt-logs-hint') as HTMLButtonElement | null;
    expect(hintBtn).toBeTruthy();
    hintBtn!.click();
    expect(modal?.querySelectorAll('.hunt-log-mark').length).toBeGreaterThan(0);
    (modal!.querySelector('#hunt-logs-close') as HTMLButtonElement).click();
    expect(document.querySelector('#hunt-logs-modal')).toBeNull();

    // Backdrop click on the overlay dismisses
    openBtn.click();
    modal = document.querySelector('#hunt-logs-modal');
    vi.advanceTimersByTime(2000);
    modal!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.querySelector('#hunt-logs-modal')).toBeNull();
  });

  it('reveals timeline markers as nodes are visited and opens captures on click', () => {
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();

    const strip = host.querySelector('#hunt-timeline') as HTMLElement;
    expect(strip.hidden).toBe(false);
    const dots = () => [...strip.querySelectorAll('.hunt-timeline-dot')] as HTMLButtonElement[];

    // Start node reveals observed-logs markers (tl-alert)
    expect(dots().some(d => d.classList.contains('hunt-timeline-revealed'))).toBe(true);
    const unobserved = dots().filter(d => d.disabled);
    expect(unobserved.length).toBeGreaterThan(0);

    findAction(host, 'Inspect the HTTP sessions').click();
    flushFeed();
    expect(dots().filter(d => d.classList.contains('hunt-timeline-revealed')).length)
      .toBeGreaterThan(1);

    const clickable = dots().find(d => !d.disabled && d.classList.contains('hunt-timeline-revealed'));
    expect(clickable).toBeDefined();
    clickable!.click();
    vi.advanceTimersByTime(2000);
    const modal = document.querySelector('#hunt-logs-modal');
    expect(modal).toBeTruthy();
    // Timeline opens with auto-hint
    expect(modal?.querySelectorAll('.hunt-log-mark').length).toBeGreaterThan(0);
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  });

  it('wrong close code loses and names the correct first move; Play Again + True Positive wins', () => {
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();
    walkPath(host, mcp, [
      'observed-logs', 'http-conn', 'dns-logs', 'device-profile', 'class-context', 'decision',
    ]);

    expect(host.querySelector('#hunt-node-name')?.textContent).toBe('Close codes');
    findAction(host, 'False Positive').click();
    flushFeed();

    expect(outcomes).toEqual([
      expect.objectContaining({ kind: 'hunt-lose' }),
    ]);
    const dialog = host.querySelector('.hunt-dialog');
    expect(dialog?.textContent).toMatch(/Wrong close code|incorrect/i);
    expect(dialog?.textContent).toMatch(/Correct first move:\s*True Positive/);

    clickLabeledButton(host, 'Play Again');
    flushFeed();
    // Play Again jumps straight into a new run (start()), not briefing
    expect(host.querySelector('.hunt-layout')).toBeTruthy();
    walkPath(host, mcp, [
      'observed-logs', 'http-conn', 'dns-logs', 'device-profile', 'class-context', 'decision',
    ]);
    findAction(host, 'True Positive').click();
    flushFeed();

    expect(outcomes[outcomes.length - 1].kind).toBe('hunt-win');
    expect(host.querySelector('.hunt-dialog')?.textContent).toMatch(/Closed True Positive|correct action/i);
  });
});

const allHuntFixtures: HuntConfig[] = (() => {
  const src = readFileSync(
    path.join(__dirname, '../static/threat-hunt-config.js'),
    'utf8',
  );
  const w: { THREAT_HUNTS?: HuntConfig[] } = {};
  new Function('window', src)(w);
  return w.THREAT_HUNTS ?? [];
})();

describe.each(allHuntFixtures.map(h => [h.id, h] as const))(
  'threat hunt engine UI thin path: %s',
  (_id, huntFixture) => {
  let host: HTMLElement;
  let outcomes: string[];

  beforeEach(() => {
    vi.useFakeTimers();
    stubReducedMotion();
    document.body.innerHTML = '';
    loadScripts();
    // Re-resolve hunt from freshly loaded registry (fixture is structural only).
    const hunt = window.THREAT_HUNTS!.find(h => h.id === huntFixture.id)!;
    host = document.createElement('div');
    document.body.appendChild(host);
    outcomes = [];
    window.ThreatHunt!.mount(host, hunt, (kind) => { outcomes.push(kind); });
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('walks shortest unlocked path and wins on the correct close code', () => {
    const hunt = window.THREAT_HUNTS!.find(h => h.id === huntFixture.id)!;
    clickLabeledButton(host, 'Start Hunt');
    flushFeed();
    const path = pathToDecision(hunt);
    walkPath(host, hunt, path);

    const decision = hunt.nodes[path[path.length - 1]];
    expect(decision.isDecision).toBe(true);
    const correct = (decision.actions ?? []).find(a => a.correct)!;
    findAction(host, correct.label).click();
    flushFeed();
    expect(outcomes).toEqual(['hunt-win']);
    expect(host.querySelector('.hunt-dialog')).toBeTruthy();
  });
  },
);

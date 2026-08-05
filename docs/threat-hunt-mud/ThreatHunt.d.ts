/**
 * Threat Hunt — the "MUD as code" contract.
 *
 * A threat hunt is authored entirely as data: a graph of investigation nodes
 * (log sources, hosts, network segments) connected by pivots, ending in one
 * decision node where the player picks a containment action. The engine
 * (`ThreatHunt.jsx`) reads this shape and never hardcodes scenario content,
 * so any hunt drops in through the `config` prop with no engine change.
 *
 * Narration voice follows the system register: third person, present tense,
 * no direct references to the player, numbers first, no exclamation marks.
 * Containment actions use the fixed vocabulary
 * (Acknowledge / Isolate / Allow / Block / Escalate / Dismiss).
 */

export interface ThreatHuntEvidence {
  /** Stable id — evidence is collected into a de-duplicated set. */
  id: string;
  /** Short chip text, mono register: "2,904 attempts / 6 min". */
  label: string;
  /** One sentence of investigative meaning, shown in the narration feed. */
  detail: string;
  /**
   * Optional hint substrings. When the node has `logs`, the evidence chip is
   * clickable and reopens those captures; "Show hint" highlights log lines
   * containing any of these substrings and scrolls to the first match.
   * Each entry must appear verbatim in the source node's log lines.
   */
  hint?: string[];
}

export interface ThreatHuntExit {
  /** Target node id. Revisiting a node is allowed; evidence never duplicates. */
  to: string;
  /** Button label, sentence case, verb first: "Pivot to proxy logs". */
  label: string;
  /**
   * Minimum number of collected evidence items before this pivot unlocks.
   * The button renders disabled with a hint until the count is met.
   */
  requiresEvidence?: number;
}

export interface ThreatHuntAction {
  /** Stable id, reported to the console toast pipeline on resolution. */
  id: string;
  /** Sentence case, from the fixed action vocabulary: "Block source". */
  label: string;
  /** Exactly one action per decision node should be correct. */
  correct?: boolean;
  /**
   * Honest one-sentence explanation of why this action is or is not the
   * right first move. Shown on the end screen for the chosen action.
   */
  resultNote: string;
}

export interface ThreatHuntTimelineEvent {
  /** Stable id for the event marker. */
  id: string;
  /** Incident time within the capture window: "16:42:46" or "16:42". */
  t: string;
  /**
   * What happened at that moment, in the system voice. Same no-tip-off rule
   * as log captures: state when and what, never label the answer.
   */
  label: string;
  /**
   * Node ids this event correlates to. The marker stays dim ("unobserved")
   * until one of these nodes has been visited, and highlights while one of
   * them is the active node.
   */
  nodes?: string[];
  /**
   * Substrings into the correlated node's log lines. Clicking a revealed
   * marker opens that node's captures with these highlighted (same machinery
   * as evidence hints). Each entry must appear verbatim in the node's logs.
   */
  hint?: string[];
  /** Marker tone: info (default) | warn | critical. */
  tone?: 'info' | 'warn' | 'critical';
}

export interface ThreatHuntLogBlock {
  /** Stable id for the capture block. */
  id?: string;
  /** Short source label shown above the pre block: "corelight_http_raw · URI rollup". */
  title: string;
  /** Preformatted log lines (already obfuscated). Rendered verbatim in a mono panel. */
  lines: string[];
}

export interface ThreatHuntNode {
  /** Panel-header name of the surface: "Proxy logs". */
  name: string;
  /** Bracketed mono source tag for the narration feed: "[proxy]". */
  tag: string;
  /** Appended to the narration feed on entry. System voice, no "you". */
  narration: string;
  /** Collected on entry. Every visit is worth something — no punishing dead ends. */
  evidence?: ThreatHuntEvidence[];
  /**
   * Optional obfuscated log captures shown in the Logs rail when this node is
   * active. Authored from real sensor rows, then hard-scrubbed (no real IPs,
   * orgs, people, or bearer tokens).
   */
  logs?: ThreatHuntLogBlock[];
  /** Outbound pivots. Omit on the decision node. */
  exits?: ThreatHuntExit[];
  /** Marks the containment-choice node. Its actions replace the pivot list. */
  isDecision?: boolean;
  /** Containment choices. Rendered with equal visual weight — no styling hint. */
  actions?: ThreatHuntAction[];
}

export interface ThreatHuntEnding {
  /** Dialog title, sentence case: "Source blocked". */
  title: string;
  /** Closing narration for the end screen. */
  narration: string;
}

export interface ThreatHuntMeta {
  /** Scenario title, sentence case: "Credential stuffing, guest portal". */
  title: string;
  /** Briefing paragraph shown before the hunt starts. States the alert and the goal. */
  briefing: string;
  /** Soft time target in seconds (~180 for walk-up play). Elapsed time over the
   * target flips the timer badge to warn; it never hard-fails the hunt. */
  targetSeconds: number;
}

export interface ThreatHuntConfig {
  /** Stable scenario id: "credential-stuffing-guest-portal". */
  id: string;
  meta: ThreatHuntMeta;
  /**
   * Optional ELI5 glossary. Keys are matched case-insensitively in briefing,
   * narration, evidence, and endings; longer keys win. Hover/focus shows the
   * plain-language tip.
   */
  glossary?: Record<string, string>;
  /**
   * Optional incident timeline rendered as a strip above the narration feed.
   * Markers reveal as their correlated nodes are visited, so the incident
   * story assembles as the player pivots. Omit for hunts without
   * time-grounded captures.
   */
  timeline?: ThreatHuntTimelineEvent[];
  /**
   * Optional overrides for engine chrome copy, so a config alone controls
   * every rendered string. Any subset may be set; unset keys use engine
   * defaults. Keys: openingTag, openingLine, briefingHint, noEvidence,
   * logsButton, logsTitle, logsQuerying, logsLoadingTitle, logsLoadingMeta,
   * timelineTitle, timelineHint, timelineUnobserved, timelineClickPrompt,
   * timelineEmpty.
   */
  ui?: Partial<Record<
    | 'openingTag' | 'openingLine' | 'briefingHint' | 'noEvidence'
    | 'logsButton' | 'logsTitle' | 'logsQuerying'
    | 'logsLoadingTitle' | 'logsLoadingMeta'
    | 'timelineTitle' | 'timelineHint' | 'timelineUnobserved'
    | 'timelineClickPrompt' | 'timelineEmpty',
    string
  >>;
  /** Id of the first node the player enters on start. */
  startNode: string;
  /** The investigation graph. Every exit `to` must name a key in this map,
   * and at least one node reachable from `startNode` must be a decision node. */
  nodes: Record<string, ThreatHuntNode>;
  /** Outcome copy. `timeout` is reserved for future hard-timed variants;
   * the reference engine only uses `win` and `lose`. */
  endings: {
    win: ThreatHuntEnding;
    lose: ThreatHuntEnding;
    timeout?: ThreatHuntEnding;
  };
}

export interface ThreatHuntProps {
  /** The authored hunt. See `threat-hunt-config.js` for the reference instance. */
  config: ThreatHuntConfig;
  /** Console action pipeline (the shared toast `push`). Called with
   * "hunt-win" or "hunt-lose" and the chosen action when the hunt resolves. */
  onAction?: (kind: string, subject?: Record<string, unknown>) => Promise<{ ok: boolean }> | void;
}

export declare function ThreatHunt(props: ThreatHuntProps): JSX.Element;

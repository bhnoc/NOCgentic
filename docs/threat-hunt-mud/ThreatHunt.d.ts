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

export interface ThreatHuntNode {
  /** Panel-header name of the surface: "Proxy logs". */
  name: string;
  /** Bracketed mono source tag for the narration feed: "[proxy]". */
  tag: string;
  /** Appended to the narration feed on entry. System voice, no "you". */
  narration: string;
  /** Collected on entry. Every visit is worth something — no punishing dead ends. */
  evidence?: ThreatHuntEvidence[];
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

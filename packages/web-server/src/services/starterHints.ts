/**
 * Starter hints — the chips on the welcome banner, before anyone has asked
 * anything.
 *
 * These are the questions a first-time visitor actually asks when they walk up
 * to a NOC screen: what's the risk, what's the most interesting attack, is
 * anything happening right now, how is the network doing. They are author-
 * written on purpose (no LLM call at page load: no latency, no cost, no
 * sanitiser surface on the one part of the UI that renders before a session
 * exists), and sampled per request so the wall doesn't show the same five
 * strings all week.
 *
 * NETWORK_QUALITY is guaranteed a fixed number of slots in every draw --
 * network quality is half of what this NOC does, and a purely random draw over
 * one flat pool regularly returned five threat questions and made the platform
 * look security-only.
 *
 * Keep entries vendor-free (same rule as the orchestrator's follow-up hints)
 * and answerable by a routed agent: threat/traffic questions land on
 * athena-hunter, quality/latency/loss questions on thousandeyes-analyst.
 */

/** Minimum network-quality chips in any draw. Product requirement, not a tuning knob. */
export const MIN_NETWORK_QUALITY = 2;

/** Default number of chips the welcome banner shows. */
export const DEFAULT_STARTER_HINT_COUNT = 5;

export const NETWORK_QUALITY_HINTS: readonly string[] = [
  'How is the network quality right now?',
  'Is there any latency reported to AWS?',
  'Any packet loss on the conference uplinks in the last hour?',
  'Are attendees seeing slow or failing connections right now?',
  'Have there been any BGP path changes today?',
  'Which monitored destinations are the slowest to reach right now?',
  'Is DNS resolution healthy for attendees?',
  'How does network performance right now compare to earlier today?',
  'Are there any outages affecting conference infrastructure?',
];

/**
 * Everything else, grouped so a draw spreads across angles instead of returning
 * three ways of asking "what are the top threats".
 */
const OTHER_HINT_GROUPS: readonly (readonly string[])[] = [
  // Overall risk / posture — the most common first question.
  [
    'What is the biggest risk so far?',
    'What should I be worried about right now?',
    'Give me a summary of the security posture today',
    'What are the highest-severity threats active right now?',
    'How many alerts have fired today, and what kind?',
  ],
  // Live activity.
  [
    'Are there any attacks happening right now?',
    'Any brute-force or credential attacks on conference hosts?',
    'Any beaconing or C2 patterns in outbound traffic today?',
    'Any scanning activity against the conference network right now?',
  ],
  // The "show me something good" question.
  [
    'What is the most interesting attack so far?',
    'What is the strangest thing on the network today?',
    'What was the most notable incident of the event so far?',
  ],
  // Orientation — what does this network even look like.
  [
    'Who are the top talkers by traffic volume today?',
    'What does normal traffic look like on this network?',
    'Any suspicious DNS lookups in the last hour?',
    'Which conference zones are the busiest right now?',
  ],
];

/** Fisher-Yates over a copy; `rand` injected so tests are deterministic. */
function shuffled<T>(items: readonly T[], rand: () => number): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Draw `count` starter hints, at least MIN_NETWORK_QUALITY of them about
 * network quality. Non-quality picks take one entry per group before any group
 * is used twice, then the whole set is shuffled so the quality chips are not
 * always in the same position.
 */
export function pickStarterHints(
  count: number = DEFAULT_STARTER_HINT_COUNT,
  rand: () => number = Math.random,
): string[] {
  const total = Math.max(0, Math.min(count, NETWORK_QUALITY_HINTS.length + OTHER_HINT_GROUPS.flat().length));
  const quality = Math.min(MIN_NETWORK_QUALITY, total, NETWORK_QUALITY_HINTS.length);

  const picked = shuffled(NETWORK_QUALITY_HINTS, rand).slice(0, quality);

  // One pass per group, round-robin, so a 3-pick draw hits 3 different angles.
  const pools = shuffled(OTHER_HINT_GROUPS, rand).map((g) => shuffled(g, rand));
  let round = 0;
  while (picked.length < total && round < Math.max(...pools.map((p) => p.length))) {
    for (const pool of pools) {
      if (picked.length >= total) break;
      const next = pool[round];
      if (next) picked.push(next);
    }
    round++;
  }

  // Top up from the quality pool if the other groups ran dry (only reachable
  // with an unusually large `count`).
  if (picked.length < total) {
    for (const hint of NETWORK_QUALITY_HINTS) {
      if (picked.length >= total) break;
      if (!picked.includes(hint)) picked.push(hint);
    }
  }

  return shuffled(picked, rand);
}

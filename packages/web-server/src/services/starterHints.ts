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
 * ── Every entry has to be answerable by a real agent ────────────────────────
 * Network-quality chips route to thousandeyes-analyst and are written against
 * the tests actually configured for this event: cloud reachability (AWS, Azure,
 * Google, cloud status pages), the Black Hat site, the attendee app API, DNS
 * (internal resolver vs public), bulk-download throughput, an internal transfer
 * target, the first hop to the venue's ISP, agent-to-agent paths to the core,
 * and ~1100 enterprise probes named after physical rooms.
 *
 * Everything else routes to athena-hunter or alert-triage and is written
 * against the live Athena schema (see agents/athena-hunter/main.py:
 * conn/dns/ssl/http/files/notice/suricata_corelight, alerts, entity_context,
 * asset_classification, device_links, known_*, kerberos/ntlm) and against alert
 * types the feed is really emitting right now: notice (Invalid_Server_Cert,
 * CustomCrypto), yara file hits, suricata SNI signatures, ml.
 *
 * ── Two hard constraints on the wording ─────────────────────────────────────
 * 1. NO restricted-zone words. The orchestrator's _ZONE_RE matches
 *    "Registration" and "Tools" (case-insensitive) and answers ANY query
 *    containing them with a silent cover response. "Which AI tools are
 *    attendees using" would render as a chip and then quietly refuse, which
 *    reads as a broken product. Say "assistants" / "services" / "the front
 *    desk area" instead. Same for the refusal patterns ("how do I hack…",
 *    "write an exploit…") and the off-topic list.
 * 2. NO vendor or product names for OUR OWN stack — same rule the orchestrator
 *    applies to generated follow-up hints (_VENDOR_RE). Monitored public
 *    destinations (AWS, Azure, Google, the Black Hat site) are fair game; the
 *    ISP, the MDM, the DNS security product and the chat platform are not.
 *
 * Draws spread across sub-groups so five chips are five different angles, not
 * five ways of asking "what are the top threats".
 */

/** Minimum network-quality chips in any draw. Product requirement, not a tuning knob. */
export const MIN_NETWORK_QUALITY = 2;

/** Default number of chips the welcome banner shows. */
export const DEFAULT_STARTER_HINT_COUNT = 5;

/**
 * Network quality — thousandeyes-analyst. Grouped so two picks are two
 * different aspects (not "how is DNS" twice). Most carry a word from the
 * orchestrator's _TE_KW set (latency, packet loss, jitter, outage, uplink,
 * reachability, BGP, network quality) so routing survives an LLM-classifier
 * failure and falls back to the heuristic correctly.
 */
const NETWORK_QUALITY_GROUPS: readonly (readonly string[])[] = [
  // Cloud and SaaS reachability — the AWS/Azure/Google/Black Hat-site tests.
  [
    'Is there any latency reported to AWS?',
    'How is our reachability to Azure right now?',
    'Any latency or packet loss reaching Google right now?',
    'Are all the major cloud providers reachable from the show floor?',
    'Is the Black Hat website loading normally for attendees?',
    'How is the attendee app API performing right now?',
    'Is any cloud provider reporting a regional problem that affects us?',
  ],
  // DNS — internal resolver vs public resolver tests.
  [
    'Is DNS resolution healthy for attendees?',
    'Are the DNS monitoring probes resolving normally right now?',
    'Are the internal and public resolvers returning the same answers?',
    'Any DNS resolution failures in the last hour?',
    'Is the internal resolver slower than public DNS right now?',
  ],
  // Throughput and capacity — the bulk-download and internal-transfer tests.
  [
    'Are attendees getting the download speeds we expect?',
    'Has throughput dropped on the large-file download tests today?',
    'How is internal file-transfer performance inside the venue?',
    'Is the network saturated anywhere right now?',
    'What does availability look like across all monitored tests today?',
  ],
  // Uplink, path and routing — ISP first hop, agent-to-agent, BGP.
  [
    'Any packet loss on the conference uplinks in the last hour?',
    'Have there been any BGP path changes today?',
    "How is the first hop to the venue's internet provider performing?",
    'Is there jitter that would affect voice or video calls?',
    'Any routing changes that could explain a slowdown?',
    'How is the network path between the NOC and the core?',
    'Are there any outages affecting conference infrastructure?',
  ],
  // Monitored-test status. NOT per-room: the analyst aggregates across a
  // test's agents, so a room-named question invites a fabricated room answer.
  [
    'Which monitored web services are responding slowly right now?',
    'Is any monitored service completely unreachable right now?',
    'Which monitored destinations are slowest to respond right now?',
    'Which monitored location has the worst experience right now?',
    'Which monitored tests are failing or degraded right now?',
    'Are attendees in any room seeing failed connections right now?',
  ],
  // Trend and triage — "just tell me if anything is wrong".
  [
    'How is the network quality right now?',
    'How does network performance now compare to earlier today?',
    'Has anything on the network degraded in the last hour?',
    'Show me every monitored test that is currently degraded',
    'Is availability holding above target across all monitored tests?',
    'What is the slowest thing on the network right now?',
  ],
];

/** Flat view of the quality pool — the guaranteed slice of every draw. */
export const NETWORK_QUALITY_HINTS: readonly string[] = NETWORK_QUALITY_GROUPS.flat();

/** Everything else: athena-hunter and alert-triage territory. */
const OTHER_HINT_GROUPS: readonly (readonly string[])[] = [
  // Overall risk and posture — the most common first question of all.
  [
    'What is the biggest risk so far?',
    'What should I be worried about right now?',
    'Give me a summary of the security posture today',
    'What are the highest-severity threats active right now?',
    'How many alerts have fired today, and what kind?',
    'Which detector is producing the most alerts today?',
    'Which hosts have the most alerts against them today?',
    'What are the top five things worth investigating right now?',
    'Is today busier than yesterday for high-severity alerts?',
    'What changed in the last hour that I should know about?',
    'What is the single most suspicious host on the network?',
  ],
  // Live attack activity.
  [
    'Are there any attacks happening right now?',
    'Any brute-force or credential attacks on conference hosts?',
    'Any beaconing or command-and-control patterns in outbound traffic today?',
    'Any scanning activity against the conference network right now?',
    'Which internal hosts are talking to each other the most today?',
    'Any spike in failed authentication in the last hour?',
    'Any intrusion attempts against venue infrastructure today?',
    'Any signs of a compromised attendee device?',
    'What files did malware signatures flag today?',
    'Any port scans coming from inside the conference network?',
    'Has anyone tried to attack the NOC itself?',
  ],
  // The "show me something good" question — what people actually walk up for.
  [
    'What is the most interesting attack so far?',
    'What is the strangest thing on the network today?',
    'What was the most notable incident of the event so far?',
    "Show me something surprising in today's traffic",
    'What is the rarest alert that fired today?',
    'Which host is behaving the most oddly today?',
    'Any traffic to destinations we almost never see?',
    'What is the most unusual protocol on the network today?',
    "Any attendee devices doing something they probably shouldn't?",
    "What is the most interesting thing you can tell me about today's traffic?",
  ],
  // Devices and identity — entity_context, asset_classification, device_links.
  [
    'How many devices are on the network right now?',
    'Which operating systems are most common on the conference network today?',
    'Which hardware makers are most common among devices on the network?',
    'Which AI service domains are devices connecting to today?',
    'Which hosts are enrolled with a client certificate today?',
    'How many devices are hiding behind randomized MAC addresses?',
    'Which hosts are running listening services on the attendee network?',
    "Are any devices leaking their employer's internal domain?",
    'Which devices have been on the network the longest today?',
    'Are any attendees using more than one device?',
    'Which hosts advertise the most services to their neighbours?',
  ],
  // Certificates, crypto and DNS hygiene — what the alert feed is full of today.
  [
    'Any self-signed or invalid certificates being accepted today?',
    'Is anyone still sending traffic over plain HTTP?',
    'Any certificate validation failures on the network today?',
    'What TLS versions are attendees actually using?',
    'Any suspicious DNS lookups in the last hour?',
    'Which domains are queried most on the network today?',
    'Any file-sharing or cloud-storage domains in TLS server names today?',
    'Any services using custom or non-standard encryption?',
    'Any domains that failed to resolve unusually often today?',
    'Any rare or newly seen certificates on the network today?',
    'Are any hosts reusing one TLS fingerprint across several addresses?',
  ],
  // Orientation — what does this network even look like.
  [
    'Who are the top talkers by traffic volume today?',
    'What does normal traffic look like on this network?',
    'Which conference zones are the busiest right now?',
    'Which training class is generating the most traffic?',
    'What protocols dominate the network right now?',
    'How much data has crossed the network today?',
    'Which external organizations are attendees connecting to most?',
    'Any unusually long-lived connections open right now?',
    'What was the busiest hour on the network so far today?',
    'Which hosts talk to the most distinct external destinations?',
  ],
];

/** Every hint in the pool, quality first. Exported for tests and tooling. */
export const ALL_STARTER_HINTS: readonly string[] = [
  ...NETWORK_QUALITY_HINTS,
  ...OTHER_HINT_GROUPS.flat(),
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
 * Draw `n` entries from grouped pools, one per group before any group is used
 * twice. That spread is the whole point of grouping: with a flat pool of 100 a
 * five-chip draw regularly came back as three certificate questions.
 */
function drawSpread(groups: readonly (readonly string[])[], n: number, rand: () => number): string[] {
  if (n <= 0) return [];
  const pools = shuffled(groups, rand).map((g) => shuffled(g, rand));
  const deepest = pools.reduce((max, p) => Math.max(max, p.length), 0);
  const out: string[] = [];
  for (let round = 0; round < deepest && out.length < n; round++) {
    for (const pool of pools) {
      if (out.length >= n) break;
      if (pool[round]) out.push(pool[round]);
    }
  }
  return out;
}

/**
 * Draw `count` starter hints, at least MIN_NETWORK_QUALITY of them about
 * network quality, then shuffle so the quality chips are not always in the
 * same position.
 */
export function pickStarterHints(
  count: number = DEFAULT_STARTER_HINT_COUNT,
  rand: () => number = Math.random,
): string[] {
  const total = Math.max(0, Math.min(count, ALL_STARTER_HINTS.length));
  const quality = Math.min(MIN_NETWORK_QUALITY, total, NETWORK_QUALITY_HINTS.length);

  const picked = drawSpread(NETWORK_QUALITY_GROUPS, quality, rand);
  picked.push(...drawSpread(OTHER_HINT_GROUPS, total - picked.length, rand));

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

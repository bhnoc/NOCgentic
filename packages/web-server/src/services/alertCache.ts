import { Alert } from '@bhnoc/shared';

const ATHENA_HUNTER_URL = process.env.ATHENA_HUNTER_URL ?? 'http://athena-hunter:8005';
// Kill-switch source: the orchestrator holds the authoritative in-memory switch.
// ADMIN_BEARER_TOKEN must be added to the web-server service in docker-compose.
const ORCHESTRATOR_URL = process.env.ORCHESTRATOR_URL ?? 'http://orchestrator:8001';
// Read per call, not frozen at import: api/manifold.ts already does it this way,
// and a token added to the environment after boot should start working without a
// restart of the process that polls the emergency switch.
const adminBearerToken = (): string => process.env.ADMIN_BEARER_TOKEN ?? '';
const REFRESH_INTERVAL_MS = parseInt(process.env.ALERT_REFRESH_MS ?? '1800000', 10); // 30 min
// Kill-switch polled on its own short cycle so the emergency freeze is responsive
// (the 30 min alert refresh would be far too slow for an emergency control).
const KILL_POLL_MS = parseInt(process.env.KILL_POLL_MS ?? '15000', 10); // 15 s
const LOOKBACK_HOURS = parseInt(process.env.ALERT_LOOKBACK_HOURS ?? '24', 10);
const MAX_ALERTS = parseInt(process.env.ALERT_MAX_FETCH ?? '200', 10);
const BOOT_RETRY_MS = 8000;
const BOOT_MAX_RETRIES = 6;

// ---------------------------------------------------------------------------
// Restricted-range filter — mirrors the orchestrator's sanitizer so alert
// cards on the sidebar never expose those subnets or zone names to the UI.
// ---------------------------------------------------------------------------
const RESTRICTED_OCTETS = new Set([12, 13, 14, 15, 150, 152, 153, 154, 199]);
const DECOY_THIRD_OCTET = 69;
const IP_RE = /\b10\.220\.(\d{1,3})\.(\d{1,3})\b/g;
const ZONE_RE = /\b(Registration|Tools?)\b/g;

export function scrubString(s: string | null | undefined): string | undefined {
  if (!s) return s ?? undefined;
  let out = s.replace(IP_RE, (full, third, host) => {
    const n = parseInt(third, 10);
    if (!RESTRICTED_OCTETS.has(n)) return full;
    return `10.220.${DECOY_THIRD_OCTET}.${host}`;
  });
  out = out.replace(ZONE_RE, 'internal');
  return out;
}

function ipIsRestricted(ip: string | null | undefined): boolean {
  if (!ip) return false;
  const m = /^10\.220\.(\d{1,3})\./.exec(ip);
  return m ? RESTRICTED_OCTETS.has(parseInt(m[1], 10)) : false;
}

export interface RawAlert {
  id: string;
  timestamp: string;
  severity: Alert['severity'];
  source: string;
  description: string;
  srcIp?: string | null;
  dstIp?: string | null;
}

class AlertCache {
  private queue: RawAlert[] = [];
  private emitted: Alert[] = [];
  private lastRefreshAt: number = 0;
  private refreshTimer: NodeJS.Timeout | null = null;
  private killTimer: NodeJS.Timeout | null = null;
  private running = false;
  // When the orchestrator's kill-switch is on, freeze the feed.
  //
  // Two different failure directions, and they are NOT symmetric:
  //  * Never observed a kill (boot, no admin token, orchestrator not up yet) →
  //    stay live. A feed that freezes because a check failed is an outage.
  //  * Observed a kill → STAY killed until a successful check says otherwise.
  //    Clearing this on a timeout would un-pull a plug someone pulled on
  //    purpose, at the exact moment the platform is least healthy.
  private athenaKilled = false;
  // Has a kill-switch poll ever succeeded? Without a token, or with the
  // orchestrator unreachable since boot, the freeze half of the plug is not
  // wired at all — and the only symptom was a log line nobody reads.
  private killSwitchVerified = false;

  // --- Test-only hooks (additive; do not affect production behavior) --------
  /** Push a raw alert onto the queue so dequeue() can be exercised in tests. */
  __enqueueForTest(raw: RawAlert): void {
    this.queue.push(raw);
  }
  /** Drive the kill-switch transition tests take. Routed through the real
   *  applyKillState so a test cannot pass against behaviour production skips. */
  __setAthenaKilledForTest(killed: boolean): void {
    this.applyKillState(killed);
  }
  /** Run one kill-switch poll against whatever global fetch is stubbed to. */
  async __refreshKillSwitchForTest(): Promise<void> {
    await this.refreshKillSwitch();
  }
  /** Forget that a poll ever succeeded (the flag is process-wide otherwise). */
  __resetKillVerifiedForTest(): void {
    this.killSwitchVerified = false;
  }
  /** Observe the emitted buffer without going through the killed-state filter. */
  __emittedCountForTest(): number {
    return this.emitted.length;
  }
  // --------------------------------------------------------------------------

  start(): void {
    if (this.running) return;
    this.running = true;
    void this.bootRefresh();
    this.refreshTimer = setInterval(() => void this.refresh(), REFRESH_INTERVAL_MS);
    void this.refreshKillSwitch();
    this.killTimer = setInterval(() => void this.refreshKillSwitch(), KILL_POLL_MS);
  }

  /** Initial refresh with retry in case athena-hunter isn't up yet. */
  private async bootRefresh(): Promise<void> {
    for (let i = 0; i < BOOT_MAX_RETRIES; i++) {
      const ok = await this.refresh();
      if (ok) return;
      await new Promise((r) => setTimeout(r, BOOT_RETRY_MS));
    }
  }

  stop(): void {
    this.running = false;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.killTimer) {
      clearInterval(this.killTimer);
      this.killTimer = null;
    }
  }

  /** Pace (ms between broadcasts) so queue drains evenly over refresh window. */
  pacingMs(): number {
    const qLen = this.queue.length;
    if (qLen === 0) return 15000;
    const raw = Math.floor(REFRESH_INTERVAL_MS / qLen);
    return Math.max(4000, Math.min(raw, 30000));
  }

  /** Pull one alert off the queue for broadcast. Re-stamps timestamp to now.
   *  Sanitizes restricted subnets and zone names before anything reaches the UI. */
  dequeue(): Alert | null {
    // Kill-switch: nothing leaves the cache while the plug is pulled. The queue
    // and the emitted buffer were both dropped when the switch was thrown (see
    // applyKillState), so there is nothing here to resume from either — the
    // refresh after restore repopulates from Athena.
    if (this.athenaKilled) return null;
    const raw = this.queue.shift();
    if (!raw) return null;
    // Mask restricted IPs on both src/dst, and scrub the description text.
    const maskIp = (ip: string | null | undefined): string | undefined => {
      if (!ip) return undefined;
      return scrubString(ip);
    };
    const srcIp = maskIp(raw.srcIp);
    const dstIp = maskIp(raw.dstIp);
    const alert: Alert = {
      id: scrubString(raw.id) ?? raw.id,
      timestamp: new Date().toISOString(),
      severity: raw.severity,
      source: raw.source,
      description: scrubString(raw.description) ?? raw.description,
      ...(srcIp ? { srcIp } : {}),
      ...(dstIp ? { dstIp } : {}),
    };
    this.emitted.push(alert);
    while (this.emitted.length > 50) this.emitted.shift();
    return alert;
  }

  /** Recent alerts already emitted — for the initial REST fetch by new clients.
   *  Empty while killed: freezing the WebSocket trickle but still handing the
   *  last 20 live alerts to every page load would leave the plug half-pulled. */
  recentEmitted(limit = 20): Alert[] {
    if (this.athenaKilled) return [];
    return this.emitted.slice(-limit);
  }

  status(): {
    queueLength: number;
    emitted: number;
    lastRefreshAt: number;
    pacingMs: number;
    killed: boolean;
    killSwitchVerified: boolean;
  } {
    return {
      queueLength: this.queue.length,
      emitted: this.emitted.length,
      lastRefreshAt: this.lastRefreshAt,
      pacingMs: this.pacingMs(),
      // Operators need to see the plug is actually pulled from the outside,
      // without the admin bearer the orchestrator's own endpoint requires.
      killed: this.athenaKilled,
      // false = this process has never successfully read the switch, so the
      // feed would NOT freeze if someone threw it. Check this before trusting
      // the plug, not after.
      killSwitchVerified: this.killSwitchVerified,
    };
  }

  /** Apply an observed kill state. Throwing the switch drops everything the
   *  cache is holding: queued and already-emitted alerts are live venue data,
   *  and keeping them in memory to resume from would mean the plug stopped the
   *  refills but not the disclosures. */
  private applyKillState(killed: boolean): void {
    if (killed === this.athenaKilled) return;
    console.log(`[alertCache] kill-switch now ${killed ? 'ON (feed frozen, buffers dropped)' : 'OFF (feed live)'}`);
    this.athenaKilled = killed;
    if (killed) {
      this.queue = [];
      this.emitted = [];
    } else if (this.running) {
      // Restored: refill immediately rather than waiting out the 30 min cycle.
      // Guarded on `running` so a unit test flipping the flag doesn't reach out
      // to Athena as a side effect.
      void this.refresh();
    }
  }

  /** Poll the orchestrator's authoritative kill-switch.
   *
   *  Only a SUCCESSFUL read may change the cached state. An unreachable
   *  orchestrator, a 500, a bad token or a missing token all leave the current
   *  state alone: at boot that means the feed stays live (nothing was ever
   *  killed), and after a kill it means the freeze holds. The previous version
   *  set the flag to false on every one of those paths, so anything that took
   *  the orchestrator down also un-froze the feed. */
  private async refreshKillSwitch(): Promise<void> {
    const token = adminBearerToken();
    if (!token) {
      console.warn('[alertCache] ADMIN_BEARER_TOKEN unset; cannot verify kill-switch (state unchanged)');
      return;
    }
    try {
      const resp = await fetch(`${ORCHESTRATOR_URL}/admin/killswitch`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(10000),
      });
      if (!resp.ok) {
        console.warn(`[alertCache] killswitch check returned ${resp.status}; state unchanged (killed=${this.athenaKilled})`);
        return;
      }
      const data = (await resp.json()) as Record<string, boolean>;
      this.killSwitchVerified = true;
      this.applyKillState(data.athena_hunter === true);
    } catch (err) {
      console.warn(
        `[alertCache] killswitch check failed; state unchanged (killed=${this.athenaKilled}):`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  private async refresh(): Promise<boolean> {
    // The plug stops the pull, not just the push: a killed feed must not keep
    // fetching venue alerts out of Athena into this process every 30 minutes.
    if (this.athenaKilled) {
      console.warn('[alertCache] refresh skipped: kill-switch active');
      return false;
    }
    try {
      const url = `${ATHENA_HUNTER_URL}/alerts/recent?hours=${LOOKBACK_HOURS}&limit=${MAX_ALERTS}`;
      const resp = await fetch(url, { signal: AbortSignal.timeout(60000) });
      if (!resp.ok) {
        console.warn(`[alertCache] athena-hunter returned ${resp.status}`);
        return false;
      }
      const data = (await resp.json()) as { alerts?: RawAlert[]; count?: number; athena_ms?: number };
      if (!Array.isArray(data.alerts)) {
        console.warn('[alertCache] malformed response');
        return false;
      }
      // Shuffle so consecutive trickle doesn't surface 30 alerts from the same IP
      this.queue = shuffle(data.alerts);
      this.lastRefreshAt = Date.now();
      console.log(
        `[alertCache] refreshed: ${data.alerts.length} alerts, athena=${data.athena_ms ?? '?'}ms, pacing=${this.pacingMs()}ms`,
      );
      return true;
    } catch (err) {
      console.warn('[alertCache] refresh failed:', err instanceof Error ? err.message : err);
      return false;
    }
  }
}

function shuffle<T>(arr: T[]): T[] {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

export const alertCache = new AlertCache();

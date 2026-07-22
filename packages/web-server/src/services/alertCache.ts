import { Alert } from '@bhnoc/shared';

const ATHENA_HUNTER_URL = process.env.ATHENA_HUNTER_URL ?? 'http://athena-hunter:8005';
const REFRESH_INTERVAL_MS = parseInt(process.env.ALERT_REFRESH_MS ?? '1800000', 10); // 30 min
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

function scrubString(s: string | null | undefined): string | undefined {
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

interface RawAlert {
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
  private running = false;

  start(): void {
    if (this.running) return;
    this.running = true;
    void this.bootRefresh();
    this.refreshTimer = setInterval(() => void this.refresh(), REFRESH_INTERVAL_MS);
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
      id: raw.id,
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

  /** Recent alerts already emitted — for the initial REST fetch by new clients. */
  recentEmitted(limit = 20): Alert[] {
    return this.emitted.slice(-limit);
  }

  status(): { queueLength: number; emitted: number; lastRefreshAt: number; pacingMs: number } {
    return {
      queueLength: this.queue.length,
      emitted: this.emitted.length,
      lastRefreshAt: this.lastRefreshAt,
      pacingMs: this.pacingMs(),
    };
  }

  private async refresh(): Promise<boolean> {
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

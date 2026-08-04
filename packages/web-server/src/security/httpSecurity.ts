import { FastifyRequest } from 'fastify';

// Matches a single well-formed IPv4 or IPv6 address (no lists, no whitespace).
// Used to decide whether a client-appendable X-Real-IP header is trustworthy as
// a rate-limit key (see rateLimitKeyGenerator below).
export const SINGLE_IP_RE =
  /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[0-9a-fA-F:]+$/;

// Content-Security-Policy for the served UI. CSS/JS live in static/app.css and
// static/app.js ('self'). Inline onclick handlers still need 'unsafe-inline' on
// script-src (acceptable: first-party static UI). Google Fonts is the only
// external origin (stylesheet + font files).
export const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  // First-party video only (the /Manifold wall). default-src would already
  // cover it; stated explicitly so a later default-src change cannot silently
  // widen or break it.
  "media-src 'self'",
  "connect-src 'self' ws: wss:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

// Baseline security headers applied to every response (hand-rolled; no helmet dep).
export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

/**
 * Rate-limit key. nginx OVERWRITES X-Real-IP at the edge, so behind the proxy this
 * is always a single trusted client IP. But a direct hit to the container (bypassing
 * nginx / SSRF) lets an attacker rotate X-Real-IP to mint unlimited buckets. So only
 * trust it when it's a single well-formed IP; a list ("a, b") or garbage falls back to
 * req.ip. The edge remains the primary control -- this just denies the trivial
 * direct-hit bypass.
 */
export function rateLimitKeyGenerator(req: FastifyRequest): string {
  const header = req.headers['x-real-ip'];
  const realIp = (Array.isArray(header) ? header[0] : header)?.trim();
  const isSingleIp = !!realIp && SINGLE_IP_RE.test(realIp);
  return isSingleIp ? realIp : req.ip;
}

/**
 * Must carry statusCode: @fastify/rate-limit hands this object to Fastify's error
 * path, and without an explicit statusCode Fastify defaults it to 500 (which breaks
 * client backoff and trips the ">1% API error rate" alarm).
 */
export function rateLimitErrorResponse(): {
  statusCode: number;
  error: string;
  message: string;
} {
  return {
    statusCode: 429,
    error: 'Too Many Requests',
    message: 'Rate limit exceeded. Please wait before sending more queries.',
  };
}

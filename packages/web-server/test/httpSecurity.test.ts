import { describe, it, expect } from 'vitest';
import type { FastifyRequest } from 'fastify';
import {
  CSP,
  SECURITY_HEADERS,
  rateLimitKeyGenerator,
  rateLimitErrorResponse,
} from '../src/security/httpSecurity';

// Minimal FastifyRequest-shaped stub for keyGenerator: headers + req.ip.
function req(xRealIp: string | string[] | undefined, ip = '203.0.113.9'): FastifyRequest {
  return {
    headers: xRealIp === undefined ? {} : { 'x-real-ip': xRealIp },
    ip,
  } as unknown as FastifyRequest;
}

describe('rateLimitKeyGenerator (sweep-1 web-1 + sweep-5 sec-2)', () => {
  it('keys on a well-formed single X-Real-IP', () => {
    expect(rateLimitKeyGenerator(req('198.51.100.7'))).toBe('198.51.100.7');
  });

  it('falls back to req.ip for a comma-LIST X-Real-IP (no new bucket)', () => {
    expect(rateLimitKeyGenerator(req('198.51.100.7, 10.0.0.1'))).toBe('203.0.113.9');
  });

  it('falls back to req.ip for garbage X-Real-IP', () => {
    expect(rateLimitKeyGenerator(req('junk'))).toBe('203.0.113.9');
  });

  it('falls back to req.ip when X-Real-IP is missing', () => {
    expect(rateLimitKeyGenerator(req(undefined))).toBe('203.0.113.9');
  });

  it('trims whitespace on a single well-formed IP', () => {
    expect(rateLimitKeyGenerator(req('  198.51.100.7  '))).toBe('198.51.100.7');
  });
});

describe('rateLimitErrorResponse (429 not 500, sweep-5 sec-1)', () => {
  it('returns statusCode 429', () => {
    const body = rateLimitErrorResponse();
    expect(body.statusCode).toBe(429);
    expect(body.statusCode).not.toBe(500);
    expect(body.error).toBe('Too Many Requests');
  });
});

describe('CSP / security headers (sweep-4 web-10)', () => {
  it('CSP string is present with expected directives', () => {
    expect(CSP).toContain("default-src 'self'");
    expect(CSP).toContain("frame-ancestors 'none'");
    expect(CSP).toContain("base-uri 'self'");
  });

  it('security-header set includes CSP, X-Frame-Options DENY, nosniff, Referrer-Policy', () => {
    expect(SECURITY_HEADERS['Content-Security-Policy']).toBe(CSP);
    expect(SECURITY_HEADERS['X-Frame-Options']).toBe('DENY');
    expect(SECURITY_HEADERS['X-Content-Type-Options']).toBe('nosniff');
    expect(SECURITY_HEADERS['Referrer-Policy']).toBe('no-referrer');
  });
});

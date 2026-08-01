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

// uuid v14 is ESM-only ("type": "module"). This package compiles to CommonJS, so it
// is loaded via require(), which Node only supports for ESM from 20.19.0 / 22.12.0.
// The container is node:20-slim, currently 20.20.2, so it works. But a base-image
// downgrade would break session-cookie and jobId minting at RUNTIME with
// ERR_REQUIRE_ESM, and typecheck would not catch it (the WebSocket v11 change
// already proved tsc is not a runtime guarantee here).
describe('uuid v14 ESM interop under CommonJS', () => {
  it('is requirable from CommonJS on this Node', () => {
    const { v4 } = require('uuid');
    expect(typeof v4).toBe('function');
    expect(v4()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('runs on a Node new enough for require(esm)', () => {
    const [maj, min] = process.versions.node.split('.').map(Number);
    const ok = maj > 20 || (maj === 20 && min >= 19);
    expect(ok).toBe(true);
  });
});

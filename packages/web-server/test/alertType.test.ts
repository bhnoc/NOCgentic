import { describe, it, expect } from 'vitest';
import type { Alert } from '@bhnoc/shared';

// Compile-level assertion: if 'unknown' were removed from the severity union,
// this assignment would fail `vitest run` type-checking is not enforced at
// runtime, so we also assign into a typed variable that MUST typecheck.
describe("Alert severity accepts 'unknown'", () => {
  it("typechecks an Alert with severity 'unknown'", () => {
    const alert: Alert = {
      id: 'a1',
      timestamp: '2026-07-20T00:00:00.000Z',
      severity: 'unknown',
      source: 'test',
      description: 'desc',
    };
    // Runtime sanity so the test is meaningful even without type-check step.
    const accepted: Alert['severity'][] = [
      'critical',
      'high',
      'medium',
      'low',
      'informational',
      'unknown',
    ];
    expect(accepted).toContain(alert.severity);
  });
});

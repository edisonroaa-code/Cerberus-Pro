import { describe, expect, it } from 'vitest';
import { computeOmniRiskLevel } from './omniRisk';

describe('computeOmniRiskLevel', () => {
  it('returns LOW for conservative config', () => {
    const level = computeOmniRiskLevel({
      mode: 'web',
      maxParallel: 1,
      vectorsCount: 1,
      sqlRisk: 1,
      sqlLevel: 1,
    });
    expect(level).toBe('LOW');
  });

  it('returns CRITICAL for aggressive config', () => {
    const level = computeOmniRiskLevel({
      mode: 'direct_db',
      maxParallel: 8,
      vectorsCount: 6,
      sqlRisk: 3,
      sqlLevel: 5,
    });
    expect(level).toBe('CRITICAL');
  });
});


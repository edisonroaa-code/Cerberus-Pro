import { describe, expect, it } from 'vitest';
import { formatBlockerForDisplay, normalizeCoverageBlockers, normalizeReport } from './reportNormalization';

const completeCoverage = {
  coverage_summary: {
    coverage_percentage: 100,
    engines_requested: ['SQLMAP'],
    engines_executed: ['SQLMAP'],
    inputs_tested: 3,
    deps_missing: [],
    preflight_ok: true,
    execution_ok: true,
    verdict_phase_completed: true
  },
  conclusive_blockers: []
};

describe('normalizeReport', () => {
  it('downgrades missing dependencies to INCONCLUSIVE', () => {
    const payload = {
      verdict: 'NO_VULNERABLE',
      conclusive: true,
      vulnerable: false,
      coverage: {
        ...completeCoverage,
        coverage_summary: {
          ...completeCoverage.coverage_summary,
          deps_missing: ['playwright']
        },
        conclusive_blockers: [{ code: 'missing_dependencies', message: 'Dependencias faltantes' }]
      }
    };
    const report = normalizeReport(payload);
    expect(report.verdict).toBe('INCONCLUSIVE');
    expect(report.conclusive).toBe(false);
  });

  it('downgrades incomplete engine execution to INCONCLUSIVE', () => {
    const payload = {
      verdict: 'NO_VULNERABLE',
      conclusive: true,
      vulnerable: false,
      coverage: {
        ...completeCoverage,
        coverage_summary: {
          ...completeCoverage.coverage_summary,
          engines_requested: ['SQLMAP', 'ZAP'],
          engines_executed: ['SQLMAP']
        }
      }
    };
    const report = normalizeReport(payload);
    expect(report.verdict).toBe('INCONCLUSIVE');
  });

  it('keeps NO_VULNERABLE only with full critical coverage and no blockers', () => {
    const report = normalizeReport({
      verdict: 'NO_VULNERABLE',
      conclusive: true,
      vulnerable: false,
      coverage: completeCoverage
    });
    expect(report.verdict).toBe('NO_VULNERABLE');
    expect(report.conclusive).toBe(true);
  });

  it('forces VULNERABLE when confirmed finding exists', () => {
    const report = normalizeReport({
      verdict: 'INCONCLUSIVE',
      conclusive: false,
      vulnerable: true,
      coverage: {
        conclusive_blockers: [{ code: 'engine_errors', message: 'errores internos' }]
      }
    });
    expect(report.verdict).toBe('VULNERABLE');
    expect(report.vulnerable).toBe(true);
  });

  it('never elevates backend INCONCLUSIVE to NO_VULNERABLE', () => {
    const report = normalizeReport({
      verdict: 'INCONCLUSIVE',
      conclusive: true,
      vulnerable: false,
      coverage: completeCoverage
    });
    expect(report.verdict).toBe('INCONCLUSIVE');
    expect(report.conclusive).toBe(false);
  });

  it('formats structured blockers without raw object rendering', () => {
    const blockers = normalizeCoverageBlockers({
      conclusive_blockers: [{ code: 'missing_deps', message: 'Falta sqlmap', detail: { dep: 'sqlmap' } }]
    });
    expect(blockers).toHaveLength(1);
    expect(formatBlockerForDisplay(blockers[0])).toBe('missing_deps: Falta sqlmap');
  });

  it('collapses duplicate blockers with same code+phase', () => {
    const blockers = normalizeCoverageBlockers({
      conclusive_blockers: [
        { code: 'missing_vectors', message: 'Vectores requeridos no ejecutados', phase: 'verdict' },
        { code: 'missing_vectors', message: 'vectores no ejecutados', phase: 'verdict' },
        { code: 'vector_failures', message: 'Fallas o timeout en vectores', phase: 'verdict' }
      ]
    });
    expect(blockers.map((b) => b.code)).toEqual(['missing_vectors', 'vector_failures']);
  });
});

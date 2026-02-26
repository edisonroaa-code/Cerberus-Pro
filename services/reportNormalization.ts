export type ReportVerdict = 'VULNERABLE' | 'NO_VULNERABLE' | 'INCONCLUSIVE';

export type ConclusiveBlocker = {
  code: string;
  message: string;
  detail?: unknown;
  phase?: string;
  recoverable?: boolean;
};

type CoverageSummary = {
  coverage_percentage?: number;
  engines_requested?: string[];
  engines_executed?: string[];
  inputs_tested?: number;
  deps_missing?: string[];
  preflight_ok?: boolean;
  execution_ok?: boolean;
  verdict_phase_completed?: boolean;
};

export type ReportState = {
  verdict: ReportVerdict;
  conclusive: boolean;
  vulnerable: boolean;
  message: string;
  count: number;
  evidenceCount: number;
  resultsCount: number;
  data: any[];
  coverage: Record<string, any> | null;
  kind: string;
  mode: string;
  scanId: string;
};

const VALID_VERDICTS = new Set<ReportVerdict>(['VULNERABLE', 'NO_VULNERABLE', 'INCONCLUSIVE']);

export const safeStringify = (value: unknown, pretty = false): string => {
  try {
    const seen = new WeakSet<object>();
    return JSON.stringify(
      value,
      (_k, v) => {
        if (typeof v === 'object' && v !== null) {
          if (seen.has(v)) return '[Circular]';
          seen.add(v);
        }
        return v;
      },
      pretty ? 2 : 0
    );
  } catch {
    return String(value ?? '');
  }
};

const toObject = (value: unknown): Record<string, any> | null => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, any>;
};

const parseBoolean = (value: unknown): boolean | undefined => {
  if (typeof value === 'boolean') return value;
  return undefined;
};

const toStringList = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v ?? '').trim()).filter(Boolean);
};

const normalizeBlocker = (entry: unknown): ConclusiveBlocker | null => {
  if (entry === null || entry === undefined) return null;
  if (typeof entry === 'string') {
    const text = entry.trim();
    if (!text) return null;
    const sep = text.indexOf(':');
    if (sep > 0) {
      const code = text.slice(0, sep).trim().toLowerCase().replace(/\s+/g, '_');
      const message = text.slice(sep + 1).trim() || text;
      return { code: code || 'legacy_blocker', message, detail: { raw: text } };
    }
    return { code: text.toLowerCase().replace(/\s+/g, '_'), message: text, detail: { raw: text } };
  }
  if (typeof entry !== 'object') return null;
  const item = entry as Record<string, any>;
  const code = String(item.code ?? item.category ?? 'legacy_blocker').trim().toLowerCase().replace(/\s+/g, '_');
  const message = String(item.message ?? item.detail ?? item.raw ?? code).trim();
  if (!message) return null;
  const detail = item.detail !== undefined ? item.detail : (item.raw !== undefined ? { raw: item.raw } : undefined);
  return {
    code: code || 'legacy_blocker',
    message,
    detail,
    phase: item.phase ? String(item.phase) : undefined,
    recoverable: parseBoolean(item.recoverable)
  };
};

export const normalizeCoverageBlockers = (coverage: unknown): ConclusiveBlocker[] => {
  const cov = toObject(coverage);
  if (!cov) return [];
  const raw = Array.isArray(cov.conclusive_blockers) ? cov.conclusive_blockers : [];
  const normalized = raw.map(normalizeBlocker).filter((b): b is ConclusiveBlocker => Boolean(b));
  const seen = new Set<string>();
  const deduped: ConclusiveBlocker[] = [];
  for (const blocker of normalized) {
    const key = `${blocker.code}|${blocker.message}|${String(blocker.phase || '')}|${safeStringify(blocker.detail)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(blocker);
  }

  // Defensive dedupe: keep a single blocker per semantic key (code+phase).
  // Backend should already avoid this, but legacy payloads can still duplicate with different wording.
  const bySemantic = new Map<string, ConclusiveBlocker>();
  for (const blocker of deduped) {
    const semanticKey = `${String(blocker.code || '').trim().toLowerCase()}|${String(blocker.phase || '').trim().toLowerCase()}`;
    const prev = bySemantic.get(semanticKey);
    if (!prev) {
      bySemantic.set(semanticKey, blocker);
      continue;
    }
    bySemantic.set(semanticKey, {
      ...prev,
      detail: prev.detail !== undefined ? prev.detail : blocker.detail,
      recoverable: prev.recoverable !== undefined ? prev.recoverable : blocker.recoverable,
    });
  }

  return Array.from(bySemantic.values());
};

export const formatBlockerForDisplay = (blocker: ConclusiveBlocker): string => {
  const code = String(blocker.code || '').trim();
  const message = String(blocker.message || '').trim();
  if (code && message) return `${code}: ${message}`;
  return message || code || 'coverage_incomplete';
};

const extractSummary = (coverage: Record<string, any> | null): CoverageSummary => {
  if (!coverage) return {};
  const nested = toObject(coverage.coverage_summary);
  const ledger = toObject(coverage.ledger);
  return {
    coverage_percentage: Number((nested?.coverage_percentage ?? ledger?.coverage_percentage ?? coverage.coverage_percentage) ?? 0),
    engines_requested: toStringList(nested?.engines_requested ?? ledger?.engines_requested),
    engines_executed: toStringList(nested?.engines_executed ?? ledger?.engines_executed),
    inputs_tested: Number((nested?.inputs_tested ?? ledger?.inputs_tested ?? coverage.tested_parameters_count) ?? 0),
    deps_missing: toStringList(nested?.deps_missing ?? ledger?.deps_missing ?? coverage.missing_dependencies),
    preflight_ok: parseBoolean(nested?.preflight_ok),
    execution_ok: parseBoolean(nested?.execution_ok),
    verdict_phase_completed: parseBoolean(nested?.verdict_phase_completed)
  };
};

const isCriticalCoverageComplete = (summary: CoverageSummary, blockers: ConclusiveBlocker[]): boolean => {
  const requested = (summary.engines_requested || []).filter(Boolean);
  const executed = (summary.engines_executed || []).filter(Boolean);
  const depsMissing = (summary.deps_missing || []).filter(Boolean);
  const inputsTested = Number(summary.inputs_tested ?? 0);
  const requestedSet = new Set(requested.map((e) => e.toUpperCase()));
  const executedSet = new Set(executed.map((e) => e.toUpperCase()));
  const sameEngines = requestedSet.size > 0 && requestedSet.size === executedSet.size && [...requestedSet].every((e) => executedSet.has(e));
  const preflightOk = summary.preflight_ok !== false;
  const executionOk = summary.execution_ok !== false;
  const verdictPhaseCompleted = summary.verdict_phase_completed !== false;
  return Boolean(
    sameEngines &&
    inputsTested > 0 &&
    depsMissing.length === 0 &&
    blockers.length === 0 &&
    preflightOk &&
    executionOk &&
    verdictPhaseCompleted
  );
};

export const normalizeReport = (payload: unknown, fallbackMessage = ''): ReportState => {
  const data = toObject(payload) || {};
  const coverage = toObject(data.coverage);
  const blockers = normalizeCoverageBlockers(coverage);
  const summary = extractSummary(coverage);
  const criticalComplete = isCriticalCoverageComplete(summary, blockers);
  const rawVerdict = String(data.verdict || '').toUpperCase();
  const backendVerdict = VALID_VERDICTS.has(rawVerdict as ReportVerdict) ? (rawVerdict as ReportVerdict) : undefined;
  const vulnerable = Boolean(data.vulnerable);

  let verdict: ReportVerdict = 'INCONCLUSIVE';

  if (vulnerable || backendVerdict === 'VULNERABLE') {
    verdict = 'VULNERABLE';
  } else if (backendVerdict === 'INCONCLUSIVE') {
    verdict = 'INCONCLUSIVE';
  } else if (backendVerdict === 'NO_VULNERABLE') {
    verdict = criticalComplete ? 'NO_VULNERABLE' : 'INCONCLUSIVE';
  } else {
    verdict = 'INCONCLUSIVE';
  }

  const backendConclusive = parseBoolean(data.conclusive);
  const conclusive = verdict === 'INCONCLUSIVE' ? false : (backendConclusive === false ? false : true);
  const extractedData = Array.isArray(data.data) ? data.data : [];
  const resultsCount = Number(data.results_count ?? data.resultsCount ?? data.count ?? extractedData.length ?? 0) || 0;
  const evidenceDefault = vulnerable ? extractedData.length : 0;
  const evidenceCount = Number(data.evidence_count ?? data.evidenceCount ?? evidenceDefault) || 0;

  const payloadMessage = String(data.msg || data.message || '').trim();
  const message = payloadMessage
    || fallbackMessage
    || (
      verdict === 'VULNERABLE'
        ? 'VULNERABLE - Se detectaron evidencias de explotación.'
        : verdict === 'NO_VULNERABLE'
          ? 'NO VULNERABLE - Sin hallazgos con cobertura completa.'
          : 'INCONCLUSO - Cobertura insuficiente o bloqueos detectados.'
    );

  const normalizedCoverage = coverage
    ? {
      ...coverage,
      conclusive_blockers: blockers,
      coverage_summary: {
        ...(toObject(coverage.coverage_summary) || {}),
        ...summary
      }
    }
    : null;

  return {
    verdict,
    conclusive,
    vulnerable: verdict === 'VULNERABLE' ? true : vulnerable,
    message,
    count: resultsCount,
    evidenceCount,
    resultsCount,
    data: extractedData,
    coverage: normalizedCoverage,
    kind: String(data.kind || coverage?.kind || ''),
    mode: String(data.mode || coverage?.mode || ''),
    scanId: String(data.scan_id || coverage?.scan_id || '')
  };
};

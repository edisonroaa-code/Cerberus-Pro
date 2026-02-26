import React from 'react';
import clsx from 'clsx';
import { formatBlockerForDisplay, normalizeCoverageBlockers } from '../services/reportNormalization';

interface ReportPanelProps {
  verdict?: 'VULNERABLE' | 'NO_VULNERABLE' | 'INCONCLUSIVE';
  conclusive?: boolean;
  vulnerable: boolean;
  message: string;
  count?: number;
  evidenceCount?: number;
  resultsCount?: number;
  logs?: any[];
  coverage?: any;
  onExportMarkdown?: () => void;
  onExportExcel?: () => void;
  onRetry?: () => void;
  isVisible: boolean;
}

const translateLogObject = (obj: any): any => {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(translateLogObject);

  const translated: any = {};
  for (const [key, value] of Object.entries(obj)) {
    let newKey = key;
    if (key === 'vector') newKey = 'vector_ataque';
    else if (key === 'vulnerable') newKey = 'es_vulnerable';
    else if (key === 'parameter') newKey = 'param_inyectado';
    else if (key === 'evidence') newKey = 'evidencia_tecnica';
    else if (key === 'command') newKey = 'comando_ejecutado';
    else if (key === 'technique') newKey = 'tecnica';

    let newValue = value;
    if (typeof value === 'boolean') {
      newValue = value ? 'SÍ' : 'NO';
    } else if (typeof value === 'string') {
      const v = value.toUpperCase();
      if (v === 'BOOLEAN') newValue = 'BOOLEANO (Blind SI/NO)';
      else if (v === 'ERROR') newValue = 'ERRORES (Error-based)';
      else if (v === 'TIME') newValue = 'TIEMPO (Blind por Tiempo)';
      else if (v === 'UNION') newValue = 'UNION QUERY';
      else if (v === 'STACKED') newValue = 'QUERIES APILADOS (Stacked)';
      else if (v === 'INLINE') newValue = 'INLINE QUERIES';
      else if (v === 'AIIE') newValue = 'MOTOR DE IA (AIIE)';
      else if (v === 'SQLMAP') newValue = 'MOTOR SQLMAP LOCAL';
    } else if (typeof value === 'object') {
      newValue = translateLogObject(value);
    }
    translated[newKey] = newValue;
  }
  return translated;
};

const ReportPanel: React.FC<ReportPanelProps> = ({
  verdict,
  conclusive,
  vulnerable,
  message,
  count = 0,
  evidenceCount,
  resultsCount,
  logs,
  coverage,
  onExportMarkdown,
  onExportExcel,
  onRetry,
  isVisible
}) => {
  if (!isVisible) return null;

  const effectiveVerdict =
    verdict || (vulnerable ? 'VULNERABLE' : 'INCONCLUSIVE');

  const isInconclusive =
    effectiveVerdict === 'INCONCLUSIVE' ||
    (conclusive === false && effectiveVerdict !== 'VULNERABLE');

  const variant: 'danger' | 'warn' | 'ok' =
    effectiveVerdict === 'VULNERABLE' ? 'danger' : (isInconclusive ? 'warn' : 'ok');

  const borderClass =
    variant === 'danger'
      ? 'border-red-500'
      : (variant === 'warn' ? 'border-amber-500' : 'border-emerald-500');

  const headerClass =
    variant === 'danger'
      ? 'border-red-500 bg-red-500/10'
      : (variant === 'warn' ? 'border-amber-500 bg-amber-500/10' : 'border-emerald-500 bg-emerald-500/10');

  const dotClass =
    variant === 'danger'
      ? 'bg-red-500'
      : (variant === 'warn' ? 'bg-amber-500' : 'bg-emerald-500');

  const titleClass =
    variant === 'danger'
      ? 'text-red-400'
      : (variant === 'warn' ? 'text-amber-300' : 'text-emerald-400');

  const titleText =
    variant === 'danger'
      ? '⚠️ VULNERABILIDAD ENCONTRADA'
      : (variant === 'warn' ? '⏸️ ANÁLISIS INCONCLUSO' : '✓ ANÁLISIS COMPLETADO');

  const evidence = typeof evidenceCount === 'number' ? evidenceCount : count;
  const results = typeof resultsCount === 'number' ? resultsCount : count;
  const safeStringify = (value: unknown, pretty = false): string => {
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
  const formatValue = (value: unknown): string => {
    if (value === null || value === undefined) return '(sin datos)';
    if (typeof value === 'string') {
      const text = value.trim();
      if (!text) return '(vacío)';
      if (text === '[object Object]') return '(objeto sin serializar en origen)';
      if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
        try {
          return safeStringify(JSON.parse(text), false);
        } catch {
          return text;
        }
      }
      return text;
    }
    if (typeof value === 'object') return safeStringify(value, false);
    return String(value);
  };
  const blockers = normalizeCoverageBlockers(coverage).map(formatBlockerForDisplay);

  const summary = coverage?.coverage_summary && typeof coverage.coverage_summary === 'object' ? coverage.coverage_summary : {};
  const ledger = coverage?.ledger && typeof coverage.ledger === 'object' ? coverage.ledger : {};
  const coveragePctRaw = Number(summary.coverage_percentage ?? ledger.coverage_percentage ?? coverage?.coverage_percentage);
  const coveragePct = Number.isFinite(coveragePctRaw) ? coveragePctRaw : null;
  const enginesRequested = Array.isArray(summary.engines_requested) ? summary.engines_requested : (Array.isArray(ledger.engines_requested) ? ledger.engines_requested : []);
  const enginesExecuted = Array.isArray(summary.engines_executed) ? summary.engines_executed : (Array.isArray(ledger.engines_executed) ? ledger.engines_executed : []);
  const depsMissing = Array.isArray(summary.deps_missing)
    ? summary.deps_missing
    : (Array.isArray(ledger.deps_missing) ? ledger.deps_missing : (Array.isArray(coverage?.missing_dependencies) ? coverage.missing_dependencies : []));
  const inputsTested = Number(summary.inputs_tested ?? ledger.inputs_tested ?? coverage?.tested_parameters_count);
  const inputsTestedSafe = Number.isFinite(inputsTested) ? inputsTested : null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className={clsx(
        "bg-cyber-900 border-2 rounded-lg shadow-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden",
        borderClass
      )}>
        {/* Header */}
        <div className={clsx(
          "px-6 py-4 border-b-2 flex items-center gap-3",
          headerClass
        )}>
          <div className={clsx(
            "w-4 h-4 rounded-full animate-pulse",
            dotClass
          )} />
          <h2 className={clsx(
            "text-xl font-bold",
            titleClass
          )}>
            {titleText}
          </h2>
        </div>

        {/* Content */}
        <div className="px-6 py-6 space-y-4 overflow-y-auto flex-1 custom-scrollbar">
          <p className="text-gray-300">{message}</p>
          {coverage ? (
            <div className="bg-cyber-950/50 border border-cyber-700 rounded p-3 space-y-1">
              <p className="text-cyan-300 font-bold text-xs">Resumen de Cobertura</p>
              <p className="text-gray-300 text-xs">
                Cobertura: {coveragePct !== null ? `${coveragePct.toFixed(1)}%` : 'n/a'}
                {' | '}Inputs probados: {inputsTestedSafe !== null ? inputsTestedSafe : 'n/a'}
              </p>
              <p className="text-gray-300 text-xs">
                Motores: {enginesExecuted.length}/{enginesRequested.length}
                {' | '}Dependencias faltantes: {depsMissing.length}
              </p>
            </div>
          ) : null}

          {variant === 'danger' && (
            <div className="bg-red-500/10 border border-red-500 rounded p-4 space-y-3">
              <p className="text-red-400 font-bold">Hallazgo:</p>
              <p className="text-red-300 text-sm">
                Se detectaron {evidence} punto(s) de evidencia.
                Hay indicios suficientes para marcar el objetivo como vulnerable.
              </p>

              {logs && logs.length > 0 && (
                <div className="mt-3 bg-red-900/30 rounded p-3 max-h-64 overflow-y-auto">
                  <p className="text-red-300 font-bold text-xs mb-2">📊 Datos Extraídos:</p>
                  <ul className="text-red-300 text-xs space-y-1 font-mono">
                    {logs.map((line, idx) => (
                      <li key={idx} className="break-all whitespace-pre-wrap">
                        {formatValue(translateLogObject(line))}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {variant === 'warn' && (
            <div className="bg-amber-500/10 border border-amber-500 rounded p-4 space-y-3">
              <p className="text-amber-300 font-bold">Resultado:</p>
              <p className="text-amber-200 text-sm">
                El sistema no puede afirmar “NO VULNERABLE” con certeza. Falta cobertura o hubo bloqueos/errores.
              </p>
              {blockers.length ? (
                <div className="bg-amber-950/30 rounded p-3">
                  <p className="text-amber-200 font-bold text-xs mb-2">Cobertura / Bloqueos:</p>
                  <ul className="text-amber-200 text-xs space-y-1 font-mono">
                    {blockers.slice(0, 12).map((b: string, idx: number) => (
                      <li key={idx} className="break-all">{b}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <p className="text-amber-200 text-xs">
                Evidencias técnicas: {evidence} | Resultados: {results}
              </p>
            </div>
          )}

          {variant === 'ok' && (
            <div className="bg-emerald-500/10 border border-emerald-500 rounded p-4">
              <p className="text-emerald-400 font-bold">Resultado:</p>
              <p className="text-emerald-300 text-sm mt-2">
                No se detectaron vulnerabilidades con la cobertura ejecutada.
              </p>
              <p className="text-emerald-300 text-xs mt-2">
                Evidencias técnicas: {evidence} | Resultados: {results}
              </p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="px-6 py-4 border-t border-cyber-700 bg-cyber-950 flex gap-3 flex-wrap">
          <button
            onClick={onExportMarkdown}
            className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition-colors flex items-center justify-center gap-2"
          >
            📋 Exportar Markdown
          </button>
          <button
            onClick={onExportExcel}
            className="flex-1 bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition-colors flex items-center justify-center gap-2"
          >
            📊 Exportar Excel
          </button>
          <button
            onClick={onRetry || (() => window.location.reload())}
            className="flex-1 bg-cyber-700 hover:bg-cyber-600 text-gray-300 font-bold py-2 px-4 rounded transition-colors"
          >
            ✕ Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReportPanel;

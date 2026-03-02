import { LogEntry, AttackProfile } from '../types';
import { API_BASE_URL } from './apiConfig';

/**
 * Cerberus AI Service - Frontend Bridge.
 * 
 * Instead of calling Google SDK directly (which leaks keys and fails in browser),
 * we proxy all tactical and forensic AI requests through the Cerberus Backend.
 */

const buildAiHeaders = (accessToken?: string | null): HeadersInit => {
  const token = `${accessToken || localStorage.getItem('token') || ''}`.trim();
  return token
    ? {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
    : {
      'Content-Type': 'application/json'
    };
};

export const analyzeWafResponse = async (
  logEntry: LogEntry,
  currentProfile: AttackProfile,
  accessToken?: string | null
): Promise<string> => {
  try {
    const response = await fetch(`${API_BASE_URL}/ai/analyze-waf`, {
      method: 'POST',
      credentials: 'include',
      headers: buildAiHeaders(accessToken),
      body: JSON.stringify({
        signal_data: {
          block_rate: (logEntry.message.toLowerCase().includes('waf') || logEntry.message.toLowerCase().includes('403')) ? 1.0 : 0.0,
          message: logEntry.message
        },
        scan_context: {
          current_profile: currentProfile,
          component: logEntry.component
        }
      })
    });

    if (!response.ok) throw new Error("Backend AI unavailable");

    const data = await response.json();

    // Format the tactical decision into the UI block
    return `### 🧠 ANÁLISIS CORTEX AI (${data.source || 'gemini'})\n\n` +
      `**Análisis**: ${data.reasoning || 'Detección de patrones de bloqueo'}\n\n` +
      `**Acción Táctica**: ${data.action.toUpperCase()}\n\n` +
      `**Recomendación**: ${JSON.stringify(data.params)}\n\n` +
      `**Confianza**: ${(data.confidence * 100).toFixed(0)}%`;

  } catch (error) {
    console.error("Cortex Analysis Failed:", error);
    return heuristicAnalysis(logEntry, currentProfile);
  }
};

export const generateExecutiveReport = async (logs: LogEntry[], accessToken?: string | null): Promise<string> => {
  try {
    const findings = logs.filter(l => l.level === 'SUCCESS' || l.level === 'CRITICAL');
    const maxWindow = 200;
    const recent = logs.slice(-maxWindow);
    const components = recent
      .map((entry) => `${entry.component || ''}`.trim())
      .filter(Boolean);
    const uniqueComponents = new Set(components);
    const inferredCoverage = recent.length
      ? Math.round((uniqueComponents.size / Math.max(1, recent.length)) * 10000) / 100
      : 0;

    const response = await fetch(`${API_BASE_URL}/ai/generate-narrative`, {
      method: 'POST',
      credentials: 'include',
      headers: buildAiHeaders(accessToken),
      body: JSON.stringify({
        verdict_status: findings.length > 0 ? "VULNERABLE" : "INCONCLUSIVE",
        findings: findings.map(f => ({ message: f.message, component: f.component })),
        coverage_pct: inferredCoverage
      })
    });

    if (!response.ok) throw new Error("Backend Narrative failed");
    const data = await response.json();
    return data.narrative;

  } catch (error) {
    return localExecutiveReport(logs);
  }
};

const heuristicAnalysis = (logEntry: LogEntry, currentProfile: AttackProfile): string => {
  const msg = logEntry.message.toLowerCase();
  let analysis = "No se pudo realizar el análisis de IA. Análisis heurístico local activado.";
  let recommendation = "Continuar con precaución.";
  let command = "N/A";

  if (msg.includes("waf") || msg.includes("bloqueo") || msg.includes("forbidden") || msg.includes("403")) {
    analysis = "Se detectó una respuesta de bloqueo del WAF. Probablemente causada por firmas de sqlmap o frecuencia de peticiones.";
    recommendation = "Cambiar a perfil 'Corporativo-Sigiloso' para aumentar el delay y randomizar headers.";
    command = "set profile Corporativo-Sigiloso";
  } else if (msg.includes("connection reset") || msg.includes("timeout")) {
    analysis = "El servidor o el IPS están cortando las conexiones activamente.";
    recommendation = "Reducir el número de hilos o activar modo HPP (HTTP Parameter Pollution).";
    command = "set sqlmap.threads 1";
  }

  return `### 🛡️ ANÁLISIS LOCAL (Fallback)\n\n**Análisis**: ${analysis}\n\n**Recomendación**: ${recommendation}\n\n**Comando Sugerido**: \`${command}\``;
};

const localExecutiveReport = (logs: LogEntry[]): string => {
  const recent = logs.slice(-200);
  const total = recent.length || 1;
  const errors = recent.filter((l) => l.level === 'ERROR').length;
  const warns = recent.filter((l) => l.level === 'WARN').length;
  const success = recent.filter((l) => l.level === 'SUCCESS').length;

  const health = Math.max(0, 100 - Math.round(((errors + warns * 0.5) / total) * 100));
  const successRate = Math.min(100, Math.round((success / total) * 100));

  return [
    "### RESUMEN EJECUTIVO (Fallback Local)",
    "",
    `- Señales analizadas: **${recent.length}**`,
    `- Estabilidad operativa estimada: **${health}%**`,
    `- Éxitos observados: **${success}** (${successRate}%)`,
    "",
    "**Recomendación táctica**",
    "- Mantener cobertura por vectores y validar hallazgos con evidencia reproducible."
  ].join('\n');
};

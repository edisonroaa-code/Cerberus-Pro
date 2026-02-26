import { GoogleGenAI } from "@google/genai";
import { LogEntry, AttackProfile } from '../types';

const apiKey = process.env.API_KEY;

// Initialize the client conditionally to handle cases where the key might be missing during dev
const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;
export const GEMINI_ONLINE = Boolean(ai);

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
  } else if (msg.includes("honeypot") || msg.includes("decoy")) {
    analysis = "Se sospecha la presencia de un Honeypot/Decoy.";
    recommendation = "Activar modo sigilo absoluto y verificar headers de respuesta en busca de patrones sospechosos.";
  }

  return `### 🛡️ ANÁLISIS LOCAL (Fallback)\n\n**Análisis**: ${analysis}\n\n**Recomendación**: ${recommendation}\n\n**Comando Sugerido**: \`${command}\``;
};

export const analyzeWafResponse = async (logEntry: LogEntry, currentProfile: AttackProfile): Promise<string> => {
  if (!ai) return heuristicAnalysis(logEntry, currentProfile);

  const prompt = `
    Eres el Orquestador de IA para el Sistema de Penetración Cerberus. 
    Analiza el siguiente registro de detección de WAF y proporciona una recomendación táctica EN ESPAÑOL.
    
    Perfil Actual: ${currentProfile}
    Componente del Log: ${logEntry.component}
    Mensaje: ${logEntry.message}
    Metadatos: ${JSON.stringify(logEntry.metadata || {})}

    Proporciona una respuesta concisa (formato texto o markdown ligero) que incluya:
    1. "Análisis": Qué activó probablemente el WAF (ej: User-Agent, palabra clave SQL, frecuencia).
    2. "Recomendación": Acción específica a tomar (ej: Cambiar a perfil Móvil-5G, Aumentar Retraso, Ofuscar Payload).
    3. "Comando": Una acción sugerida o comando CLI.
    
    Responde ÚNICAMENTE en ESPAÑOL.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
    });
    return response.text;
  } catch (error) {
    console.error("Gemini Analysis Failed:", error);
    return heuristicAnalysis(logEntry, currentProfile);
  }
};

export const generateExecutiveReport = async (logs: LogEntry[]): Promise<string> => {
  if (!ai) return localExecutiveReport(logs);

  const recentLogs = logs.slice(-20).map(l => `[${l.component}] ${l.message}`).join('\n');

  const prompt = `
    Genera un breve Resumen Ejecutivo para la sesión de pruebas de penetración actual basado en estos registros recientes.
    
    Logs recientes:
    ${recentLogs}
    
    Enfócate en:
    1. Tasa de éxito general.
    2. Vulnerabilidades clave identificadas (si las hay).
    3. Eficiencia del WAF contra nuestras técnicas de evasión.

    Responde ÚNICAMENTE en ESPAÑOL con un tono profesional de ciberseguridad.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
    });
    return response.text;
  } catch (error) {
    return localExecutiveReport(logs);
  }
};

const localExecutiveReport = (logs: LogEntry[]): string => {
  const recent = logs.slice(-200);
  const total = recent.length || 1;
  const errors = recent.filter((l) => l.level === 'ERROR').length;
  const warns = recent.filter((l) => l.level === 'WARN').length;
  const success = recent.filter((l) => l.level === 'SUCCESS').length;

  const blockSignals = recent.filter((l) => {
    const m = (l.message || '').toLowerCase();
    return m.includes('waf') || m.includes('403') || m.includes('forbidden') || m.includes('blocked') || m.includes('timeout');
  }).length;

  const vulnSignals = recent.filter((l) => {
    const m = (l.message || '').toLowerCase();
    return m.includes('injectable') || m.includes('vulnerable') || m.includes('sql injection') || m.includes('inyección');
  }).length;

  const health = Math.max(0, 100 - Math.round(((errors + warns * 0.5) / total) * 100));
  const successRate = Math.min(100, Math.round((success / total) * 100));

  return [
    "### RESUMEN EJECUTIVO (Fallback Local)",
    "",
    `- Señales analizadas: **${recent.length}**`,
    `- Estabilidad operativa estimada: **${health}%**`,
    `- Éxitos observados: **${success}** (${successRate}%)`,
    `- Señales de bloqueo/WAF: **${blockSignals}**`,
    `- Señales de hallazgo potencial: **${vulnSignals}**`,
    "",
    "**Lectura rápida**",
    blockSignals > vulnSignals
      ? "- Predominan bloqueos defensivos sobre evidencia de explotación."
      : "- Hay más señales de posible hallazgo que de bloqueo defensivo.",
    "",
    "**Recomendación táctica**",
    "- Mantener cobertura por vectores y validar hallazgos con evidencia reproducible antes de emitir veredicto."
  ].join('\n');
};

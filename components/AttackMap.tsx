import React, { useMemo, useState } from 'react';
import { LogEntry, MapNodeDetail, SystemMetrics } from '../types';
import { X } from 'lucide-react';

interface AttackMapProps {
  agentConnected: boolean;
  events: LogEntry[];
  targetUrl: string;
  metrics?: SystemMetrics | null;
}

type NodeId = 'Atacante' | 'Agente Cerberus' | 'Orquestador' | 'Pool Proxies' | 'WAF' | 'BD Objetivo';
type EdgeId = 'ATTACKER_ORCH' | 'AGENT_ORCH' | 'ORCH_PROXY' | 'PROXY_WAF' | 'WAF_TARGET';
type Severity = 'NONE' | 'INFO' | 'SUCCESS' | 'WARN' | 'ERROR';

const LEVEL_SEVERITY: Record<LogEntry['level'], Severity> = {
  INFO: 'INFO',
  SUCCESS: 'SUCCESS',
  WARN: 'WARN',
  ERROR: 'ERROR',
};

function maxSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ['NONE', 'INFO', 'SUCCESS', 'WARN', 'ERROR'];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

function severityColor(sev: Severity) {
  switch (sev) {
    case 'ERROR': return '#ef4444';
    case 'WARN': return '#f59e0b';
    case 'SUCCESS': return '#10b981';
    case 'INFO': return '#38bdf8';
    default: return '#334155';
  }
}

function safeHost(url: string): string {
  try {
    if (!url) return 'sin objetivo';
    const u = new URL(url);
    return u.host || u.hostname || url;
  } catch {
    return url || 'sin objetivo';
  }
}

function shortMsg(s: string, max = 42) {
  const t = (s || '').replace(/\s+/g, ' ').trim();
  if (t.length <= max) return t;
  return t.slice(0, max - 1) + '…';
}

function classifyEdge(log: LogEntry): EdgeId | null {
  const msg = (log.message || '').toLowerCase();
  const comp = log.component;

  // UI/agent -> orchestrator signals (WS, agent modal, etc.)
  if (comp === 'SISTEMA') {
    if (msg.includes('conectado') && msg.includes('websocket')) return 'AGENT_ORCH';
    if (msg.includes('backend no disponible')) return 'AGENT_ORCH';
    if (msg.startsWith('> ')) return 'ATTACKER_ORCH';
  }

  // Orchestrator -> infra
  if (comp === 'ORQUESTADOR') {
    if (msg.includes('job encolado') || msg.includes('enviando comando')) return 'ATTACKER_ORCH';
    if (msg.includes('perfil aplicado') || msg.includes('iniciando')) return 'ORCH_PROXY';
    if (msg.includes('calibration waf') || msg.includes('waf preset')) return 'PROXY_WAF';
  }

  // WAF signals
  if (comp === 'CERBERUS_PRO' || comp === 'SENSOR_WAF' || comp === 'SQLMAP') {
    if (msg.includes('waf') || msg.includes('ips') || msg.includes('captcha') || msg.includes('cloudflare')) return 'PROXY_WAF';
    if (msg.includes('testing url') || msg.includes('probando') || msg.includes('get http') || msg.includes('starting @')) return 'WAF_TARGET';
    if (msg.includes('cookie') || msg.includes('user-agent') || msg.includes('tamper')) return 'ORCH_PROXY';
  }

  // Default: treat engine logs as reaching the target.
  if (comp === 'CERBERUS_PRO' || comp === 'SQLMAP') return 'WAF_TARGET';

  return null;
}

const AttackMap: React.FC<AttackMapProps> = ({ agentConnected, events, targetUrl, metrics = null }) => {
  const [selectedNode, setSelectedNode] = useState<MapNodeDetail | null>(null);

  const computed = useMemo(() => {
    const now = Date.now();
    const horizonMs = 30_000;
    const activeMs = 6_000;

    const last = (events || []).slice(-300); // enough context without overwork per render

    const edgeStats: Record<EdgeId, { count: number; lastTs: number | null; lastMsg: string; severity: Severity }> = {
      ATTACKER_ORCH: { count: 0, lastTs: null, lastMsg: '', severity: 'NONE' },
      AGENT_ORCH: { count: 0, lastTs: null, lastMsg: '', severity: 'NONE' },
      ORCH_PROXY: { count: 0, lastTs: null, lastMsg: '', severity: 'NONE' },
      PROXY_WAF: { count: 0, lastTs: null, lastMsg: '', severity: 'NONE' },
      WAF_TARGET: { count: 0, lastTs: null, lastMsg: '', severity: 'NONE' },
    };

    const ticker: Array<{ ts: number; edge: EdgeId; level: LogEntry['level']; component: LogEntry['component']; message: string }> = [];

    for (const ev of last) {
      const ts = (typeof ev.ts === 'number' ? ev.ts : now);
      if (ts < now - horizonMs) continue;
      const edge = classifyEdge(ev);
      if (!edge) continue;
      const sev = LEVEL_SEVERITY[ev.level] || 'INFO';
      const st = edgeStats[edge];
      st.count += 1;
      st.severity = maxSeverity(st.severity, sev);
      if (!st.lastTs || ts >= st.lastTs) {
        st.lastTs = ts;
        st.lastMsg = ev.message || '';
      }
      ticker.push({ ts, edge, level: ev.level, component: ev.component, message: ev.message || '' });
    }

    const edgeActive: Record<EdgeId, boolean> = {
      ATTACKER_ORCH: !!edgeStats.ATTACKER_ORCH.lastTs && (now - edgeStats.ATTACKER_ORCH.lastTs) <= activeMs,
      AGENT_ORCH: !!edgeStats.AGENT_ORCH.lastTs && (now - edgeStats.AGENT_ORCH.lastTs) <= activeMs,
      ORCH_PROXY: !!edgeStats.ORCH_PROXY.lastTs && (now - edgeStats.ORCH_PROXY.lastTs) <= activeMs,
      PROXY_WAF: !!edgeStats.PROXY_WAF.lastTs && (now - edgeStats.PROXY_WAF.lastTs) <= activeMs,
      WAF_TARGET: !!edgeStats.WAF_TARGET.lastTs && (now - edgeStats.WAF_TARGET.lastTs) <= activeMs,
    };

    const host = safeHost(targetUrl);

    const wafStatus =
      edgeStats.PROXY_WAF.severity === 'ERROR' ? 'Bloqueo/IPS' :
        edgeStats.PROXY_WAF.severity === 'WARN' ? 'Detectado (WAF)' :
          edgeStats.PROXY_WAF.count > 0 ? 'Señales' : 'Sin señales';

    const targetStatus =
      edgeStats.WAF_TARGET.severity === 'ERROR' ? 'Error/timeout' :
        edgeStats.WAF_TARGET.count > 0 ? 'Tráfico' : 'Idle';

    const nodeDetails: Record<NodeId, MapNodeDetail> = {
      'Atacante': {
        id: 'Atacante',
        type: 'Operador (UI)',
        status: 'Local',
        details: [
          'Origen: Consola Cerberus',
          `Eventos(30s): ${edgeStats.ATTACKER_ORCH.count}`,
          `Ultimo: ${shortMsg(edgeStats.ATTACKER_ORCH.lastMsg || 'sin actividad')}`,
        ]
      },
      'Agente Cerberus': {
        id: 'Agente Cerberus',
        type: 'Canal Tiempo Real',
        status: agentConnected ? 'WS ONLINE' : 'WS OFFLINE',
        details: [
          'Nota: este estado refleja el WebSocket UI <-> Motor',
          `Eventos(30s): ${edgeStats.AGENT_ORCH.count}`,
          `Ultimo: ${shortMsg(edgeStats.AGENT_ORCH.lastMsg || 'sin actividad')}`,
        ]
      },
      'Orquestador': {
        id: 'Orquestador',
        type: 'Control',
        status: edgeStats.ORCH_PROXY.count > 0 ? 'Activo' : 'Idle',
        details: [
          `Objetivo: ${host}`,
          `RPS: ${metrics ? metrics.requestsPerSecond.toFixed(1) : 'n/a'}`,
          `Evasion: ${metrics ? Math.round(metrics.evasionRate) + '%' : 'n/a'}`,
        ]
      },
      'Pool Proxies': {
        id: 'Pool Proxies',
        type: 'Transporte',
        status: edgeStats.ORCH_PROXY.severity === 'ERROR' ? 'Degradado' : (edgeStats.ORCH_PROXY.count > 0 ? 'Activo' : 'Idle'),
        details: [
          `Eventos(30s): ${edgeStats.ORCH_PROXY.count}`,
          `Ultimo: ${shortMsg(edgeStats.ORCH_PROXY.lastMsg || 'sin actividad')}`,
          `Bloqueos WAF: ${metrics ? metrics.wafBlockCount : 'n/a'}`,
        ]
      },
      'WAF': {
        id: 'WAF',
        type: 'Defensa',
        status: wafStatus,
        details: [
          `Eventos(30s): ${edgeStats.PROXY_WAF.count}`,
          `Severidad: ${edgeStats.PROXY_WAF.severity}`,
          `Ultimo: ${shortMsg(edgeStats.PROXY_WAF.lastMsg || 'sin actividad')}`,
        ]
      },
      'BD Objetivo': {
        id: 'BD Objetivo',
        type: 'Objetivo Web',
        status: targetStatus,
        details: [
          `Host: ${host}`,
          `Eventos(30s): ${edgeStats.WAF_TARGET.count}`,
          `Ultimo: ${shortMsg(edgeStats.WAF_TARGET.lastMsg || 'sin actividad')}`,
        ]
      },
    };

    const orderedTicker = ticker
      .sort((a, b) => b.ts - a.ts)
      .slice(0, 6);

    return { now, host, edgeStats, edgeActive, nodeDetails, ticker: orderedTicker };
  }, [events, targetUrl, agentConnected, metrics]);

  const width = 960;
  const height = 300;

  const nodes: Array<{ id: NodeId; x: number; y: number; role: 'source' | 'agent' | 'control' | 'proxy' | 'defense' | 'target' }> = [
    { id: 'Atacante', x: 70, y: height / 2, role: 'source' },
    { id: 'Agente Cerberus', x: 190, y: height / 3, role: 'agent' },
    { id: 'Orquestador', x: 320, y: height / 2, role: 'control' },
    { id: 'Pool Proxies', x: 520, y: height / 2, role: 'proxy' },
    { id: 'WAF', x: 700, y: height / 2, role: 'defense' },
    { id: 'BD Objetivo', x: 860, y: height / 2, role: 'target' },
  ];

  const edges: Array<{ id: EdgeId; source: NodeId; target: NodeId; label: string }> = [
    { id: 'ATTACKER_ORCH', source: 'Atacante', target: 'Orquestador', label: 'Comando' },
    { id: 'AGENT_ORCH', source: 'Agente Cerberus', target: 'Orquestador', label: 'WS' },
    { id: 'ORCH_PROXY', source: 'Orquestador', target: 'Pool Proxies', label: 'Evasión' },
    { id: 'PROXY_WAF', source: 'Pool Proxies', target: 'WAF', label: 'Detección' },
    { id: 'WAF_TARGET', source: 'WAF', target: 'BD Objetivo', label: 'Request' },
  ];

  const nodeColor = (role: string) => {
    if (role === 'target') return '#ef4444';
    if (role === 'defense') return '#f59e0b';
    if (role === 'proxy') return '#06b6d4';
    if (role === 'agent') return agentConnected ? '#10b981' : '#1f2937';
    return '#10b981';
  };

  return (
    <div className="w-full h-[300px] bg-cyber-900 rounded-lg border border-cyber-700 shadow-lg relative overflow-hidden">
      <div className="absolute top-2 left-3 text-xs text-cyber-accent font-mono uppercase tracking-widest pointer-events-none">
        Topología de Tráfico (30s) | {computed.host}
      </div>

      <div className="absolute top-2 right-3 text-[10px] font-mono text-gray-300 bg-black/30 border border-cyber-700 rounded px-2 py-1">
        <div className="flex gap-3">
          <span>RPS: <span className="text-emerald-300">{metrics ? metrics.requestsPerSecond.toFixed(1) : 'n/a'}</span></span>
          <span>WAF: <span className="text-yellow-300">{metrics ? metrics.wafBlockCount : 'n/a'}</span></span>
          <span>INJ: <span className="text-cyan-300">{metrics ? metrics.successfulInjections : 'n/a'}</span></span>
        </div>
      </div>

      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
          </marker>
          <style>
            {`
              @keyframes flowDash { from { stroke-dashoffset: 0; } to { stroke-dashoffset: -24; } }
            `}
          </style>
        </defs>

        {/* Edges */}
        {edges.map((e) => {
          const s = nodes.find(n => n.id === e.source)!;
          const t = nodes.find(n => n.id === e.target)!;
          const st = computed.edgeStats[e.id];
          const active = computed.edgeActive[e.id];
          const sev = st.severity;
          const stroke = severityColor(sev);
          const opacity = active ? 1 : (st.count > 0 ? 0.75 : 0.35);
          const w = 2 + Math.min(6, st.count / 4);
          const dash = active ? '6 6' : (e.id === 'AGENT_ORCH' && !agentConnected ? '5 5' : '0');
          const style: React.CSSProperties = active ? { animation: 'flowDash 1.2s linear infinite' } : {};

          const midX = (s.x + t.x) / 2;
          const midY = (s.y + t.y) / 2;

          return (
            <g key={e.id}>
              <line
                x1={s.x}
                y1={s.y}
                x2={t.x}
                y2={t.y}
                stroke={stroke}
                strokeWidth={w}
                opacity={opacity}
                strokeDasharray={dash}
                style={style}
                markerEnd="url(#arrow)"
              />
              <text
                x={midX}
                y={midY - 10}
                textAnchor="middle"
                fontFamily="monospace"
                fontSize="10"
                fill="#94a3b8"
                opacity={active ? 1 : 0.6}
              >
                {e.label} {st.count ? `(${st.count})` : ''}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map((n) => (
          <g
            key={n.id}
            transform={`translate(${n.x},${n.y})`}
            style={{ cursor: computed.nodeDetails[n.id] ? 'pointer' : 'default' }}
            onClick={() => computed.nodeDetails[n.id] && setSelectedNode(computed.nodeDetails[n.id])}
          >
            <circle
              r={n.role === 'agent' ? 16 : 20}
              fill={nodeColor(n.role)}
              stroke="#0f172a"
              strokeWidth={2}
              opacity={n.role === 'agent' && !agentConnected ? 0.6 : 1}
            />
            <text
              y={38}
              textAnchor="middle"
              fill={n.role === 'agent' && !agentConnected ? '#4b5563' : '#94a3b8'}
              fontSize="10"
              fontFamily="monospace"
            >
              {n.id}
            </text>
          </g>
        ))}
      </svg>

      {/* Event ticker */}
      <div className="absolute bottom-2 left-2 right-2 grid grid-cols-1 md:grid-cols-2 gap-1 text-[10px] font-mono">
        {computed.ticker.map((t, idx) => (
          <div
            key={idx}
            className="bg-black/30 border border-cyber-800 rounded px-2 py-1 flex items-center justify-between gap-2"
          >
            <span className="text-gray-400">
              {t.component} {t.level}
            </span>
            <span className="text-gray-200 truncate">{shortMsg(t.message, 56)}</span>
          </div>
        ))}
      </div>

      {/* Node Detail Popup */}
      {selectedNode && (
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-cyber-950/95 border border-emerald-500 rounded p-4 w-64 shadow-2xl backdrop-blur-md z-10 animate-in fade-in zoom-in duration-200">
          <div className="flex justify-between items-center mb-2 border-b border-cyber-800 pb-2">
            <h3 className="font-bold text-emerald-400">{selectedNode.id}</h3>
            <button onClick={() => setSelectedNode(null)} className="text-gray-400 hover:text-white" aria-label="Cerrar detalles del nodo"><X size={16} /></button>
          </div>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between"><span className="text-gray-500">Tipo:</span> <span className="text-white">{selectedNode.type}</span></div>
            <div className="flex justify-between"><span className="text-gray-500">Estado:</span> <span className="text-white">{selectedNode.status}</span></div>
            <div className="mt-2 pt-2 border-t border-cyber-800 space-y-1">
              {selectedNode.details.map((detail, idx) => (
                <div key={idx} className="text-cyan-600">{detail}</div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackMap;

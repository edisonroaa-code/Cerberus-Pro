import React from 'react';
import clsx from 'clsx';
import { Database, Zap, BrainCircuit, Skull, Eye } from 'lucide-react';
import { CopyableText } from './ui/CopyableText';
import { TargetConfig, AttackProfile } from '../types';
import { UnifiedUiConfig, UnifiedCapabilities, UnifiedMode, UnifiedVector, DirectDbEngine, UNIFIED_PRESETS } from '../config/unifiedConfig';
import { PROFILE_RULES } from '../config/scanDefaults';

interface CampaignPanelProps {
    targetConfig: TargetConfig;
    setTargetConfig: React.Dispatch<React.SetStateAction<TargetConfig>>;
    unifiedConfig: UnifiedUiConfig;
    setUnifiedConfig: React.Dispatch<React.SetStateAction<UnifiedUiConfig>>;
    showAdvancedCampaign: boolean;
    setShowAdvancedCampaign: React.Dispatch<React.SetStateAction<boolean>>;
    unifiedRisk: { label: string; className: string };
    unifiedCapabilities: UnifiedCapabilities;
    unifiedStatus: any;
    sendUnifiedStartCommand: (m?: UnifiedMode) => Promise<void>;
    sendUnifiedStopCommand: () => Promise<void>;
    getCommandPreview: () => string;
}

export const CampaignPanel: React.FC<CampaignPanelProps> = ({
    targetConfig,
    setTargetConfig,
    unifiedConfig,
    setUnifiedConfig,
    showAdvancedCampaign,
    setShowAdvancedCampaign,
    unifiedRisk,
    unifiedCapabilities,
    unifiedStatus,
    sendUnifiedStartCommand,
    sendUnifiedStopCommand,
    getCommandPreview,
}) => {
    return (
        <div className="h-full overflow-y-auto pr-1 space-y-6">
            <div className="glass-panel p-2 p-5 relative overflow-hidden">
                <h2 className="text-lg font-bold text-emerald-300 mb-2">Control IA (Recomendado)</h2>
                <p className="text-xs text-gray-400 mb-4">
                    Define objetivo e intensidad. La IA ajusta SQLMap automáticamente y aplica tuning dinámico.
                </p>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm text-cyan-400 mb-1 font-bold">Objetivo</label>
                        <input
                            type="text"
                            value={targetConfig.url}
                            onChange={(e) => setTargetConfig({ ...targetConfig, url: e.target.value })}
                            aria-label="URL objetivo principal"
                            className="w-full glass-input w-full px-4 py-3 text-white focus:border-emerald-500 focus:outline-none font-mono"
                            placeholder="http://target.com/vuln.php?id=1"
                        />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-3 bg-indigo-500/5 backdrop-blur-sm border border-indigo-500/20 shadow-inner rounded-lg">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-sm font-bold text-indigo-300">Modo Auto-Piloto</h3>
                                    <p className="text-[10px] text-gray-500">IA controla vectores y parámetros</p>
                                </div>
                                <button
                                    onClick={() => setTargetConfig({ ...targetConfig, autoPilot: !targetConfig.autoPilot })}
                                    className={clsx(
                                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none",
                                        targetConfig.autoPilot ? "bg-indigo-600" : "bg-gray-700"
                                    )}
                                    type="button"
                                    aria-label="Alternar auto-piloto"
                                >
                                    <span
                                        className={clsx(
                                            "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                            targetConfig.autoPilot ? "translate-x-6" : "translate-x-1"
                                        )}
                                    />
                                </button>
                            </div>
                        </div>

                        <div className="p-3 bg-cyber-950 border border-cyber-700 rounded-lg">
                            <div className="flex justify-between text-sm mb-2">
                                <span className="text-gray-400">Intensidad</span>
                                <span className="text-emerald-400 font-bold">{targetConfig.aggressionLevel}</span>
                            </div>
                            <input
                                type="range"
                                min="1"
                                max="10"
                                value={targetConfig.aggressionLevel}
                                onChange={(e) => setTargetConfig({ ...targetConfig, aggressionLevel: parseInt(e.target.value) })}
                                className="w-full accent-emerald-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                aria-label="Intensidad de ejecución"
                            />
                        </div>
                    </div>

                    <div className="flex items-center justify-between gap-3 pt-1">
                        <span className={clsx("px-2 py-1 rounded border text-[10px] font-bold", unifiedRisk.className)}>
                            Riesgo estimado: {unifiedRisk.label}
                        </span>
                        <button
                            onClick={() => setShowAdvancedCampaign((prev) => !prev)}
                            className="text-xs btn-cyber px-3 py-1.5 rounded border border-cyber-600 transition-all"
                            type="button"
                        >
                            {showAdvancedCampaign ? 'Ocultar configuración avanzada' : 'Mostrar configuración avanzada'}
                        </button>
                    </div>
                </div>
            </div>

            {showAdvancedCampaign && (
                <div className="glass-panel p-2 p-6 relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-2 opacity-10"><Database size={150} className="text-emerald-500" /></div>
                    <h2 className="text-lg font-bold text-white mb-6 border-b border-cyber-800 pb-2 flex justify-between items-center">
                        <span>Configuración Avanzada (Manual)</span>
                        <span className="text-xs font-mono text-emerald-500 border border-emerald-500 px-2 py-0.5 rounded">--batch mode</span>
                    </h2>

                    <div className="space-y-4 relative z-10">
                        {/* Auto-Pilot Toggle */}
                        <div className="flex items-center justify-between p-3 bg-indigo-500/5 backdrop-blur-sm border border-indigo-500/20 shadow-inner rounded-lg mb-4">
                            <div className="flex items-center gap-3">
                                <div className={clsx(
                                    "p-2 rounded-full",
                                    targetConfig.autoPilot ? "bg-indigo-500 text-white animate-pulse" : "bg-gray-800 text-gray-400"
                                )}>
                                    <Zap size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-indigo-400">Modo Auto-Piloto</h3>
                                    <p className="text-[10px] text-gray-500">Ajuste adaptativo y reintentos automáticos</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setTargetConfig({ ...targetConfig, autoPilot: !targetConfig.autoPilot })}
                                className={clsx(
                                    "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none",
                                    targetConfig.autoPilot ? "bg-indigo-600" : "bg-gray-700"
                                )}
                            >
                                <span
                                    className={clsx(
                                        "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                        targetConfig.autoPilot ? "translate-x-6" : "translate-x-1"
                                    )}
                                />
                            </button>
                        </div>

                        {/* Unified engine panel */}
                        <div className="p-3 bg-emerald-500/5 backdrop-blur-sm border border-emerald-500/20 shadow-inner rounded-lg">
                            <div className="flex items-center justify-between mb-3">
                                <div>
                                    <h3 className="text-sm font-bold text-emerald-300">Motor Unificado v4</h3>
                                    <p className="text-[10px] text-gray-500">Orquestación multi-vector con modos web y no-web</p>
                                </div>
                                <div className={clsx("px-2 py-1 rounded border text-[10px] font-bold", unifiedRisk.className)}>
                                    Riesgo: {unifiedRisk.label}
                                </div>
                                <div className="flex items-center gap-2">
                                    <div className="flex items-center gap-1 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                                        <BrainCircuit className={clsx("h-3 w-3", unifiedConfig.aiie ? "text-emerald-400" : "text-gray-500")} />
                                        <span className="text-[10px] font-bold text-emerald-400">AI CORE</span>
                                        <button
                                            onClick={() => setUnifiedConfig(prev => ({ ...prev, aiie: !prev.aiie }))}
                                            className={clsx(
                                                "relative inline-flex h-4 w-8 items-center rounded-full transition-colors",
                                                unifiedConfig.aiie ? "bg-emerald-600" : "bg-gray-700"
                                            )}
                                        >
                                            <span
                                                className={clsx(
                                                    "inline-block h-2.5 w-2.5 transform rounded-full bg-white transition-transform",
                                                    unifiedConfig.aiie ? "translate-x-4.5" : "translate-x-1"
                                                )}
                                            />
                                        </button>
                                    </div>
                                    <button
                                        onClick={() => setUnifiedConfig(prev => ({ ...prev, enabled: !prev.enabled }))}
                                        aria-label="Alternar motor unificado"
                                        className={clsx(
                                            "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                                            unifiedConfig.enabled ? "bg-emerald-600" : "bg-gray-700"
                                        )}
                                    >
                                        <span
                                            className={clsx(
                                                "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                                unifiedConfig.enabled ? "translate-x-6" : "translate-x-1"
                                            )}
                                        />
                                    </button>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 lg:grid-cols-6 gap-2 mb-3">
                                {(unifiedCapabilities.modes as UnifiedMode[]).map((mode) => (
                                    <button
                                        key={mode}
                                        onClick={() => setUnifiedConfig(prev => ({ ...prev, mode }))}
                                        aria-label={`Seleccionar modo ${mode}`}
                                        className={clsx(
                                            "px-2 py-1 rounded text-[10px] font-bold border uppercase",
                                            unifiedConfig.mode === mode
                                                ? "bg-emerald-500 text-black border border-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.3)]"
                                                : "bg-cyber-800 text-gray-300 border-cyber-700"
                                        )}
                                    >
                                        {mode}
                                    </button>
                                ))}
                            </div>

                            <div className="mb-3 grid grid-cols-1 lg:grid-cols-4 gap-2">
                                <button
                                    onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.silent_recon }))}
                                    className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-cyan-300 border-cyber-700 hover:border-cyan-500"
                                >
                                    Preset: Recon
                                </button>
                                <button
                                    onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.rapid_exploit }))}
                                    className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-orange-300 border-cyber-700 hover:border-orange-500"
                                >
                                    Preset: Rápido
                                </button>
                                <button
                                    onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.forensic_capture }))}
                                    className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-emerald-300 border-cyber-700 hover:border-emerald-500"
                                >
                                    Preset: Forense
                                </button>
                                <button
                                    onClick={() => {
                                        setUnifiedConfig(prev => ({
                                            ...prev,
                                            deep_audit: true,
                                            level: 5,
                                            risk: 3,
                                            noSql: true,
                                            ssti: true,
                                            aiie: true,
                                            chaining: true,
                                            maxParallel: 8
                                        }));
                                    }}
                                    className="px-2 py-1 rounded text-[10px] font-bold border btn-danger hover:text-white transition-all animate-pulse flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(239,68,68,0.3)]"
                                >
                                    <Skull size={12} /> TOTAL WAR
                                </button>
                            </div>

                            <div className="mb-3">
                                <label className="block text-[11px] text-cyan-300 mb-1 font-bold">Vectores paralelos</label>
                                <div className="grid grid-cols-3 lg:grid-cols-6 gap-1">
                                    {(unifiedCapabilities.vectors as UnifiedVector[]).map((vec) => (
                                        <label key={vec} className="flex items-center gap-1 text-[10px] text-gray-300">
                                            <input
                                                type="checkbox"
                                                checked={unifiedConfig.vectors.includes(vec)}
                                                aria-label={`Vector ${vec}`}
                                                onChange={(e) => {
                                                    setUnifiedConfig(prev => {
                                                        const next = e.target.checked
                                                            ? [...prev.vectors, vec]
                                                            : prev.vectors.filter(v => v !== vec);
                                                        return { ...prev, vectors: next.length ? next : [((unifiedCapabilities.vectors[0] as UnifiedVector) || 'UNION')] };
                                                    });
                                                }}
                                                className="w-3 h-3 accent-emerald-500"
                                            />
                                            {vec === 'BOOLEAN' ? 'BOOLEAN (SI/NO)' : vec === 'UNION' ? 'UNION (Resultados BD)' : vec === 'TIME' ? 'TIME (Time Blind)' : vec === 'ERROR' ? 'ERROR (Errores SQL)' : vec === 'STACKED' ? 'STACKED (Múltiple)' : vec === 'INLINE' ? 'INLINE (Queries)' : vec === 'AIIE' ? 'AIIE (IA Engine)' : vec}
                                        </label>
                                    ))}
                                </div>
                            </div>

                            <div className="mb-3">
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-gray-400">Paralelismo</span>
                                    <span className="text-emerald-300 font-bold">{unifiedConfig.maxParallel}</span>
                                </div>
                                <input
                                    type="range"
                                    min={unifiedCapabilities.limits.max_parallel_min}
                                    max={unifiedCapabilities.limits.max_parallel_max}
                                    value={unifiedConfig.maxParallel}
                                    aria-label="Paralelismo del motor unificado"
                                    onChange={(e) => setUnifiedConfig(prev => ({ ...prev, maxParallel: parseInt(e.target.value) }))}
                                    className="w-full accent-emerald-500"
                                />
                            </div>

                            {unifiedConfig.mode === 'graphql' && (
                                <div className="mb-3">
                                    <label className="block text-[11px] text-cyan-300 mb-1 font-bold">GraphQL Query</label>
                                    <input
                                        type="text"
                                        value={unifiedConfig.graphqlQuery}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, graphqlQuery: e.target.value }))}
                                        className="w-full glass-input px-3 py-2 text-white text-white text-xs font-mono"
                                    />
                                </div>
                            )}

                            {unifiedConfig.mode === 'direct_db' && (
                                <div className="grid grid-cols-3 gap-2 mb-3">
                                    <select
                                        value={unifiedConfig.directDb.engine}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, engine: e.target.value as DirectDbEngine } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                    >
                                        <option value="mysql">MySQL</option>
                                        <option value="postgres">Postgres</option>
                                        <option value="mssql">MSSQL</option>
                                        <option value="oracle">Oracle</option>
                                        <option value="mongodb">MongoDB</option>
                                        <option value="redis">Redis</option>
                                    </select>
                                    <input
                                        type="text"
                                        value={unifiedConfig.directDb.host}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, host: e.target.value } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="host"
                                    />
                                    <input
                                        type="number"
                                        value={unifiedConfig.directDb.port}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, port: parseInt(e.target.value || '0') } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="port"
                                    />
                                </div>
                            )}

                            {unifiedConfig.mode === 'ws' && (
                                <div className="mb-3">
                                    <label className="block text-[11px] text-cyan-300 mb-1 font-bold">WebSocket URL</label>
                                    <input
                                        type="text"
                                        value={unifiedConfig.wsUrl}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, wsUrl: e.target.value }))}
                                        className="w-full glass-input px-3 py-2 text-white text-white text-xs font-mono"
                                    />
                                </div>
                            )}

                            {unifiedConfig.mode === 'mqtt' && (
                                <div className="grid grid-cols-2 gap-2 mb-3">
                                    <input
                                        type="text"
                                        value={unifiedConfig.mqtt.host}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, mqtt: { ...prev.mqtt, host: e.target.value } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="MQTT host"
                                    />
                                    <input
                                        type="number"
                                        value={unifiedConfig.mqtt.port}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, mqtt: { ...prev.mqtt, port: parseInt(e.target.value || '0') } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="MQTT port"
                                    />
                                </div>
                            )}

                            {unifiedConfig.mode === 'grpc' && (
                                <div className="grid grid-cols-2 gap-2 mb-3">
                                    <input
                                        type="text"
                                        value={unifiedConfig.grpc.host}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, grpc: { ...prev.grpc, host: e.target.value } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="gRPC host"
                                    />
                                    <input
                                        type="number"
                                        value={unifiedConfig.grpc.port}
                                        onChange={(e) => setUnifiedConfig(prev => ({ ...prev, grpc: { ...prev.grpc, port: parseInt(e.target.value || '0') } }))}
                                        className="glass-input px-3 py-2 text-white text-white text-xs"
                                        placeholder="gRPC port"
                                    />
                                </div>
                            )}

                            <div className="flex gap-2">
                                <button
                                    onClick={() => void sendUnifiedStartCommand()}
                                    disabled={!unifiedConfig.enabled}
                                    className={clsx(
                                        "px-3 py-1.5 rounded text-xs font-bold border",
                                        unifiedConfig.enabled
                                            ? "btn-emerald py-2"
                                            : "btn-premium bg-white/5 text-gray-500 border border-white/border-5 cursor-not-allowed py-2"
                                    )}
                                >
                                    Ejecutar Motor {unifiedConfig.mode.toUpperCase()}
                                </button>
                                <button
                                    onClick={() => void sendUnifiedStopCommand()}
                                    className="px-3 py-1.5 rounded text-xs font-bold border bg-cyber-800 text-gray-300 border-cyber-700 hover:border-red-500"
                                >
                                    Detener Motor
                                </button>
                            </div>
                            <div className="mt-3 p-2 rounded border border-cyber-700 bg-black/30">
                                <div className="text-[10px] text-gray-400 mb-1">Estado del motor en tiempo real</div>
                                <div className="grid grid-cols-2 gap-2 text-[10px]">
                                    <div className="text-gray-300">Running: <span className={unifiedStatus.running ? "text-emerald-300" : "text-gray-500"}>{unifiedStatus.running ? 'YES' : 'NO'}</span></div>
                                    <div className="text-gray-300">Modo: <span className="text-cyan-300">{unifiedStatus.meta?.mode || unifiedConfig.mode}</span></div>
                                    <div className="text-gray-300">Vector: <span className="text-yellow-300">{unifiedStatus.meta?.current_vector || '-'}</span></div>
                                    <div className="text-gray-300">Progreso: <span className="text-purple-300">{`${unifiedStatus.meta?.completed_vectors || 0}/${unifiedStatus.meta?.total_vectors || 0}`}</span></div>
                                    <div className="text-gray-300 col-span-2">Estado: <span className="text-gray-200">{unifiedStatus.meta?.last_message || 'idle'}</span></div>
                                    {unifiedStatus.meta?.last_error && (
                                        <div className="text-red-300 col-span-2">Error: {unifiedStatus.meta.last_error}</div>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Profile Selector */}
                        <div className="pb-4 border-b border-cyber-800">
                            <label className="block text-sm text-cyan-400 mb-2 font-bold">Perfil de Ataque</label>
                            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                                {Object.entries(AttackProfile).map(([key, value]) => (
                                    <button
                                        key={key}
                                        onClick={() => setTargetConfig({ ...targetConfig, profile: value })}
                                        className={clsx(
                                            "px-2 py-1.5 rounded text-[10px] font-bold border transition-all truncate",
                                            targetConfig.profile === value
                                                ? "bg-emerald-500 text-black border border-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.3)]"
                                                : "bg-black/30 border border-white/5 hover:border-white/20 text-gray-400 shadow-sm"
                                        )}
                                        title={PROFILE_RULES[value].desc}
                                    >
                                        {value}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Command Preview */}
                        <div className="bg-black/40 rounded border border-cyber-700 p-3 mb-4 group relative">
                            <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><Eye size={10} /> PREVISUALIZACIÓN DE COMANDO</div>
                            <CopyableText text={getCommandPreview()} />
                        </div>

                        {/* URL Target */}
                        <div>
                            <label className="block text-sm text-cyan-400 mb-1 font-bold">Objetivo (-u)</label>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={targetConfig.url}
                                    onChange={(e) => setTargetConfig({ ...targetConfig, url: e.target.value })}
                                    aria-label="URL objetivo"
                                    className="w-full glass-input w-full px-4 py-3 text-white focus:border-emerald-500 focus:outline-none font-mono"
                                    placeholder="http://target.com/vuln.php?id=1"
                                />
                            </div>
                        </div>

                        {/* Technique & Tamper Selectors */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {/* Techniques */}
                            <div className="space-y-2">
                                <label className="block text-sm text-cyan-400 font-bold mb-2">Técnicas de Inyección</label>
                                <div className="flex flex-wrap gap-2">
                                    {[
                                        { id: 'B', label: 'Boolean', title: 'Ciega basada en Booleanos' },
                                        { id: 'E', label: 'Error', title: 'Basada en Errores' },
                                        { id: 'U', label: 'Union', title: 'Basada en consultas UNION' },
                                        { id: 'S', label: 'Stack', title: 'Consultas apiladas (Stacked)' },
                                        { id: 'T', label: 'Time', title: 'Ciega basada en Tiempo' },
                                        { id: 'Q', label: 'Inline', title: 'Consultas en línea (Inline)' },
                                    ].map((tech) => (
                                        <button
                                            key={tech.id}
                                            onClick={() => {
                                                const current = targetConfig.sqlMap.technique;
                                                const next = current.includes(tech.id)
                                                    ? current.replace(tech.id, '')
                                                    : current + tech.id;
                                                setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, technique: next || 'B' } });
                                            }}
                                            className={clsx(
                                                "px-3 py-1.5 rounded text-[10px] font-bold border transition-all",
                                                targetConfig.sqlMap.technique.includes(tech.id)
                                                    ? "bg-cyan-500 text-black border border-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                                                    : "bg-black/30 border border-white/5 hover:border-white/20 text-gray-400 shadow-sm"
                                            )}
                                            title={tech.title}
                                        >
                                            {tech.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Tamper Scripts */}
                            <div className="space-y-2">
                                <label className="block text-sm text-cyan-400 font-bold mb-2">Disfraces (Tamper Scripts)</label>
                                <div className="grid grid-cols-1 gap-1">
                                    {[
                                        { id: 'space2comment', label: 'Espacio a Comentario', desc: 'Sustituye espacios por /**/' },
                                        { id: 'randomcase', label: 'Caso Aleatorio', desc: 'Mezcla maYúScuLas y minúsculas' },
                                        { id: 'base64encode', label: 'Base64 Encode', desc: 'Codifica todo el payload en Base64' },
                                        { id: 'charencode', label: 'Char Encode', desc: 'Codifica carácteres especiales' },
                                    ].map((tamp) => (
                                        <label key={tamp.id} className="flex items-center gap-2 group cursor-pointer hover:bg-white/5 p-1 rounded">
                                            <input
                                                type="checkbox"
                                                checked={targetConfig.sqlMap.tamper.includes(tamp.id)}
                                                onChange={(e) => {
                                                    const current = targetConfig.sqlMap.tamper.split(',').filter(x => x);
                                                    const next = e.target.checked
                                                        ? [...current, tamp.id]
                                                        : current.filter(x => x !== tamp.id);
                                                    setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, tamper: next.join(',') } });
                                                }}
                                                className="w-3 h-3 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                            />
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-bold text-gray-300">{tamp.label}</span>
                                                <span className="text-[8px] text-gray-500 group-hover:text-gray-400">{tamp.desc}</span>
                                            </div>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>

                        {/* Sliders for Level/Risk/Threads */}
                        <div className="grid grid-cols-3 gap-6 pt-4">
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-gray-400">Nivel (Level)</span>
                                    <span className="text-emerald-400 font-bold">{targetConfig.sqlMap.level}</span>
                                </div>
                                <input
                                    type="range" min="1" max="5"
                                    value={targetConfig.sqlMap.level}
                                    onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, level: parseInt(e.target.value) } })}
                                    className="w-full accent-emerald-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                />
                            </div>
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-gray-400">Riesgo (Risk)</span>
                                    <span className="text-red-400 font-bold">{targetConfig.sqlMap.risk}</span>
                                </div>
                                <input
                                    type="range" min="1" max="3"
                                    value={targetConfig.sqlMap.risk}
                                    onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, risk: parseInt(e.target.value) } })}
                                    className="w-full accent-red-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                />
                            </div>
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-gray-400">Hilos (Threads)</span>
                                    <span className="text-purple-400 font-bold">{targetConfig.sqlMap.threads}</span>
                                </div>
                                <input
                                    type="range" min="1" max="10"
                                    value={targetConfig.sqlMap.threads}
                                    onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, threads: parseInt(e.target.value) } })}
                                    className="w-full accent-purple-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                />
                            </div>
                        </div>

                        <div className="pt-4 border-t border-cyber-800 grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <h4 className="text-xs text-gray-500 uppercase">Evasión Básica</h4>
                                <div className="flex items-center gap-2">
                                    <input
                                        type="checkbox"
                                        checked={targetConfig.sqlMap.randomAgent}
                                        onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, randomAgent: e.target.checked } })}
                                        className="w-4 h-4 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                    />
                                    <label className="text-sm text-gray-300">--random-agent</label>
                                </div>
                                <div className="flex items-center gap-2">
                                    <input
                                        type="checkbox"
                                        checked={targetConfig.useSmartEvasion}
                                        onChange={(e) => setTargetConfig({ ...targetConfig, useSmartEvasion: e.target.checked })}
                                        className="w-4 h-4 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                    />
                                    <label className="text-sm text-gray-300">Orquestador Inteligente</label>
                                </div>
                            </div>

                            <div className="space-y-2">
                                <h4 className="text-xs text-gray-500 uppercase font-bold">Extracción de Datos</h4>
                                <div className="grid grid-cols-1 gap-1">
                                    {[
                                        { id: 'currentUser', label: '--current-user', title: 'Obtener usuario actual de la DB' },
                                        { id: 'currentDb', label: '--current-db', title: 'Obtener nombre de la DB actual' },
                                        { id: 'getDbs', label: '--dbs', title: 'Listar todas las bases de datos' },
                                        { id: 'getTables', label: '--tables', title: 'Listar tablas de la base de datos' },
                                        { id: 'dumpAll', label: '--dump', title: 'EXTRAER DATOS (Dump)', highlight: true },
                                    ].map((act) => (
                                        <label key={act.id} className={clsx(
                                            "flex items-center gap-2 cursor-pointer p-1 rounded hover:bg-white/5",
                                            act.highlight && "bg-emerald-500/5 border border-emerald-500/20"
                                        )}>
                                            <input
                                                type="checkbox"
                                                checked={(targetConfig.sqlMap as any)[act.id]}
                                                onChange={(e) => setTargetConfig({
                                                    ...targetConfig,
                                                    sqlMap: { ...targetConfig.sqlMap, [act.id]: e.target.checked }
                                                })}
                                                className={clsx(
                                                    "w-3 h-3 bg-cyber-900 border-cyber-700",
                                                    act.highlight ? "accent-emerald-400" : "accent-cyan-500"
                                                )}
                                            />
                                            <span className={clsx(
                                                "text-[10px] font-bold",
                                                act.highlight ? "text-emerald-400" : "text-gray-400"
                                            )} title={act.title}>
                                                {act.label}
                                            </span>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};



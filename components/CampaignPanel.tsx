import React from 'react';
import clsx from 'clsx';
import { Database, Zap, BrainCircuit, Skull, Eye, Shield } from 'lucide-react';
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
    engineHealth: {
        connected: number;
        total: number;
        items: Array<{ id: string; connected: boolean; status: string }>;
    };
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
    engineHealth,
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

                        {/* Cerberus Ghost Network (Anonimización P4) */}
                        <div className="flex flex-col p-3 bg-slate-900/50 backdrop-blur-sm border border-slate-700/50 shadow-inner rounded-lg mb-4 space-y-3">
                            <div className="flex items-center justify-between border-b border-slate-700/50 pb-2">
                                <div className="flex items-center gap-3">
                                    <div className={clsx(
                                        "p-2 rounded-full",
                                        targetConfig.pivoting?.tor ? "bg-purple-600 text-white animate-pulse" : "bg-gray-800 text-gray-500"
                                    )}>
                                        <Shield size={18} />
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-bold text-slate-300">Cerberus Ghost Network</h3>
                                        <p className="text-[10px] text-gray-500">Enrutamiento Cebolla (TOR) y Proxy Rotativo</p>
                                    </div>
                                </div>
                                <button
                                    onClick={() => setTargetConfig({
                                        ...targetConfig,
                                        pivoting: {
                                            ...targetConfig.pivoting,
                                            tor: !targetConfig.pivoting?.tor,
                                            proxy: targetConfig.pivoting?.proxy || ''
                                        }
                                    })}
                                    className={clsx(
                                        "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none",
                                        targetConfig.pivoting?.tor ? "bg-purple-600" : "bg-gray-700"
                                    )}
                                >
                                    <span className={clsx("inline-block h-4 w-4 transform rounded-full bg-white transition-transform", targetConfig.pivoting?.tor ? "translate-x-6" : "translate-x-1")} />
                                </button>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                                <div>
                                    <label className="block text-slate-400 mb-1 font-bold text-[10px]">Punto de Entrada Secundario (Proxy Único)</label>
                                    <input
                                        type="text"
                                        className="glass-input w-full px-2 py-1.5 text-white"
                                        placeholder="socks5://127.0.0.1:9050"
                                        value={targetConfig.pivoting?.proxy || ''}
                                        onChange={(e) => setTargetConfig({
                                            ...targetConfig,
                                            pivoting: {
                                                tor: targetConfig.pivoting?.tor || false,
                                                proxy: e.target.value
                                            }
                                        })}
                                    />
                                </div>
                                <div>
                                    <label className="block text-slate-400 mb-1 font-bold flex items-center justify-between text-[10px]">
                                        <span>Rotación Dinámica de Nodos P2P</span>
                                        <button
                                            onClick={() => setTargetConfig({ ...targetConfig, rotateProxy: !targetConfig.rotateProxy })}
                                            className={clsx("px-2 py-0.5 rounded text-[10px] font-bold", targetConfig.rotateProxy ? "bg-emerald-600 text-white" : "bg-gray-700 text-gray-400")}
                                        >
                                            {targetConfig.rotateProxy ? "ON" : "OFF"}
                                        </button>
                                    </label>
                                    {targetConfig.rotateProxy && (
                                        <input
                                            type="text"
                                            className="glass-input w-full px-2 py-1.5 text-white"
                                            placeholder="socks5://ip1, http://ip2..."
                                            value={(targetConfig.proxies || []).join(', ')}
                                            onChange={(e) => setTargetConfig({
                                                ...targetConfig,
                                                proxies: e.target.value.split(',').map(p => p.trim()).filter(Boolean)
                                            })}
                                        />
                                    )}
                                </div>
                            </div>
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
                            <div className="flex items-center gap-2 mb-3 text-[10px]">
                                <span className={clsx(
                                    "px-2 py-1 rounded border font-bold",
                                    engineHealth.total > 0 && engineHealth.connected === engineHealth.total
                                        ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
                                        : "text-yellow-300 border-yellow-500/40 bg-yellow-500/10"
                                )}>
                                    Motores conectados: {engineHealth.connected}/{engineHealth.total || 0}
                                </span>
                                {engineHealth.items.slice(0, 6).map((engine) => (
                                    <span
                                        key={engine.id}
                                        className={clsx(
                                            "px-2 py-0.5 rounded border uppercase",
                                            engine.connected
                                                ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10"
                                                : "text-red-300 border-red-500/30 bg-red-500/10"
                                        )}
                                        title={`status=${engine.status}`}
                                    >
                                        {engine.id}
                                    </span>
                                ))}
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

                            {/* The AI dictates preset parameters, parallelism and vector mapping */}

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

                            {/* AI Tactical Sovereignty Banner */}
                            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-5 relative overflow-hidden group mb-4">
                                <div className="absolute top-0 right-0 -mt-4 -mr-4 text-emerald-500/10 transform rotate-12 group-hover:scale-110 transition-transform duration-500">
                                    <BrainCircuit size={100} />
                                </div>
                                <div className="relative z-10">
                                    <h3 className="text-emerald-400 font-bold mb-2 flex items-center gap-2">
                                        <BrainCircuit size={18} className="animate-pulse" />
                                        Cerberus Cortex AI: Soberanía Táctica Activa
                                    </h3>
                                    <p className="text-xs text-gray-400 max-w-2xl leading-relaxed">
                                        Las configuraciones manuales de ataque han sido delegadas. Cortex AI analizará el objetivo y
                                        calculará de forma autónoma la combinación óptima de <span className="text-emerald-300 font-medium">Nivel de Agresividad, Riesgo, Hilos </span> y
                                        <span className="text-emerald-300 font-medium"> Estrategias de Evasión (Tampers)</span> antes de iniciar la misión.
                                    </p>
                                </div>
                            </div>

                            <div className="pt-4 border-t border-cyber-800 grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">Comandos Dinámicos</h4>
                                    <div className="text-[10px] text-gray-400 bg-black/30 p-2 rounded border border-cyber-800">
                                        La IA ajustará automáticamente:
                                        <ul className="list-disc pl-4 mt-1 space-y-1">
                                            <li><span className="text-emerald-500">--level</span> (Impacto y profundidad)</li>
                                            <li><span className="text-red-500">--risk</span> (Peligro de modificación)</li>
                                            <li><span className="text-purple-500">--threads</span> (Paralelismo de inyección)</li>
                                            <li><span className="text-cyan-500">--tamper</span> (Evasión de WAF e IPS)</li>
                                            <li><span className="text-yellow-500">--technique</span> (Estrategia de inyección)</li>
                                        </ul>
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
                </div>
            )}
        </div>
    );
};

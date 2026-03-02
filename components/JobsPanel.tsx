import React, { useState, useMemo } from 'react';
import { Server, Database } from 'lucide-react';
import clsx from 'clsx';
import { SplitPanelLayout } from './ui/SplitPanelLayout';
import { CerberusJob, CerberusLoot } from '../types';

interface JobsPanelProps {
    jobs: CerberusJob[];
    loots?: CerberusLoot[];
    fetchJobs: () => void;
    fetchLoots?: () => void;
    deleteLoot?: (filename: string) => Promise<void>;
    stopJob: (scanId: string) => void;
    retryJob: (scanId: string) => void;
    selectedJob: CerberusJob | null;
    loadJobDetail: (scanId: string) => void;
}

export const JobsPanel: React.FC<JobsPanelProps> = ({
    jobs,
    loots = [],
    fetchJobs,
    fetchLoots,
    deleteLoot,
    stopJob,
    retryJob,
    selectedJob,
    loadJobDetail,
}) => {
    const [viewMode, setViewMode] = useState<'jobs' | 'loot'>('jobs');
    const [jobFilterStatus, setJobFilterStatus] = useState<string>('all');
    const [jobFilterKind, setJobFilterKind] = useState<string>('all');
    const [selectedLoot, setSelectedLoot] = useState<CerberusLoot | null>(null);

    const filteredJobs = useMemo(() => {
        return jobs.filter((j: CerberusJob) => {
            const status = String(j.status || '').toLowerCase();
            const kind = String(j.kind || '').toLowerCase();
            if (jobFilterStatus !== 'all' && status !== jobFilterStatus.toLowerCase()) return false;
            if (jobFilterKind !== 'all' && kind !== jobFilterKind.toLowerCase()) return false;
            return true;
        });
    }, [jobs, jobFilterStatus, jobFilterKind]);

    return (
        <div className="h-[760px] max-w-6xl mx-auto">
            <SplitPanelLayout
                defaultLeftWidth={68}
                left={
                    <div className="h-full overflow-hidden flex flex-col">
                        <div className="glass-panel p-2 overflow-hidden flex flex-col h-full">
                            <div className="p-6 border-b border-cyber-800 flex justify-between items-center bg-cyber-950/50">
                                <h2 className="text-xl font-bold text-emerald-400 flex items-center gap-2">
                                    <Server /> Jobs (cola + ejecución)
                                </h2>
                                <div className="flex items-center gap-4">
                                    <div className="flex bg-black/40 rounded border border-cyber-700 overflow-hidden">
                                        <button
                                            className={clsx("px-4 py-1.5 text-xs font-bold transition-all", viewMode === 'jobs' ? "bg-emerald-500/20 text-emerald-400" : "text-gray-500 hover:text-gray-300")}
                                            onClick={() => setViewMode('jobs')}
                                        >
                                            JOBS QUEUE
                                        </button>
                                        <button
                                            className={clsx("px-4 py-1.5 text-xs font-bold transition-all", viewMode === 'loot' ? "bg-fuchsia-500/20 text-fuchsia-400" : "text-gray-500 hover:text-gray-300")}
                                            onClick={() => setViewMode('loot')}
                                        >
                                            LOOT BOARD
                                        </button>
                                    </div>
                                    <button
                                        onClick={viewMode === 'jobs' ? fetchJobs : fetchLoots}
                                        className="text-xs bg-cyber-800 hover:bg-cyber-700 text-emerald-400 px-3 py-1.5 rounded border border-cyber-600 transition-all font-bold"
                                    >
                                        REFRESCAR
                                    </button>
                                </div>
                            </div>
                            <div className="flex-1 overflow-y-auto custom-scrollbar relative">
                            </div>
                        </div>

                        {viewMode === 'jobs' ? (
                            <>
                                <div className="p-4 border-b border-cyber-800 flex flex-col md:flex-row md:items-center gap-3 bg-black/20">
                                    <div className="flex items-center gap-2 text-[10px] uppercase text-gray-500 font-bold">
                                        Filtros
                                    </div>
                                    <div className="flex items-center gap-3 flex-wrap">
                                        <label className="text-xs text-gray-400 flex items-center gap-2">
                                            <span>Status</span>
                                            <select
                                                value={jobFilterStatus}
                                                onChange={(e) => setJobFilterStatus(e.target.value)}
                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-xs text-gray-200"
                                            >
                                                <option value="all">all</option>
                                                <option value="queued">queued</option>
                                                <option value="running">running</option>
                                                <option value="completed">completed</option>
                                                <option value="failed">failed</option>
                                                <option value="stopped">stopped</option>
                                                <option value="interrupted">interrupted</option>
                                            </select>
                                        </label>
                                        <label className="text-xs text-gray-400 flex items-center gap-2">
                                            <span>Kind</span>
                                            <select
                                                value={jobFilterKind}
                                                onChange={(e) => setJobFilterKind(e.target.value)}
                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-xs text-gray-200"
                                            >
                                                <option value="all">all</option>
                                                <option value="unified">unified</option>
                                            </select>
                                        </label>
                                        <div className="text-xs text-gray-500 font-mono">
                                            {filteredJobs.length}/{jobs.length}
                                        </div>
                                    </div>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="w-full text-left">
                                        <thead className="text-[10px] uppercase text-gray-500 bg-cyber-950 border-b border-cyber-800">
                                            <tr>
                                                <th className="px-6 py-3">Scan ID</th>
                                                <th className="px-6 py-3">Tipo</th>
                                                <th className="px-6 py-3">Estado</th>
                                                <th className="px-6 py-3">Target</th>
                                                <th className="px-6 py-3">Reporte</th>
                                                <th className="px-6 py-3">Creado</th>
                                                <th className="px-6 py-3">Error</th>
                                                <th className="px-6 py-3 text-right">Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-cyber-800/50">
                                            {filteredJobs.length > 0 ? filteredJobs.map((j: CerberusJob) => {
                                                const scanId = String(j.scan_id || '');
                                                const status = String(j.status || '');
                                                const kind = String(j.kind || '');
                                                const resultFilename = String(j.result_filename || '');
                                                const canStop = status === 'queued' || status === 'running';
                                                const canRetry = ['failed', 'stopped', 'interrupted', 'completed'].includes(status);
                                                const canOpenReport = !!resultFilename;
                                                const statusClass =
                                                    status === 'running' ? 'text-yellow-300 bg-yellow-500/10 border-yellow-500/20' :
                                                        status === 'queued' ? 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20' :
                                                            status === 'completed' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
                                                                status === 'failed' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                                                                    'text-gray-300 bg-white/5 border-cyber-700';
                                                return (
                                                    <tr key={scanId} className="hover:bg-white/5 transition-colors group cursor-pointer" onClick={() => loadJobDetail(scanId)}>
                                                        <td className="px-6 py-4 text-xs font-mono text-gray-300">
                                                            {scanId.slice(0, 10)}…
                                                        </td>
                                                        <td className="px-6 py-4 text-xs">
                                                            <span className="bg-cyber-800 text-cyan-400 px-2 py-0.5 rounded border border-cyber-700">
                                                                {kind || 'unknown'}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 text-[10px] font-bold uppercase tracking-wider">
                                                            <span className={`px-2 py-1 rounded-sm border ${statusClass}`}>
                                                                {status}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 text-sm text-gray-200 truncate max-w-[200px]" title={String(j.target || '')}>
                                                            {j.target || '-'}
                                                        </td>
                                                        <td className="px-6 py-4 text-xs font-mono text-gray-500">
                                                            {canOpenReport ? (
                                                                <span className="text-emerald-500" title={resultFilename}>OK</span>
                                                            ) : (
                                                                <span>-</span>
                                                            )}
                                                        </td>
                                                        <td className="px-6 py-4 text-xs text-gray-500 font-mono">
                                                            {j.created_at ? new Date(j.created_at).toLocaleString() : '-'}
                                                        </td>
                                                        <td className="px-6 py-4 text-xs text-red-400 truncate max-w-[150px]" title={j.error_message || ''}>
                                                            {j.error_message || ''}
                                                        </td>
                                                        <td className="px-6 py-4 text-right">
                                                            <button
                                                                onClick={(e) => { e.stopPropagation(); loadJobDetail(scanId); }}
                                                                className="text-cyan-500 hover:text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 rounded text-xs transition-all mr-2"
                                                            >
                                                                INSPECT
                                                            </button>
                                                        </td>
                                                    </tr>
                                                );
                                            }) : (
                                                <tr>
                                                    <td colSpan={8} className="px-6 py-12 text-center text-gray-600 italic">
                                                        {jobs.length === 0 ? 'No hay jobs en el sistema' : 'Ningún job coincide con los filtros'}
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </>
                        ) : (
                            <>
                                <div className="p-4 border-b border-cyber-800 bg-black/20 text-xs text-gray-400">
                                    Base de datos de vulnerabilidades explotadas automáticamente.
                                </div>
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left">
                                        <thead className="text-[10px] uppercase text-gray-500 bg-cyber-950 border-b border-cyber-800">
                                            <tr>
                                                <th className="px-6 py-3">Fecha</th>
                                                <th className="px-6 py-3">Target</th>
                                                <th className="px-6 py-3">Vector</th>
                                                <th className="px-6 py-3">Usuario DB</th>
                                                <th className="px-6 py-3">Base de Datos</th>
                                                <th className="px-6 py-3 text-right">Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-cyber-800/50">
                                            {loots.length > 0 ? loots.map((loot) => (
                                                <tr key={loot.id} className="hover:bg-white/5 transition-colors cursor-pointer" onClick={() => setSelectedLoot(loot)}>
                                                    <td className="px-6 py-4 text-xs font-mono text-gray-400">
                                                        {new Date(loot.timestamp).toLocaleString()}
                                                    </td>
                                                    <td className="px-6 py-4 text-sm text-gray-200">
                                                        {loot.target}
                                                    </td>
                                                    <td className="px-6 py-4 text-xs">
                                                        <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded">
                                                            {loot.technique_used}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 text-xs text-fuchsia-300">
                                                        {loot.extracted_data?.current_user || '-'}
                                                    </td>
                                                    <td className="px-6 py-4 text-xs text-cyan-300">
                                                        {loot.extracted_data?.database_name || '-'}
                                                    </td>
                                                    <td className="px-6 py-4 text-right">
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); setSelectedLoot(loot); }}
                                                            className="text-cyan-500 hover:text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 rounded text-xs transition-all mr-2"
                                                        >
                                                            VIEW
                                                        </button>
                                                        {deleteLoot && (
                                                            <button
                                                                onClick={(e) => { e.stopPropagation(); deleteLoot(loot.id); if (selectedLoot?.id === loot.id) setSelectedLoot(null); }}
                                                                className="text-red-500 hover:text-red-400 bg-red-500/10 hover:bg-red-500/20 px-2 py-1 rounded text-xs transition-all"
                                                            >
                                                                DEL
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            )) : (
                                                <tr>
                                                    <td colSpan={6} className="px-6 py-12 text-center text-gray-600 italic">
                                                        No hay datos extraídos en la base de datos de explotación.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </>
                        )}
                    </div>
                }
                right={
                    <div className="h-full glass-panel p-2 overflow-y-auto w-full">
                        {(() => {
                            if (viewMode === 'loot') {
                                if (!selectedLoot) {
                                    return (
                                        <div className="flex items-center justify-center h-full text-gray-600 p-8 text-center italic">
                                            Selecciona un registro de la base de explotación para visualizar su contenido extraído.
                                        </div>
                                    );
                                }
                                return (
                                    <div className="p-6 space-y-6">
                                        <div className="flex justify-between items-start">
                                            <div>
                                                <h3 className="text-lg font-bold text-emerald-400">Datos Extraídos (Loot)</h3>
                                                <div className="text-sm font-mono text-gray-400 mt-1">{selectedLoot.target}</div>
                                            </div>
                                            <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-3 py-1 text-xs rounded font-mono">
                                                {selectedLoot.technique_used}
                                            </span>
                                        </div>

                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="bg-black/30 border border-cyber-800 rounded p-3">
                                                <div className="text-[10px] text-gray-500 uppercase mb-1">Usuario DB</div>
                                                <div className="font-mono text-fuchsia-300 break-all">{selectedLoot.extracted_data?.current_user || 'N/A'}</div>
                                            </div>
                                            <div className="bg-black/30 border border-cyber-800 rounded p-3">
                                                <div className="text-[10px] text-gray-500 uppercase mb-1">Base de Datos</div>
                                                <div className="font-mono text-cyan-300 break-all">{selectedLoot.extracted_data?.database_name || 'N/A'}</div>
                                            </div>
                                            <div className="bg-black/30 border border-cyber-800 rounded p-3">
                                                <div className="text-[10px] text-gray-500 uppercase mb-1">Hostname</div>
                                                <div className="font-mono text-gray-300 break-all">{selectedLoot.extracted_data?.hostname || 'N/A'}</div>
                                            </div>
                                        </div>

                                        {selectedLoot.extracted_data?.privileges && selectedLoot.extracted_data.privileges.length > 0 && (
                                            <div>
                                                <h4 className="text-xs font-bold text-gray-400 mb-2 uppercase">Privilegios Detectados</h4>
                                                <div className="flex flex-wrap gap-2">
                                                    {selectedLoot.extracted_data.privileges.map((p, i) => (
                                                        <span key={i} className="bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 rounded text-[10px] font-mono">
                                                            {p}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {selectedLoot.extracted_data?.tables_preview && selectedLoot.extracted_data.tables_preview.length > 0 && (
                                            <div>
                                                <h4 className="text-xs font-bold text-gray-400 mb-2 uppercase">Mapeo de Tablas (Preview)</h4>
                                                <div className="bg-black/40 border border-cyber-800 rounded p-3 max-h-[300px] overflow-y-auto custom-scrollbar">
                                                    <div className="space-y-1">
                                                        {selectedLoot.extracted_data.tables_preview.map((t, i) => (
                                                            <div key={i} className="font-mono text-xs text-emerald-300/80 hover:text-emerald-300 flex items-center gap-2">
                                                                <Database size={12} className="opacity-50" />
                                                                {t}
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        <div className="bg-black/30 backdrop-blur-md rounded-lg border border-white/5 shadow-inner p-3 font-mono text-xs">
                                            <div className="text-gray-500 mb-2">RAW JSON</div>
                                            <pre className="whitespace-pre-wrap text-gray-200 overflow-x-auto custom-scrollbar">
                                                {JSON.stringify(selectedLoot, null, 2)}
                                            </pre>
                                        </div>
                                    </div>
                                );
                            }

                            // View Mode: JOBS
                            if (!selectedJob) {
                                return (
                                    <div className="flex items-center justify-center h-full text-gray-600 p-8 text-center italic">
                                        Selecciona un job para ver detalles y gestionar su ciclo de vida.
                                    </div>
                                );
                            }

                            const scanId = String(selectedJob.scan_id || '');
                            const status = String(selectedJob.status || '');
                            const canStop = status === 'queued' || status === 'running';
                            const canRetry = ['failed', 'stopped', 'interrupted', 'completed'].includes(status);

                            return (
                                <div className="p-6 space-y-6">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <h3 className="text-lg font-bold text-gray-200">Detalle del Job</h3>
                                            <div className="text-sm font-mono text-cyan-500 mt-1">{scanId}</div>
                                        </div>
                                    </div>

                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => stopJob(scanId)}
                                            disabled={!canStop}
                                            className={clsx(
                                                "px-3 py-2 rounded text-xs font-bold border transition-all",
                                                canStop ? "text-red-400 bg-red-500/10 hover:bg-red-500/20 border-red-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                            )}
                                        >
                                            DETENER
                                        </button>
                                        <button
                                            onClick={() => retryJob(scanId)}
                                            disabled={!canRetry}
                                            className={clsx(
                                                "px-3 py-2 rounded text-xs font-bold border transition-all",
                                                canRetry ? "text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                            )}
                                        >
                                            REINTENTAR
                                        </button>
                                    </div>

                                    <div className="bg-black/30 backdrop-blur-md rounded-lg border border-white/5 shadow-inner p-3 font-mono text-xs">
                                        <div className="text-gray-500 mb-2">RAW JSON</div>
                                        <pre className="whitespace-pre-wrap text-gray-200 overflow-x-auto custom-scrollbar">
                                            {JSON.stringify(selectedJob, null, 2)}
                                        </pre>
                                    </div>
                                </div>
                            );
                        })()}
                    </div >
                }
            />
        </div >
    );
};


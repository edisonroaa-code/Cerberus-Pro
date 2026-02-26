import React, { useState, useMemo } from 'react';
import { Server } from 'lucide-react';
import clsx from 'clsx';
import { SplitPanelLayout } from './ui/SplitPanelLayout';
import { CerberusJob } from '../types';

interface JobsPanelProps {
    jobs: CerberusJob[];
    fetchJobs: () => void;
    stopJob: (scanId: string) => void;
    retryJob: (scanId: string) => void;
    selectedJob: CerberusJob | null;
    loadJobDetail: (scanId: string) => void;
}

export const JobsPanel: React.FC<JobsPanelProps> = ({
    jobs,
    fetchJobs,
    stopJob,
    retryJob,
    selectedJob,
    loadJobDetail,
}) => {
    const [jobFilterStatus, setJobFilterStatus] = useState<string>('all');
    const [jobFilterKind, setJobFilterKind] = useState<string>('all');

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
                        <div className="bg-cyber-900 border border-cyber-700 rounded-lg overflow-hidden flex flex-col h-full">
                            <div className="p-6 border-b border-cyber-800 flex justify-between items-center bg-cyber-950/50">
                                <h2 className="text-xl font-bold text-emerald-400 flex items-center gap-2">
                                    <Server /> Jobs (cola + ejecución)
                                </h2>
                                <button
                                    onClick={fetchJobs}
                                    className="text-xs bg-cyber-800 hover:bg-cyber-700 text-emerald-400 px-3 py-1 rounded border border-cyber-600 transition-all"
                                >
                                    REFRESCAR
                                </button>
                            </div>

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
                                                <tr key={scanId} className="hover:bg-white/5 transition-colors group">
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
                                                            onClick={() => loadJobDetail(scanId)}
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
                        </div>
                    </div>
                }
                right={
                    <div className="h-full bg-cyber-900 border border-cyber-700 rounded-lg overflow-y-auto w-full">
                        {(() => {
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

                                    <div className="bg-black/40 rounded-lg border border-cyber-800 p-3 font-mono text-xs">
                                        <div className="text-gray-500 mb-2">RAW JSON</div>
                                        <pre className="whitespace-pre-wrap text-gray-200 overflow-x-auto">
                                            {JSON.stringify(selectedJob, null, 2)}
                                        </pre>
                                    </div>
                                </div>
                            );
                        })()}
                    </div>
                }
            />
        </div>
    );
};

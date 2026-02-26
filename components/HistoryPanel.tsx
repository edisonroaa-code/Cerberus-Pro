import React from 'react';
import { Clock, Eye } from 'lucide-react';
import { ScanHistoryItem } from '../types';

interface HistoryPanelProps {
    history: ScanHistoryItem[];
    historyLoading: boolean;
    fetchHistory: () => void;
    loadHistoryItem: (id: string) => void;
}

export const HistoryPanel: React.FC<HistoryPanelProps> = ({
    history,
    historyLoading,
    fetchHistory,
    loadHistoryItem
}) => {
    return (
        <div className="max-w-6xl mx-auto space-y-6">
            <div className="glass-panel p-2 overflow-hidden">
                <div className="p-6 border-b border-cyber-800 flex justify-between items-center bg-cyber-950/50">
                    <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
                        <Clock /> Historial de Escaneos Persistentes
                    </h2>
                    <button
                        onClick={fetchHistory}
                        className="text-xs bg-cyber-800 hover:bg-cyber-700 text-emerald-400 px-3 py-1 rounded border border-cyber-600 transition-all"
                    >
                        REFRESCAR
                    </button>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="text-[10px] uppercase text-gray-500 bg-cyber-950 border-b border-cyber-800">
                            <tr>
                                <th className="px-6 py-3">Fecha y Hora</th>
                                <th className="px-6 py-3">Objetivo (Target)</th>
                                <th className="px-6 py-3">Perfil</th>
                                <th className="px-6 py-3 text-center">Estado</th>
                                <th className="px-6 py-3 text-center">Hallazgos</th>
                                <th className="px-6 py-3 text-right">Acciones</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-cyber-800/50">
                            {history.length > 0 ? history.map((item) => (
                                <tr key={item.id} className="hover:bg-white/5 transition-colors group">
                                    <td className="px-6 py-4 text-xs font-mono text-gray-400">
                                        {new Date(item.timestamp).toLocaleString()}
                                    </td>
                                    <td className="px-6 py-4 text-sm font-bold text-white truncate max-w-[300px]" title={item.target}>
                                        {item.target}
                                    </td>
                                    <td className="px-6 py-4 text-xs">
                                        <span className="bg-cyber-800 text-cyan-400 px-2 py-0.5 rounded border border-cyber-700">
                                            {item.profile}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                        {item.vulnerable ? (
                                            <span className="text-red-500 bg-red-500/10 px-2 py-0.5 rounded text-[10px] font-bold border border-red-500/20">VULNERABLE</span>
                                        ) : (
                                            <span className="text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded text-[10px] font-bold border border-emerald-500/20">GUARECIDO</span>
                                        )}
                                    </td>
                                    <td className="px-6 py-4 text-center font-mono text-emerald-400 text-sm">
                                        {item.count}
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <button
                                            onClick={() => loadHistoryItem(item.id)}
                                            className="text-emerald-500 hover:text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 p-2 rounded transition-all"
                                            title="Ver Reporte"
                                        >
                                            <Eye size={16} />
                                        </button>
                                    </td>
                                </tr>
                            )) : (
                                <tr>
                                    <td colSpan={6} className="px-6 py-12 text-center text-gray-600 italic">
                                        {historyLoading ? (
                                            "Cargando historial..."
                                        ) : "No hay registros en el historial persistente. Completa un escaneo para guardar un registro."}
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};


import React from 'react';
import { FingerprintData } from '../types';
import { Smartphone, Globe, Shield, RefreshCw } from 'lucide-react';

interface FingerprintViewProps {
  fingerprints: FingerprintData[];
  currentFingerprintId: string;
}

const FingerprintView: React.FC<FingerprintViewProps> = ({ fingerprints, currentFingerprintId }) => {
  return (
    <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-4 h-full overflow-y-auto">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold text-emerald-400 flex items-center gap-2">
          <Shield size={20} /> Cambio de Identidad (Proxy Chimera)
        </h2>
        <button disabled className="text-xs bg-cyber-800 text-gray-500 px-3 py-1 rounded flex items-center gap-1 cursor-not-allowed opacity-60" title="Función no conectada al backend aún">
          <RefreshCw size={12} /> Rotar Identidad
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {fingerprints.map((fp) => (
          <div
            key={fp.name}
            className={`p-4 rounded border transition-all ${fp.name === currentFingerprintId
                ? 'bg-cyber-800 border-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                : 'bg-cyber-950 border-cyber-800 opacity-70 hover:opacity-100 hover:border-cyber-600'
              }`}
          >
            <div className="flex justify-between items-start mb-2">
              <div className="flex items-center gap-2">
                {fp.tags.includes('Móvil') ? <Smartphone size={16} className="text-cyan-400" /> : <Globe size={16} className="text-blue-400" />}
                <span className="font-bold text-sm">{fp.name}</span>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded ${fp.score < 30 ? 'bg-red-900 text-red-200' : 'bg-emerald-900 text-emerald-200'}`}>
                Puntuación: {fp.score}
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono text-gray-400">
              <div className="flex justify-between">
                <span>JA3:</span>
                <span className="text-gray-500 truncate w-32" title={fp.ja3Hash}>{fp.ja3Hash}</span>
              </div>
              <div className="flex justify-between">
                <span>HTTP:</span>
                <span className="text-white">{fp.httpVersion}</span>
              </div>
              <div className="flex justify-between">
                <span>UA:</span>
                <span className="text-gray-500 truncate w-32" title={fp.userAgent}>{fp.userAgent}</span>
              </div>
            </div>

            {fp.name === currentFingerprintId && (
              <div className="mt-3 text-xs text-center text-emerald-500 animate-pulse">
                ● SESIÓN ACTIVA
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default FingerprintView;
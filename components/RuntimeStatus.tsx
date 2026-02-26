import React, { useEffect, useState } from 'react';
import { Activity } from 'lucide-react';

interface RuntimeStatus {
  version: string;
  environment: string;
  timestamp: string;
  worker_id: string;
  features: Record<string, boolean>;
}

export const RuntimeStatusDisplay: React.FC = () => {
  const [status, setStatus] = useState<RuntimeStatus | null>(null);

  useEffect(() => {
    const fetchStatus = async () => {
        try {
            const res = await fetch('/status/runtime');
            if (res.ok) {
                const data = await res.json();
                setStatus(data);
            }
        } catch (err) {
            console.error("Failed to fetch runtime status", err);
        }
    };
    fetchStatus();
    // Poll every 30s
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  if (!status) return null;

  return (
    <div className="mt-4 px-4 py-2 border-t border-cyber-800 text-[10px] text-gray-500 font-mono">
      <div className="flex items-center gap-1 mb-1">
        <Activity size={10} className="text-emerald-500" />
        <span className="font-bold text-gray-400">RUNTIME</span>
      </div>
      <div>v{status.version} ({status.environment})</div>
      <div className="truncate" title={status.worker_id}>{status.worker_id}</div>
    </div>
  );
};

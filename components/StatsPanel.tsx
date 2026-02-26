import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { SystemMetrics } from '../types';

interface StatsPanelProps {
  metricsHistory: SystemMetrics[];
}

const StatsPanel: React.FC<StatsPanelProps> = React.memo(({ metricsHistory }) => {
  // Use last 20 points for chart
  const data = metricsHistory.slice(-20).map((m, i) => ({
    time: i,
    rps: m.requestsPerSecond,
    evasion: m.evasionRate,
  }));

  const lastMetric = metricsHistory[metricsHistory.length - 1] || { requestsPerSecond: 0, evasionRate: 100, activeThreads: 0, wafBlockCount: 0 };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
      {/* KPI Cards */}
      <div className="col-span-1 lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-cyber-800 p-4 rounded border border-cyber-700">
          <div className="text-gray-400 text-xs uppercase tracking-wider">Peticiones/Seg (RPS)</div>
          <div className="text-2xl font-mono text-emerald-400">{lastMetric.requestsPerSecond}</div>
        </div>
        <div className="bg-cyber-800 p-4 rounded border border-cyber-700">
          <div className="text-gray-400 text-xs uppercase tracking-wider">Tasa de Evasión</div>
          <div className="text-2xl font-mono text-cyan-400">{lastMetric.evasionRate}%</div>
        </div>
        <div className="bg-cyber-800 p-4 rounded border border-cyber-700">
          <div className="text-gray-400 text-xs uppercase tracking-wider">Hilos Activos</div>
          <div className="text-2xl font-mono text-purple-400">{lastMetric.activeThreads}</div>
        </div>
        <div className="bg-cyber-800 p-4 rounded border border-cyber-700">
          <div className="text-gray-400 text-xs uppercase tracking-wider">Bloqueos WAF</div>
          <div className="text-2xl font-mono text-red-500">{lastMetric.wafBlockCount}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="col-span-1 lg:col-span-2 bg-cyber-800 p-4 rounded border border-cyber-700 h-64">
        <h3 className="text-xs text-gray-400 uppercase mb-2">Rendimiento vs Evasión</h3>
        {/* Fixed height avoids Recharts -1 sizing when layout is still settling. */}
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorRps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorEvasion" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" hide />
            <YAxis stroke="#94a3b8" fontSize={10} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }}
              itemStyle={{ color: '#e2e8f0' }}
              formatter={(value: number, name: string) => [value, name === 'rps' ? 'RPS' : 'Evasión %']}
              labelFormatter={() => ''}
            />
            <Area type="monotone" dataKey="rps" stroke="#10b981" fillOpacity={1} fill="url(#colorRps)" name="rps" />
            <Area type="monotone" dataKey="evasion" stroke="#06b6d4" fillOpacity={1} fill="url(#colorEvasion)" name="evasion" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="col-span-1 bg-cyber-800 p-4 rounded border border-cyber-700 h-64">
        <h3 className="text-xs text-gray-400 uppercase mb-2">Confianza de Bypass WAF</h3>
        <div className="flex items-center justify-center h-full pb-6">
          <div className="relative w-40 h-40">
            <svg className="w-full h-full" viewBox="0 0 36 36">
              <path
                className="text-cyber-700"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              />
              <path
                className="text-cyber-accent"
                strokeDasharray={`${lastMetric.evasionRate}, 100`}
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-center">
              <span className="text-2xl font-bold text-white">{Math.round(lastMetric.evasionRate)}%</span>
              <span className="block text-xs text-gray-400">SIGILO</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

export default StatsPanel;

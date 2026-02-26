import React, { useEffect, useMemo, useRef, useState } from 'react';
import { LogEntry } from '../types';
import clsx from 'clsx';
import { Copy, Download, Pause, Play, Search, Trash2, ArrowDown } from 'lucide-react';

interface TerminalProps {
  logs: LogEntry[];
  onCommand: (cmd: string) => void;
  onClear?: () => void;
  title?: string;
}

const Terminal: React.FC<TerminalProps> = React.memo(({ logs, onCommand, onClear, title = 'Output Logs' }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);

  // UX controls
  const [isPaused, setIsPaused] = useState(false);
  const [pausedSnapshot, setPausedSnapshot] = useState<LogEntry[] | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLevel, setSelectedLevel] = useState<'ALL' | LogEntry['level']>('ALL');

  const displayLogs = isPaused ? (pausedSnapshot || []) : logs;

  const filteredLogs = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return displayLogs.filter((l) => {
      if (selectedLevel !== 'ALL' && l.level !== selectedLevel) return false;
      if (!q) return true;
      const hay = `${l.timestamp} ${l.component} ${l.level} ${l.message}`.toLowerCase();
      return hay.includes(q);
    });
  }, [displayLogs, searchTerm, selectedLevel]);

  useEffect(() => {
    const container = scrollRef.current;
    if (!container) return;
    if (isPaused) return;
    if (!autoScroll) return;
    container.scrollTop = container.scrollHeight;
  }, [filteredLogs, isPaused, autoScroll]);

  const handleScroll = () => {
    const container = scrollRef.current;
    if (!container) return;
    const { scrollTop, scrollHeight, clientHeight } = container;
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 80;
    setAutoScroll(isNearBottom);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      if (input.trim()) {
        onCommand(input);
        setHistory(prev => [...prev, input]);
        setHistoryIndex(-1);
        setInput('');
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0) {
        const newIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex !== -1) {
        const newIndex = Math.min(history.length - 1, historyIndex + 1);
        if (newIndex === history.length - 1 && historyIndex === history.length - 1) {
          setHistoryIndex(-1);
          setInput('');
        } else {
          setHistoryIndex(newIndex);
          setInput(history[newIndex]);
        }
      }
    }
  };

  const getLevelColor = (level: LogEntry['level']) => {
    switch (level) {
      case 'INFO': return 'text-blue-400';
      case 'WARN': return 'text-yellow-400';
      case 'ERROR': return 'text-red-500';
      case 'SUCCESS': return 'text-emerald-400';
      default: return 'text-gray-400';
    }
  };

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // ignore (clipboard can be blocked by browser permissions)
    }
  };

  const copyLogs = async () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] [${l.level}] [${l.component}] ${l.message}`)
      .join('\n');
    await copyText(text);
  };

  const downloadLogs = () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] [${l.level}] [${l.component}] ${l.message}`)
      .join('\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cerberus_logs_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const togglePause = () => {
    setIsPaused((prev) => {
      const next = !prev;
      if (next) {
        setPausedSnapshot(logs.slice());
        setAutoScroll(false);
      } else {
        setPausedSnapshot(null);
        setAutoScroll(true);
      }
      return next;
    });
  };

  return (
    <div className="bg-cyber-900 border border-cyber-700 rounded-lg overflow-hidden flex flex-col h-full font-mono text-sm shadow-[0_0_15px_rgba(0,0,0,0.5)]">
      <div className="bg-cyber-800 px-4 py-2 flex items-center justify-between border-b border-cyber-700 gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-gray-400 font-bold flex items-center gap-2 min-w-0">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="truncate">{title}</span>
          </span>
          <span className="text-[10px] text-gray-500 whitespace-nowrap">
            {filteredLogs.length}/{displayLogs.length} logs
          </span>
          {isPaused ? (
            <span className="text-[10px] text-yellow-400 border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 rounded whitespace-nowrap">
              PAUSED (buffering)
            </span>
          ) : (
            <span className="text-[10px] text-emerald-400 whitespace-nowrap">● LIVE</span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative hidden md:block">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search..."
              className="pl-8 pr-3 py-1.5 text-xs bg-cyber-950 border border-cyber-700 rounded text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
            />
          </div>

          <select
            value={selectedLevel}
            onChange={(e) => setSelectedLevel(e.target.value as any)}
            className="px-2 py-1.5 text-xs bg-cyber-950 border border-cyber-700 rounded text-gray-200 focus:outline-none"
            title="Filter by level"
          >
            <option value="ALL">All</option>
            <option value="INFO">INFO</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
          </select>

          <div className="flex items-center gap-1">
            <button
              onClick={togglePause}
              className="p-1.5 rounded hover:bg-white/5 text-gray-300"
              title={isPaused ? 'Resume' : 'Pause'}
            >
              {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            </button>
            <button
              onClick={copyLogs}
              className="p-1.5 rounded hover:bg-white/5 text-gray-300"
              title="Copy filtered logs"
            >
              <Copy className="w-4 h-4" />
            </button>
            <button
              onClick={downloadLogs}
              className="p-1.5 rounded hover:bg-white/5 text-gray-300"
              title="Download filtered logs"
            >
              <Download className="w-4 h-4" />
            </button>
            {onClear && (
              <button
                onClick={() => {
                  setPausedSnapshot(null);
                  setIsPaused(false);
                  setAutoScroll(true);
                  onClear();
                }}
                className="p-1.5 rounded hover:bg-red-500/10 text-red-400"
                title="Clear logs"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Log Output Area */}
      <div
        ref={scrollRef}
        className="flex-1 p-4 overflow-y-auto space-y-0.5 bg-black/90 font-mono text-xs scroll-smooth"
        onScroll={handleScroll}
        onClick={() => document.getElementById('term-input')?.focus()}
      >
        {displayLogs.length === 0 && <div className="text-gray-600 italic">Inicializando motor Cerberus Pro...</div>}
        {filteredLogs.map((log) => (
          <div key={log.id} className="flex gap-2 hover:bg-white/5 px-2 py-1 rounded group select-text">
            <span className="text-gray-600 shrink-0 select-none text-[10px] whitespace-nowrap">[{log.timestamp}]</span>
            <span className={clsx("font-bold w-28 shrink-0 select-none text-[10px]",
              log.component === 'ORQUESTADOR' ? 'text-purple-400' :
                (log.component === 'CERBERUS_PRO' || log.component === 'SQLMAP') ? 'text-orange-400' :
                  log.component === 'PROXY' ? 'text-cyan-400' : 'text-gray-400'
            )}>
              {log.component}
            </span>
            <span className={clsx("flex-1 break-words whitespace-normal", getLevelColor(log.level))}>
              {log.message}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                void copyText(log.message);
              }}
              className="opacity-0 group-hover:opacity-100 ml-auto text-gray-500 hover:text-gray-200"
              title="Copy line"
            >
              <Copy className="w-3 h-3" />
            </button>
          </div>
        ))}

        {!isPaused && !autoScroll && (
          <button
            onClick={() => {
              setAutoScroll(true);
              const c = scrollRef.current;
              if (c) c.scrollTop = c.scrollHeight;
            }}
            className="sticky bottom-3 left-1/2 -translate-x-1/2 px-3 py-2 rounded-full bg-cyan-600/80 hover:bg-cyan-600 text-white text-[11px] font-bold shadow-lg inline-flex items-center gap-2"
            title="Scroll to bottom"
          >
            <ArrowDown className="w-4 h-4" />
            Scroll to bottom
          </button>
        )}
      </div>

      {/* Input Area */}
      <div className="bg-cyber-950 p-2 border-t border-cyber-800 flex items-center gap-2">
        <span className="text-emerald-500 font-bold">root@cerberus:~#</span>
        <input
          id="term-input"
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-transparent border-none outline-none text-gray-200 font-mono"
          autoComplete="off"
          placeholder="Escriba un comando (ej: help, run, set target)..."
          autoFocus
        />
      </div>
    </div>
  );
});

export default Terminal;

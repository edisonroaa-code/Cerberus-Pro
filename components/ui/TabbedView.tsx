import React, { useMemo, useState } from 'react';
import clsx from 'clsx';
import { X } from 'lucide-react';

export interface TabDef {
  id: string;
  label: string;
  icon?: React.ReactNode;
  content: React.ReactNode;
  closeable?: boolean;
  badge?: number;
}

export function TabbedView({
  tabs,
  defaultTab,
  className = '',
}: {
  tabs: TabDef[];
  defaultTab?: string;
  className?: string;
}) {
  const initial = useMemo(() => defaultTab || tabs[0]?.id, [defaultTab, tabs]);
  const [activeTab, setActiveTab] = useState<string>(initial || '');
  const [openTabs, setOpenTabs] = useState<string[]>(tabs.map((t) => t.id));

  const visibleTabs = tabs.filter((t) => openTabs.includes(t.id));
  const activeTabDef = visibleTabs.find((t) => t.id === activeTab) || visibleTabs[0];

  const closeTab = (id: string) => {
    const next = openTabs.filter((t) => t !== id);
    setOpenTabs(next);
    if (activeTab === id) {
      setActiveTab(next[0] || '');
    }
  };

  return (
    <div className={clsx('flex flex-col h-full overflow-hidden', className)}>
      <div className="flex border-b border-cyber-800 bg-cyber-900/60">
        {visibleTabs.map((tab) => (
          <div
            key={tab.id}
            className={clsx(
              'flex items-center border-b-2',
              activeTab === tab.id
                ? 'bg-cyber-950 border-cyan-500'
                : 'border-transparent hover:bg-cyber-800/40'
            )}
          >
            <button
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'flex items-center gap-2 px-4 py-3 text-xs font-bold transition-colors',
                activeTab === tab.id ? 'text-white' : 'text-gray-400 hover:text-gray-200'
              )}
              aria-label={`Open tab ${tab.label}`}
              type="button"
            >
              {tab.icon}
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span className="px-2 py-0.5 text-[10px] bg-cyan-600 text-white rounded-full">
                  {tab.badge}
                </span>
              )}
            </button>
            {tab.closeable && (
              <button
                onClick={() => closeTab(tab.id)}
                className="mr-2 p-0.5 rounded hover:bg-red-500/10 text-gray-400 hover:text-red-400"
                aria-label={`Close tab ${tab.label}`}
                title="Close tab"
                type="button"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-hidden">
        {activeTabDef ? (
          <div key={activeTabDef.id} className="h-full">
            {activeTabDef.content}
          </div>
        ) : null}
      </div>
    </div>
  );
}

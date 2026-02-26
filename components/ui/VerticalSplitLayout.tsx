import React, { useEffect, useRef, useState } from 'react';

export function VerticalSplitLayout({
  top,
  bottom,
  defaultTopHeight = 55,
  minTop = 20,
  maxTop = 80,
  className = '',
}: {
  top: React.ReactNode;
  bottom: React.ReactNode;
  defaultTopHeight?: number; // percentage
  minTop?: number;
  maxTop?: number;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [topHeight, setTopHeight] = useState(defaultTopHeight);
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    if (!isResizing) return;

    const onMove = (e: MouseEvent) => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const raw = ((e.clientY - rect.top) / rect.height) * 100;
      const next = Math.max(minTop, Math.min(maxTop, raw));
      setTopHeight(next);
    };
    const onUp = () => setIsResizing(false);

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [isResizing, minTop, maxTop]);

  return (
    <div
      ref={containerRef}
      className={`flex flex-col h-full overflow-hidden min-h-0 min-w-0 ${className}`}
    >
      <div
        style={{ height: `${topHeight}%` }}
        className="flex flex-col overflow-hidden min-h-0 min-w-0"
      >
        {top}
      </div>

      <div
        onMouseDown={() => setIsResizing(true)}
        className="h-1 bg-cyber-800 hover:bg-cyan-500 cursor-row-resize relative shrink-0"
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize panels"
      >
        <div className="absolute inset-x-0 -top-1 -bottom-1" />
      </div>

      <div
        style={{ height: `${100 - topHeight}%` }}
        className="flex flex-col overflow-hidden min-h-0 min-w-0"
      >
        {bottom}
      </div>
    </div>
  );
}


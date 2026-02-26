import React, { useEffect, useRef, useState } from 'react';

export function SplitPanelLayout({
  left,
  right,
  defaultLeftWidth = 55,
  minLeft = 20,
  maxLeft = 80,
  className = '',
}: {
  left: React.ReactNode;
  right: React.ReactNode;
  defaultLeftWidth?: number;
  minLeft?: number;
  maxLeft?: number;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [leftWidth, setLeftWidth] = useState(defaultLeftWidth);
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    if (!isResizing) return;

    const onMove = (e: MouseEvent) => {
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const raw = ((e.clientX - rect.left) / rect.width) * 100;
      const next = Math.max(minLeft, Math.min(maxLeft, raw));
      setLeftWidth(next);
    };
    const onUp = () => setIsResizing(false);

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [isResizing, minLeft, maxLeft]);

  return (
    <div
      ref={containerRef}
      className={`flex flex-col lg:flex-row h-full overflow-hidden min-h-0 min-w-0 ${className}`}
    >
      {/* Mobile: stack panels without overlap. Right panel uses remaining height. */}
      <div className="lg:hidden flex-none overflow-hidden min-w-0">
        {left}
      </div>
      <div className="lg:hidden h-3 shrink-0" />
      <div className="lg:hidden flex-1 overflow-hidden min-h-0 min-w-0">
        {right}
      </div>

      {/* Desktop split */}
      <div
        style={{ width: `${leftWidth}%` }}
        className="hidden lg:flex flex-col overflow-hidden min-h-0 min-w-0"
      >
        {left}
      </div>

      <div
        onMouseDown={() => setIsResizing(true)}
        className="hidden lg:block w-1 bg-cyber-800 hover:bg-cyan-500 cursor-col-resize relative"
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize panels"
      >
        <div className="absolute inset-y-0 -left-1 -right-1" />
      </div>

      <div
        style={{ width: `${100 - leftWidth}%` }}
        className="hidden lg:flex flex-col overflow-hidden min-h-0 min-w-0"
      >
        {right}
      </div>
    </div>
  );
}

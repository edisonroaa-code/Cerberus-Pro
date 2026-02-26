import React, { useState } from 'react';
import clsx from 'clsx';
import { Check, Copy } from 'lucide-react';

export function CopyableText({
  text,
  className = '',
  label,
}: {
  text: string;
  className?: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <div className={clsx('flex items-center gap-2', className)}>
      {label && <span className="text-[10px] uppercase text-gray-500 font-bold">{label}</span>}
      <code className="flex-1 px-3 py-2 bg-black/40 border border-cyber-800 rounded font-mono text-xs text-gray-200 overflow-x-auto">
        {text}
      </code>
      <button
        onClick={onCopy}
        className="p-2 rounded hover:bg-white/5 text-gray-400 hover:text-gray-200"
        title="Copy"
        aria-label="Copy"
      >
        {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  );
}


import React, { Suspense } from 'react';
import TerminalView from './Terminal';
import { VerticalSplitLayout } from './ui/VerticalSplitLayout';
import { TabbedView } from './ui/TabbedView';
import { LogEntry, SystemMetrics, FingerprintData } from '../types';

const AttackMap = React.lazy(() => import('./AttackMap'));
const StatsPanel = React.lazy(() => import('./StatsPanel'));
const FingerprintView = React.lazy(() => import('./FingerprintView'));

interface ReportViewerProps {
    mode: 'dashboard' | 'campaign';
    logs: LogEntry[];
    metrics: SystemMetrics[];
    agentConnected: boolean;
    targetUrl: string;
    handleTerminalCommand: (cmd: string) => void;
    setLogs: (logs: LogEntry[]) => void;
    activeFingerprint: string | null;
    fingerprints: FingerprintData[];
    profileRules: any;
    targetProfile: string;
}

export const ReportViewer: React.FC<ReportViewerProps> = ({
    mode,
    logs,
    metrics,
    agentConnected,
    targetUrl,
    handleTerminalCommand,
    setLogs,
    activeFingerprint,
    fingerprints,
    profileRules,
    targetProfile,
}) => {
    if (mode === 'dashboard') {
        return (
            <div className="space-y-6">
                <div className="h-[520px]">
                    <VerticalSplitLayout
                        defaultTopHeight={55}
                        top={
                            <Suspense fallback={<div className="h-full rounded border border-cyber-700 bg-cyber-900/60 animate-pulse" />}>
                                <AttackMap
                                    agentConnected={agentConnected}
                                    events={logs}
                                    targetUrl={targetUrl}
                                    metrics={metrics.length ? metrics[metrics.length - 1] : null}
                                />
                            </Suspense>
                        }
                        bottom={
                            <TerminalView
                                logs={logs}
                                onCommand={handleTerminalCommand}
                                onClear={() => setLogs([])}
                                title="CERBERUS://CONSOLA_ROOT"
                            />
                        }
                    />
                </div>
                <div className="h-80">
                    <Suspense fallback={<div className="h-full rounded border border-cyber-700 bg-cyber-900/60 animate-pulse" />}>
                        <StatsPanel metricsHistory={metrics} />
                    </Suspense>
                </div>
            </div>
        );
    }

    // Campaign mode
    return (
        <div className="h-full overflow-hidden min-w-0">
            <TabbedView
                defaultTab="terminal"
                tabs={[
                    {
                        id: 'terminal',
                        label: 'Terminal',
                        content: (
                            <TerminalView
                                logs={logs}
                                onCommand={handleTerminalCommand}
                                onClear={() => setLogs([])}
                                title="SQLMap Output"
                            />
                        )
                    },
                    {
                        id: 'fingerprint',
                        label: 'Fingerprint',
                        content: (
                            <div className="h-full overflow-hidden">
                                <Suspense fallback={<div className="h-full rounded border border-cyber-700 bg-cyber-900/60 animate-pulse" />}>
                                    <FingerprintView
                                        fingerprints={fingerprints.filter(fp => {
                                            const rules = profileRules[targetProfile];
                                            return rules && fp.tags.some((tag: string) => rules.tags.includes(tag));
                                        })}
                                        currentFingerprintId={activeFingerprint}
                                    />
                                </Suspense>
                            </div>
                        )
                    }
                ]}
            />
        </div>
    );
};



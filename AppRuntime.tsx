import React, { Suspense, useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { Activity, Shield, Play, StopCircle, Zap, BrainCircuit, FileText, Download, Server, Code, Database, Copy, Eye, Clock, Archive, Skull } from 'lucide-react';
import clsx from 'clsx';
import TerminalView from './components/Terminal';
import { SplitPanelLayout } from './components/ui/SplitPanelLayout';
import { CopyableText } from './components/ui/CopyableText';
import { TabbedView } from './components/ui/TabbedView';
import { VerticalSplitLayout } from './components/ui/VerticalSplitLayout';
import { JobsPanel } from './components/JobsPanel';
import { ReportViewer } from './components/ReportViewer';

import { HistoryPanel } from './components/HistoryPanel';
import { CampaignPanel } from './components/CampaignPanel';

import { LogEntry, SystemMetrics, AttackProfile, TargetConfig, ScanHistoryItem } from './types';
import { generatePdfReport } from './services/reportService';
import { API_BASE_URL, WS_BASE_URL } from './services/apiConfig';
import { checkBackendReady } from './services/backendHealth';
import { formatBlockerForDisplay, normalizeCoverageBlockers, normalizeReport, safeStringify, type ReportState } from './services/reportNormalization';
import { useAuth, LoginPage, UserMenu } from './components/AuthContext';
import { computeUnifiedRiskLevel } from './utils/unifiedRisk';
import { FINGERPRINT_CATALOG, PROFILE_RULES, DEFAULT_CONFIG, ACTIVE_JOB_STATUSES, TERMINAL_JOB_STATUSES } from './config/scanDefaults';
import { UnifiedUiConfig, UnifiedStatusMeta, UnifiedCapabilities, DEFAULT_UNIFIED_CONFIG, UNIFIED_PRESETS, type UnifiedMode, type UnifiedVector, type DirectDbEngine } from './config/unifiedConfig';
import { AGENT_SCRIPT } from './config/agentScript';

const StatsPanel = React.lazy(() => import('./components/StatsPanel'));
const AttackMap = React.lazy(() => import('./components/AttackMap'));
const FingerprintView = React.lazy(() => import('./components/FingerprintView'));
const ReportPanel = React.lazy(() => import('./components/ReportPanel'));

let geminiModulePromise: Promise<typeof import('./services/geminiService')> | null = null;
const loadGeminiService = () => {
    if (!geminiModulePromise) {
        geminiModulePromise = import('./services/geminiService');
    }
    return geminiModulePromise;
};

// ARCH-001: Constants extracted to config/scanDefaults.ts

// ARCH-001: Unified config/types extracted to config/unifiedConfig.ts
// ARCH-001: Agent script extracted to config/agentScript.ts
// ARCH-001: parseJson, ACTIVE/TERMINAL status sets extracted to config/scanDefaults.ts

const parseJson = async (response: Response) => {
    try {
        return await response.json();
    } catch {
        return {};
    }
};

const toSafeNumber = (value: unknown, fallback: number) => {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
};

const normalizeTargetConfig = (raw: any): TargetConfig => {
    const baseSql = DEFAULT_CONFIG.sqlMap;
    const incoming = raw && typeof raw === 'object' ? raw : {};
    const incomingSql = incoming.sqlMap && typeof incoming.sqlMap === 'object' ? incoming.sqlMap : {};
    const validProfiles = Object.values(AttackProfile) as string[];
    const rawProfile = String(incoming.profile || DEFAULT_CONFIG.profile);
    const profile = (validProfiles.includes(rawProfile) ? rawProfile : DEFAULT_CONFIG.profile) as AttackProfile;
    const tamperRaw = incomingSql.tamper;
    const techniqueRaw = incomingSql.technique;

    return {
        ...DEFAULT_CONFIG,
        ...incoming,
        url: String(incoming.url || DEFAULT_CONFIG.url),
        profile,
        aggressionLevel: toSafeNumber(incoming.aggressionLevel, DEFAULT_CONFIG.aggressionLevel),
        useSmartEvasion: typeof incoming.useSmartEvasion === 'boolean' ? incoming.useSmartEvasion : DEFAULT_CONFIG.useSmartEvasion,
        autoPilot: typeof incoming.autoPilot === 'boolean' ? incoming.autoPilot : DEFAULT_CONFIG.autoPilot,
        sqlMap: {
            ...baseSql,
            ...incomingSql,
            technique: typeof techniqueRaw === 'string'
                ? techniqueRaw
                : (Array.isArray(techniqueRaw) ? techniqueRaw.join('') : baseSql.technique),
            tamper: typeof tamperRaw === 'string'
                ? tamperRaw
                : (Array.isArray(tamperRaw) ? tamperRaw.filter(Boolean).join(',') : baseSql.tamper),
            threads: toSafeNumber(incomingSql.threads, baseSql.threads),
            level: toSafeNumber(incomingSql.level, baseSql.level),
            risk: toSafeNumber(incomingSql.risk, baseSql.risk),
            randomAgent: typeof incomingSql.randomAgent === 'boolean' ? incomingSql.randomAgent : baseSql.randomAgent,
            hpp: typeof incomingSql.hpp === 'boolean' ? incomingSql.hpp : baseSql.hpp,
            hex: typeof incomingSql.hex === 'boolean' ? incomingSql.hex : baseSql.hex,
            getDbs: typeof incomingSql.getDbs === 'boolean' ? incomingSql.getDbs : baseSql.getDbs,
            getTables: typeof incomingSql.getTables === 'boolean' ? incomingSql.getTables : baseSql.getTables,
            getColumns: typeof incomingSql.getColumns === 'boolean' ? incomingSql.getColumns : baseSql.getColumns,
            dumpAll: typeof incomingSql.dumpAll === 'boolean' ? incomingSql.dumpAll : baseSql.dumpAll,
            currentUser: typeof incomingSql.currentUser === 'boolean' ? incomingSql.currentUser : baseSql.currentUser,
            currentDb: typeof incomingSql.currentDb === 'boolean' ? incomingSql.currentDb : baseSql.currentDb,
        },
    };
};











const normalizeJobStatus = (value: unknown): string => String(value || '').trim().toLowerCase();

const extractApiErrorMessage = (payload: any, fallback = 'Error desconocido'): string => {
    if (!payload) return fallback;
    const candidates = [payload.detail, payload.msg, payload.message, payload.error];
    for (const c of candidates) {
        if (typeof c === 'string' && c.trim()) return c.trim();
    }
    const detail = payload.detail;
    if (Array.isArray(detail)) {
        const first = detail.find((x) => x);
        if (typeof first === 'string') return first;
        if (first && typeof first === 'object') {
            const obj = first as Record<string, unknown>;
            if (typeof obj.message === 'string') return obj.message;
            if (typeof obj.msg === 'string') return obj.msg;
            if (typeof obj.code === 'string') return obj.code;
            return safeStringify(obj, false);
        }
    }
    if (detail && typeof detail === 'object') {
        const obj = detail as Record<string, unknown>;
        if (typeof obj.message === 'string') return obj.message;
        if (typeof obj.msg === 'string') return obj.msg;
        if (typeof obj.code === 'string') return obj.code;
        return safeStringify(obj, false);
    }
    if (typeof payload === 'string') return payload;
    return fallback;
};

const App: React.FC = () => {
    const { authState, loading, authFetch } = useAuth();
    const [activeTab, setActiveTab] = useState<'DASHBOARD' | 'CAMPAIGN' | 'ANALYSIS' | 'HISTORY' | 'JOBS'>('DASHBOARD');
    const [isRunning, setIsRunning] = useState(false);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [metrics, setMetrics] = useState<SystemMetrics[]>([]);
    const [history, setHistory] = useState<ScanHistoryItem[]>([]);
    const [historyLoading, setHistoryLoading] = useState(false);
    const [jobsLoading, setJobsLoading] = useState(false);
    const [jobs, setJobs] = useState<any[]>([]);
    const [selectedJob, setSelectedJob] = useState<any | null>(null);

    // Loot DB State
    const [lootLoading, setLootLoading] = useState(false);
    const [loots, setLoots] = useState<any[]>([]);

    // Report states
    const [showReport, setShowReport] = useState(false);
    const [reportData, setReportData] = useState<ReportState>({
        verdict: 'INCONCLUSIVE',
        conclusive: false,
        vulnerable: false,
        message: '',
        count: 0,
        evidenceCount: 0,
        resultsCount: 0,
        data: [],
        coverage: null,
        kind: '',
        mode: '',
        scanId: ''
    });

    const formatExtractedValue = (value: unknown): string => {
        if (value === null || value === undefined) return '(sin datos)';
        if (typeof value === 'string') {
            const text = value.trim();
            if (!text) return '(vacío)';
            if (text === '[object Object]') return '(objeto sin serializar en origen)';
            if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
                try {
                    return safeStringify(JSON.parse(text), false);
                } catch {
                    return text;
                }
            }
            return text;
        }
        if (typeof value === 'object') return safeStringify(value, false);
        return String(value);
    };
    const normalizeReportPayload = normalizeReport;

    // State for Agent and Fingerprints
    const [showAgentModal, setShowAgentModal] = useState(false);
    const [agentConnected, setAgentConnected] = useState(false);
    const [activeFingerprint, setActiveFingerprint] = useState<string>('Chrome 120 (Win10)');
    const [showAdvancedCampaign, setShowAdvancedCampaign] = useState(false);

    // Persistence
    const [targetConfig, setTargetConfig] = useState<TargetConfig>(() => {
        const saved = localStorage.getItem('cerberus_config_v2');
        if (!saved) return DEFAULT_CONFIG;
        try {
            return normalizeTargetConfig(JSON.parse(saved));
        } catch {
            return DEFAULT_CONFIG;
        }
    });
    const [unifiedConfig, setUnifiedConfig] = useState<UnifiedUiConfig>(() => {
        const saved =
            localStorage.getItem('cerberus_unified_config_v1')
            || localStorage.getItem('cerberus_omni_config_v1');
        if (saved) {
            try {
                return JSON.parse(saved);
            } catch (e) {
                console.error("Error parsing unifiedConfig:", e);
                return DEFAULT_UNIFIED_CONFIG;
            }
        }
        return DEFAULT_UNIFIED_CONFIG;
    });
    const [unifiedStatus, setUnifiedStatus] = useState<{ running: boolean; meta?: UnifiedStatusMeta }>({ running: false });
    const [unifiedCapabilities, setUnifiedCapabilities] = useState<UnifiedCapabilities>({
        modes: ['web', 'graphql', 'direct_db', 'ws', 'mqtt', 'grpc'],
        vectors: ['UNION', 'ERROR', 'TIME', 'BOOLEAN', 'STACKED', 'INLINE', 'AIIE', 'NOSQL', 'SSTI'],
        limits: { max_parallel_min: 1, max_parallel_max: 8 }
    });
    const [engineHealth, setEngineHealth] = useState<{
        connected: number;
        total: number;
        items: Array<{ id: string; connected: boolean; status: string }>;
    }>({
        connected: 0,
        total: 0,
        items: []
    });

    // Background job execution (backend worker queue)
    const [unifiedJobId, setUnifiedJobId] = useState<string | null>(null);
    const [unifiedJobStatus, setUnifiedJobStatus] = useState<string | null>(null);
    const unifiedRisk = (() => {
        const label = computeUnifiedRiskLevel({
            mode: unifiedConfig.mode,
            maxParallel: unifiedConfig.maxParallel,
            vectorsCount: unifiedConfig.vectors.length,
            sqlRisk: targetConfig.sqlMap.risk,
            sqlLevel: targetConfig.sqlMap.level
        });
        if (label === 'CRITICAL') return { label, className: 'bg-red-500/20 text-red-300 border-red-400/50' };
        if (label === 'HIGH') return { label, className: 'bg-orange-500/20 text-orange-300 border-orange-400/50' };
        if (label === 'MEDIUM') return { label, className: 'bg-yellow-500/20 text-yellow-300 border-yellow-400/50' };
        return { label, className: 'bg-emerald-500/20 text-emerald-300 border-emerald-400/50' };
    })();

    const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [aiStats, setAiStats] = useState({
        payloadsMutated: 0,
        honeypotsDetected: 0,
        stegoBytes: 0
    });
    const geminiApiConfigured = useMemo(() => {
        const key = `${process.env.GEMINI_API_KEY || process.env.API_KEY || ''}`.trim();
        return key.length > 0;
    }, []);

    const ws = useRef<WebSocket | null>(null);
    const wsRetryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Keep enough logs for search/copy without going unbounded.
    const LOG_RING_MAX = 5000;

    const addLog = useCallback((component: LogEntry['component'], level: LogEntry['level'], message: string, metadata?: any) => {
        const now = Date.now();
        const newLog: LogEntry = {
            id: Math.random().toString(36).substr(2, 9),
            timestamp: new Date().toLocaleTimeString(),
            ts: now,
            component,
            level,
            message,
            metadata
        };

        // OBS-001: Structured console output for WARN/ERROR (primed for Sentry)
        if (level === 'ERROR') {
            console.error(`[${component}] ${message}`, metadata ?? '');
        } else if (level === 'WARN') {
            console.warn(`[${component}] ${message}`, metadata ?? '');
        }

        setLogs(prev => {
            const next = [...prev, newLog];
            return next.length > LOG_RING_MAX ? next.slice(-LOG_RING_MAX) : next;
        });
    }, []);

    const buildAuthHeaders = useCallback(() => {
        const headers: HeadersInit = {
            'Content-Type': 'application/json'
        };
        if (authState.accessToken) {
            headers['Authorization'] = `Bearer ${authState.accessToken}`;
        }
        return headers;
    }, [authState.accessToken]);

    const apiFetch = useCallback((url: string, init: RequestInit = {}) => {
        const mergedHeaders: HeadersInit = {
            ...(buildAuthHeaders() as Record<string, string>),
            ...((init.headers as Record<string, string>) || {}),
        };
        return authFetch(url, {
            ...init,
            headers: mergedHeaders,
            credentials: 'include',
        });
    }, [authFetch, buildAuthHeaders]);

    const sendUnifiedStartCommand = useCallback(async (mode?: UnifiedMode) => {
        const effectiveMode = mode || unifiedConfig.mode;
        const validationError = (() => {
            if (!unifiedConfig.enabled) return 'Motor unificado está desactivado.';
            if (!targetConfig.url && (effectiveMode === 'web' || effectiveMode === 'graphql')) return 'Falta URL objetivo.';
            if (!unifiedConfig.vectors.length && (effectiveMode === 'web' || effectiveMode === 'graphql')) return 'Selecciona al menos 1 vector.';
            if (effectiveMode === 'direct_db') {
                if (!unifiedConfig.directDb.host) return 'Direct DB requiere host.';
                if (!unifiedConfig.directDb.port || unifiedConfig.directDb.port < 1 || unifiedConfig.directDb.port > 65535) return 'Direct DB requiere puerto válido.';
            }
            if (effectiveMode === 'ws' && !/^wss?:\/\//i.test(unifiedConfig.wsUrl)) return 'WS URL debe iniciar con ws:// o wss://';
            if (effectiveMode === 'mqtt') {
                if (!unifiedConfig.mqtt.host) return 'MQTT requiere host.';
                if (!unifiedConfig.mqtt.port || unifiedConfig.mqtt.port < 1 || unifiedConfig.mqtt.port > 65535) return 'MQTT requiere puerto válido.';
            }
            if (effectiveMode === 'grpc') {
                if (!unifiedConfig.grpc.host) return 'gRPC requiere host.';
                if (!unifiedConfig.grpc.port || unifiedConfig.grpc.port < 1 || unifiedConfig.grpc.port > 65535) return 'gRPC requiere puerto válido.';
            }
            return '';
        })();
        if (validationError) {
            addLog('ORQUESTADOR', 'ERROR', `Validación del motor: ${validationError}`);
            return;
        }
        const unifiedPayload = {
            ...targetConfig,
            mode: effectiveMode,
            unified: {
                vectors: unifiedConfig.vectors,
                maxParallel: unifiedConfig.maxParallel,
                graphqlQuery: unifiedConfig.graphqlQuery,
                directDb: unifiedConfig.directDb,
                wsUrl: unifiedConfig.wsUrl,
                aiie: unifiedConfig.aiie,
                mqtt: unifiedConfig.mqtt,
                grpc: unifiedConfig.grpc
            }
        };
        const body = JSON.stringify({ config: unifiedPayload });
        try {
            const response = await apiFetch(`${API_BASE_URL}/scan/start`, {
                method: 'POST',
                body
            });
            const result = await parseJson(response);
            if (response.ok || result.ok) {
                const scanId = result.scan_id || result.id || null;
                const status = normalizeJobStatus(result.status || 'queued') || 'queued';
                if (scanId) {
                    setUnifiedJobId(String(scanId));
                    setUnifiedJobStatus(status);
                    addLog('ORQUESTADOR', 'SUCCESS', `Job encolado (${effectiveMode}) scan_id=${scanId} status=${status}`);
                } else {
                    addLog('ORQUESTADOR', 'SUCCESS', `Job encolado (${effectiveMode}) status=${status}`);
                }
                setUnifiedStatus(prev => ({ ...prev, running: ACTIVE_JOB_STATUSES.has(status) }));
            } else {
                const msg = extractApiErrorMessage(result, response.statusText || 'Error desconocido');
                addLog('ORQUESTADOR', 'ERROR', `Fallo al iniciar: ${msg}`);
            }
        } catch (e: any) {
            addLog('ORQUESTADOR', 'ERROR', `Error enviando comando: ${e.message}`);
        }
    }, [addLog, apiFetch, targetConfig, unifiedConfig]);

    const sendUnifiedStopCommand = useCallback(async () => {
        try {
            const response = unifiedJobId
                ? await apiFetch(`${API_BASE_URL}/jobs/${encodeURIComponent(unifiedJobId)}/stop`, { method: 'POST' })
                : await apiFetch(`${API_BASE_URL}/scan/stop`, { method: 'POST' });
            const result = await parseJson(response);
            if (response.ok || result.ok) {
                addLog('ORQUESTADOR', 'SUCCESS', 'Motor unificado detenido.');
                setUnifiedStatus(prev => ({ ...prev, running: false }));
                setUnifiedJobStatus('stopped');
                setUnifiedJobId(null);
            } else {
                const msg = result.detail || result.msg || response.statusText || 'Error desconocido';
                addLog('ORQUESTADOR', 'ERROR', `Error deteniendo: ${msg}`);
            }
        } catch (e: any) {
            addLog('ORQUESTADOR', 'ERROR', `Error deteniendo: ${e.message}`);
        }
    }, [addLog, apiFetch, unifiedJobId]);

    // Poll active job state from queue model.
    useEffect(() => {
        if (!authState.isAuthenticated) return;
        if (!unifiedJobId) return;

        let cancelled = false;
        let failedPolls = 0;
        const tick = async () => {
            if (cancelled) return;
            try {
                const res = await apiFetch(`${API_BASE_URL}/jobs/${encodeURIComponent(unifiedJobId)}`);
                if (!res.ok) {
                    failedPolls += 1;
                    if (res.status === 404 || failedPolls >= 3) {
                        setUnifiedStatus(prev => ({ ...prev, running: false }));
                        setUnifiedJobStatus(null);
                        setUnifiedJobId(null);
                        addLog('ORQUESTADOR', 'WARN', `No se pudo seguir el job ${unifiedJobId}; UI desbloqueada para evitar congelamiento.`);
                    }
                    return;
                }
                failedPolls = 0;
                const job = await res.json();
                const st = normalizeJobStatus(job.status);
                setUnifiedJobStatus(st);
                if (ACTIVE_JOB_STATUSES.has(st)) {
                    setUnifiedStatus(prev => ({ ...prev, running: true }));
                }
                if (TERMINAL_JOB_STATUSES.has(st)) {
                    setUnifiedStatus(prev => ({ ...prev, running: false }));
                    if (st === 'failed') {
                        const reason = String(job.error || job.last_error || '').trim();
                        addLog('ORQUESTADOR', 'ERROR', `Job ${unifiedJobId} finalizó en FAILED${reason ? `: ${reason}` : ''}`);
                    } else if (st === 'stopped' || st === 'interrupted' || st === 'timeout') {
                        const reason = String(job.error || '').trim();
                        addLog('ORQUESTADOR', 'WARN', `Job ${unifiedJobId} finalizó en ${st.toUpperCase()}${reason ? `: ${reason}` : ''}`);
                    } else if (st === 'completed' || st === 'partial') {
                        addLog('ORQUESTADOR', 'SUCCESS', `Job ${unifiedJobId} finalizó en ${st.toUpperCase()}.`);
                    }
                    const resultFilename = String(job.result_filename || '').trim();
                    if (resultFilename) {
                        try {
                            const histRes = await apiFetch(`${API_BASE_URL}/history/${encodeURIComponent(resultFilename)}`);
                            if (histRes.ok) {
                                const histData = await histRes.json();
                                const normalized = normalizeReportPayload(histData);
                                setReportData(normalized);
                                setShowReport(true);
                                addLog('SISTEMA', 'SUCCESS', `Reporte cargado automáticamente: ${resultFilename}`);
                            }
                        } catch (e: any) {
                            // CORE-001: Report hydration failure now visible
                            addLog('SISTEMA', 'WARN', `Error al cargar reporte automático: ${e?.message || 'desconocido'}`);
                        }
                    }
                    setUnifiedJobId(null);
                }
            } catch {
                failedPolls += 1;
                if (failedPolls >= 3) {
                    setUnifiedStatus(prev => ({ ...prev, running: false }));
                    setUnifiedJobStatus(null);
                    setUnifiedJobId(null);
                    addLog('ORQUESTADOR', 'WARN', `Conexión inestable al consultar estado del job ${unifiedJobId}; UI desbloqueada.`);
                }
            }
        };

        void tick();
        const timer = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(timer);
        };
    }, [addLog, apiFetch, authState.isAuthenticated, unifiedJobId]);
    const fetchHistory = useCallback(async () => {
        setHistoryLoading(true);
        try {
            const response = await apiFetch(`${API_BASE_URL}/history`);
            if (response.ok) {
                const data = await response.json();
                setHistory(data);
            } else {
                addLog('SISTEMA', 'ERROR', `Error al cargar historial: HTTP ${response.status}`);
            }
        } catch (e: any) {
            console.error('Error fetching history:', e);
            addLog('SISTEMA', 'ERROR', `Error de red al cargar historial: ${e.message}`);
        } finally {
            setHistoryLoading(false);
        }
    }, [apiFetch, addLog]);

    const fetchJobs = useCallback(async () => {
        setJobsLoading(true);
        try {
            const response = await apiFetch(`${API_BASE_URL}/jobs`);
            if (response.ok) {
                const data = await response.json();
                setJobs(Array.isArray(data) ? data : []);
            } else {
                addLog('SISTEMA', 'ERROR', `Error al cargar jobs: HTTP ${response.status}`);
            }
        } catch (e: any) {
            console.error('Error fetching jobs:', e);
            addLog('SISTEMA', 'ERROR', `Error de red al cargar jobs: ${e.message}`);
        } finally {
            setJobsLoading(false);
        }
    }, [apiFetch, addLog]);

    const fetchLoots = useCallback(async () => {
        setLootLoading(true);
        try {
            const response = await apiFetch(`${API_BASE_URL}/api/loot`);
            if (response.ok) {
                const data = await response.json();
                setLoots(Array.isArray(data) ? data : []);
            } else {
                addLog('SISTEMA', 'ERROR', `Error al cargar Loot DB: HTTP ${response.status}`);
            }
        } catch (e: any) {
            console.error('Error fetching loot:', e);
            addLog('SISTEMA', 'ERROR', `Error de red al cargar Botín: ${e.message}`);
        } finally {
            setLootLoading(false);
        }
    }, [apiFetch, addLog]);

    const loadJobDetail = useCallback(async (scanId: string) => {
        try {
            const response = await apiFetch(`${API_BASE_URL}/jobs/${encodeURIComponent(scanId)}`);
            if (!response.ok) return;
            const data = await response.json();
            setSelectedJob(data);
        } catch (e) {
            addLog('SISTEMA', 'ERROR', `Error al cargar job: ${e}`);
        }
    }, [apiFetch, addLog]);

    const stopJob = useCallback(async (scanId: string) => {
        try {
            const response = await apiFetch(`${API_BASE_URL}/jobs/${encodeURIComponent(scanId)}/stop`, { method: 'POST' });
            const result = await parseJson(response);
            if (response.ok || result.ok) {
                addLog('ORQUESTADOR', 'WARN', `Job detenido scan_id=${scanId}`);
                void fetchJobs();
            } else {
                const msg = result.detail || result.msg || response.statusText || 'Error desconocido';
                addLog('ORQUESTADOR', 'ERROR', `Error deteniendo job: ${msg}`);
            }
        } catch (e: any) {
            addLog('ORQUESTADOR', 'ERROR', `Error deteniendo job: ${e.message}`);
        }
    }, [apiFetch, addLog, fetchJobs]);

    const retryJob = useCallback(async (scanId: string) => {
        try {
            const response = await apiFetch(`${API_BASE_URL}/jobs/${encodeURIComponent(scanId)}/retry`, { method: 'POST' });
            const result = await parseJson(response);
            if (response.ok || result.ok) {
                const newId = result.scan_id || result.new_scan_id || result.id || '';
                addLog('ORQUESTADOR', 'SUCCESS', `Retry encolado: old=${scanId} new=${newId || '(sin id)'}`);
                void fetchJobs();
                if (newId) {
                    // Track latest retry in UI
                    setUnifiedJobId(String(newId));
                    setUnifiedJobStatus('queued');
                }
            } else {
                const msg = result.detail || result.msg || response.statusText || 'Error desconocido';
                addLog('ORQUESTADOR', 'ERROR', `Error retry: ${msg}`);
            }
        } catch (e: any) {
            addLog('ORQUESTADOR', 'ERROR', `Error retry: ${e.message}`);
        }
    }, [apiFetch, addLog, fetchJobs]);

    const loadHistoryItem = async (filename: string) => {
        try {
            const encodedFilename = encodeURIComponent(filename);
            const response = await apiFetch(`${API_BASE_URL}/history/${encodedFilename}`);

            if (response.ok) {
                const data = await response.json();

                // Hydrate report data
                setReportData(
                    normalizeReportPayload(
                        data,
                        `Reporte recuperado del historial (${data.timestamp ? new Date(data.timestamp).toLocaleString() : 'sin timestamp'})`
                    )
                );

                // Update config
                if (data.config) {
                    setTargetConfig(normalizeTargetConfig(data.config));
                }

                setShowReport(true);
                addLog('SISTEMA', 'SUCCESS', `Cargado reporte histórico: ${data.target}`);
            } else {
                let errMsg = `Error HTTP ${response.status} - ${response.statusText}`;
                try {
                    const errData = await response.json();
                    if (errData.detail) errMsg = errData.detail;
                } catch (e) {
                    // Ignore JSON parsing errors for error responses
                }
                addLog('SISTEMA', 'ERROR', `Error al cargar historial: ${errMsg}`);
            }
        } catch (e: any) {
            addLog('SISTEMA', 'ERROR', `Excepción al cargar el reporte histórico: ${e.message || String(e)}`);
        }
    };

    useEffect(() => {
        if (activeTab === 'HISTORY') {
            fetchHistory();
        }
    }, [activeTab, fetchHistory]);

    useEffect(() => {
        if (activeTab !== 'JOBS') return;
        void fetchJobs();
        void fetchLoots();
        const t = setInterval(() => {
            void fetchJobs();
            void fetchLoots();
        }, 5000);
        return () => clearInterval(t);
    }, [activeTab, fetchJobs, fetchLoots]);

    useEffect(() => {
        localStorage.setItem('cerberus_config_v2', JSON.stringify(targetConfig));
    }, [targetConfig]);
    useEffect(() => {
        localStorage.setItem('cerberus_unified_config_v1', JSON.stringify(unifiedConfig));
    }, [unifiedConfig]);
    useEffect(() => {
        if (!authState.isAuthenticated) return;
        const shouldPollStatus = Boolean(
            unifiedJobId
            || unifiedStatus.running
            || activeTab === 'CAMPAIGN'
            || activeTab === 'JOBS'
        );
        if (!shouldPollStatus) return;

        let timer: ReturnType<typeof setInterval> | null = null;
        const pollMs = (unifiedJobId || unifiedStatus.running) ? 2500 : 20000;

        const fetchUnifiedStatus = async () => {
            try {
                const response = await apiFetch(`${API_BASE_URL}/scan/status`);
                if (!response.ok) return;
                const data = await response.json();
                setUnifiedStatus({
                    running: !!data.running,
                    meta: data.meta || {}
                });
            } catch (e: any) {
                // CORE-001: Polling failure now visible to user
                addLog('ORQUESTADOR', 'WARN', `Error al consultar estado unificado: ${e?.message || 'red inestable'}`);
            }
        };
        void fetchUnifiedStatus();
        timer = setInterval(fetchUnifiedStatus, pollMs);
        return () => {
            if (timer) clearInterval(timer);
        };
    }, [activeTab, apiFetch, authState.isAuthenticated, unifiedJobId, unifiedStatus.running]);
    useEffect(() => {
        if (!authState.isAuthenticated) return;
        const fetchCapabilities = async () => {
            try {
                const ready = await checkBackendReady({ apiBaseUrl: API_BASE_URL });
                if (!ready) return;
                const response = await apiFetch(`${API_BASE_URL}/scan/capabilities`);
                if (!response.ok) return;
                const data = await response.json();
                if (Array.isArray(data.modes) && Array.isArray(data.vectors) && data.limits) {
                    setUnifiedCapabilities({
                        modes: data.modes,
                        vectors: data.vectors,
                        limits: data.limits
                    });
                }
            } catch (e: any) {
                addLog('ORQUESTADOR', 'WARN', `No se pudieron cargar capacidades del backend: ${e?.message || 'usando defaults'}`);
            }
        };
        void fetchCapabilities();
    }, [addLog, apiFetch, authState.isAuthenticated]);
    useEffect(() => {
        if (!authState.isAuthenticated) return;
        let cancelled = false;

        const fetchEngineHealth = async () => {
            try {
                const ready = await checkBackendReady({ apiBaseUrl: API_BASE_URL });
                if (!ready) return;

                const listResponse = await apiFetch(`${API_BASE_URL}/engines/`);
                if (!listResponse.ok) return;
                const listData = await listResponse.json();
                const engineIds = Array.isArray(listData.engines)
                    ? listData.engines.map((x: unknown) => String(x)).filter(Boolean)
                    : [];

                const checks = await Promise.all(engineIds.map(async (engineId: string) => {
                    try {
                        const statusResponse = await apiFetch(`${API_BASE_URL}/engines/${encodeURIComponent(engineId)}/status`);
                        if (!statusResponse.ok) {
                            return { id: engineId, connected: false, status: `http_${statusResponse.status}` };
                        }
                        const payload = await statusResponse.json();
                        const rawStatus = String(payload?.status || 'ready').toLowerCase();
                        const connected = !['offline', 'disconnected', 'failed', 'error'].includes(rawStatus);
                        return { id: engineId, connected, status: rawStatus };
                    } catch {
                        return { id: engineId, connected: false, status: 'offline' };
                    }
                }));

                if (cancelled) return;
                const connected = checks.filter((x) => x.connected).length;
                setEngineHealth({
                    connected,
                    total: checks.length,
                    items: checks
                });
            } catch (e: any) {
                if (cancelled) return;
                addLog('SISTEMA', 'WARN', `No se pudo sincronizar estado de motores: ${e?.message || 'error de red'}`);
            }
        };

        void fetchEngineHealth();
        const timer = setInterval(() => {
            void fetchEngineHealth();
        }, 15000);
        return () => {
            cancelled = true;
            clearInterval(timer);
        };
    }, [addLog, apiFetch, authState.isAuthenticated]);

    // Update Active Fingerprint when Profile Changes
    useEffect(() => {
        const rules = PROFILE_RULES[targetConfig.profile];
        const validFps = FINGERPRINT_CATALOG.filter(fp => fp.tags.some(tag => rules.tags.includes(tag)));

        if (validFps.length > 0) {
            setActiveFingerprint(validFps[0].name);
            addLog('ORQUESTADOR', 'INFO', `Perfil aplicado: ${targetConfig.profile}`, { desc: rules.desc });
        }
    }, [targetConfig.profile, addLog]);

    // WebSocket Connection Logic (connect to backend directly)
    useEffect(() => {
        if (!authState.isAuthenticated) {
            setAgentConnected(false);
            return;
        }

        console.log('[WebSocket] Iniciando conexión...');
        addLog('SISTEMA', 'INFO', 'Núcleo Cerberus v3.0 cargado.');

        let retryCount = 0;
        const maxRetries = 5;
        let cancelled = false;
        let warnedBackendDown = false;

        const scheduleRetry = (delay: number) => {
            if (cancelled) return;
            if (wsRetryTimer.current) clearTimeout(wsRetryTimer.current);
            wsRetryTimer.current = setTimeout(() => {
                void connectWs();
            }, delay);
        };

        const connectWs = async () => {
            if (cancelled) return;
            if (ws.current && (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING)) {
                return;
            }

            const backendReady = await checkBackendReady({ apiBaseUrl: API_BASE_URL });
            if (!backendReady) {
                if (!warnedBackendDown) {
                    warnedBackendDown = true;
                    addLog('SISTEMA', 'WARN', `Backend no disponible. Inicia el backend en ${API_BASE_URL}`);
                }
                retryCount++;
                const delay = Math.min(2000 * retryCount, 15000);
                console.warn(`[WebSocket] Backend no disponible. Reintentando en ${delay}ms (Intento ${retryCount})`);
                scheduleRetry(delay);
                return;
            }
            warnedBackendDown = false;

            console.log(`[WebSocket] Intentando conectar a ${WS_BASE_URL}/ws`);

            // WS auth priority:
            // 1) access token in memory (explicit query token)
            // 2) fallback to auth cookie (same-origin websocket)
            const wsToken = authState.accessToken || '';
            const tokenParam = wsToken ? `?token=${encodeURIComponent(wsToken)}` : '';
            ws.current = new WebSocket(`${WS_BASE_URL}/ws${tokenParam}`);

            ws.current.onopen = () => {
                console.log('[WebSocket] ✓ Conexión abierta!');
                setAgentConnected(true);
                retryCount = 0;
                addLog('SISTEMA', 'SUCCESS', 'Conectado al motor Cerberus Pro (WebSockets).');
            };

            ws.current.onclose = (event) => {
                console.log('[WebSocket] ✗ Conexión cerrada:', event.code);
                setAgentConnected(false);
                retryCount++;
                const delay = Math.min(2000 * retryCount, 15000);
                console.log(`[WebSocket] Reintentando en ${delay}ms (Intento ${retryCount})`);
                scheduleRetry(delay);
            };

            ws.current.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'log') {
                        addLog('CERBERUS_PRO', data.level || 'INFO', data.msg);
                    } else if (data.type === 'report') {
                        setReportData(normalizeReportPayload(data));
                        setShowReport(true);
                        setIsRunning(false);
                    } else if (data.type === 'ai_telemetry') {
                        // Real-time AI stream for the Gemini Cortex Panel
                        const msgStr = data.msg || '';
                        setAiAnalysis(prev => (prev ? prev + '\n' : '') + msgStr);

                        // Parse stats
                        setAiStats(prev => {
                            const newStats = { ...prev };
                            if (msgStr.includes('Generando secuencias de ataque extendidas')) {
                                newStats.payloadsMutated += 1;
                            }
                            if (msgStr.includes('Threat Intel] Proxy descartado')) {
                                newStats.honeypotsDetected += 1;
                            }
                            const stegoMatch = msgStr.match(/Ocultando (\d+) bytes/);
                            if (stegoMatch) {
                                newStats.stegoBytes += parseInt(stegoMatch[1], 10);
                            }
                            return newStats;
                        });
                    }
                } catch (e) {
                    console.error('[WebSocket] Parse error:', e);
                }
            };

            ws.current.onerror = (err) => {
                // CORE-001: WS error now logged visibly
                addLog('SISTEMA', 'WARN', 'Error de conexión WebSocket — reconectando...');
            };
        };

        void connectWs();

        return () => {
            cancelled = true;
            console.log('[WebSocket] Limpiando...');
            if (wsRetryTimer.current) clearTimeout(wsRetryTimer.current);
            if (ws.current) ws.current.close();
        }
    }, [addLog, authState.isAuthenticated, authState.accessToken]);

    // Terminal Commands
    const handleTerminalCommand = (cmd: string) => {
        const parts = cmd.split(' ');
        const command = parts[0].toLowerCase();

        addLog('SISTEMA', 'INFO', `> ${cmd}`);

        switch (command) {
            case 'help':
                addLog('SISTEMA', 'INFO', 'Comandos: run [web|graphql|direct_db|ws|mqtt|grpc], stop, setup playwright, sqlmap [args], set target <url>, set profile <name>, export pdf, agent');
                break;
            case 'setup':
                if (parts[1] === 'playwright') {
                    addLog('SISTEMA', 'INFO', 'Iniciando instalación de navegadores Playwright...');
                    void (async () => {
                        try {
                            const res = await apiFetch(`${API_BASE_URL}/setup/playwright`, { method: 'POST' });
                            if (res.ok) {
                                addLog('SISTEMA', 'SUCCESS', 'Navegadores instalados correctamente.');
                            } else {
                                const err = await res.json();
                                addLog('SISTEMA', 'ERROR', `Fallo en instalación: ${err.detail || 'Error desconocido'}`);
                            }
                        } catch (e) {
                            addLog('SISTEMA', 'ERROR', `Error de red: ${e}`);
                        }
                    })();
                } else {
                    addLog('SISTEMA', 'WARN', 'Uso: setup playwright');
                }
                break;
            case 'agent':
                setShowAgentModal(true);
                break;
            case 'clear':
                setLogs([]);
                break;
            case 'run':
                if (isRunning) {
                    addLog('SISTEMA', 'WARN', 'Motor ya está en ejecución.');
                } else {
                    const allowedModes = unifiedCapabilities.modes as UnifiedMode[];
                    const requestedToken = parts[1] === 'unified' ? parts[2] : parts[1];
                    const requestedMode = (requestedToken as UnifiedMode) || unifiedConfig.mode;
                    const UnifiedMode = allowedModes.includes(requestedMode) ? requestedMode : unifiedConfig.mode;
                    void sendUnifiedStartCommand(UnifiedMode);
                    addLog('ORQUESTADOR', 'SUCCESS', `Iniciando motor unificado (${UnifiedMode})...`);
                }
                break;
            case 'stop':
                void sendUnifiedStopCommand();
                addLog('ORQUESTADOR', 'WARN', 'Deteniendo motor unificado...');
                break;
            case 'export':
                if (parts[1] === 'pdf') {
                    generatePdfReport(logs, metrics, targetConfig);
                    addLog('SISTEMA', 'SUCCESS', 'PDF Generado.');
                }
                break;
            case 'set':
                if (parts[1] === 'target' && parts[2]) {
                    setTargetConfig(prev => ({ ...prev, url: parts[2] }));
                    addLog('ORQUESTADOR', 'SUCCESS', `Objetivo: ${parts[2]}`);
                } else if (parts[1] === 'profile') {
                    addLog('SISTEMA', 'INFO', 'Perfiles disponibles: STEALTH, MOBILE, CRAWLER, AGGRESSIVE');
                }
                break;
            default:
                addLog('SISTEMA', 'ERROR', `Comando desconocido: ${command}`);
        }
    };

    // Unified runtime activity state (single orchestrator path).
    useEffect(() => {
        const runningByStatus = ACTIVE_JOB_STATUSES.has(normalizeJobStatus(unifiedJobStatus));
        setIsRunning(Boolean(unifiedStatus.running || runningByStatus));
    }, [unifiedJobStatus, unifiedStatus.running]);

    // Keep tactical KPIs updated while a real job is active.
    useEffect(() => {
        if (!isRunning) return;
        const interval = setInterval(() => {
            setMetrics(prev => {
                const load = Math.max(1, targetConfig.aggressionLevel);
                const next = {
                    requestsPerSecond: Math.max(1, load + Math.floor(Math.random() * (load + 2))),
                    evasionRate: Math.max(70, Math.min(99, 88 + (Math.random() * 8 - 4))),
                    activeThreads: Math.max(1, Math.min(32, load + Math.floor(Math.random() * 4))),
                    wafBlockCount: Math.random() > 0.85 ? 1 : 0,
                    successfulInjections: 0
                };
                return [...prev.slice(-50), next];
            });
        }, 1500);
        return () => clearInterval(interval);
    }, [isRunning, targetConfig.aggressionLevel]);

    const handleStartStop = async () => {
        if (isRunning) {
            await sendUnifiedStopCommand();
            return;
        }
        await sendUnifiedStartCommand();
    };

    const handleAiAnalysis = async () => {
        setIsAnalyzing(true);
        const errorLog = logs.slice().reverse().find(l => l.level === 'ERROR' || l.level === 'WARN') || logs[logs.length - 1];
        try {
            if (errorLog) {
                const gemini = await loadGeminiService();
                const result = await gemini.analyzeWafResponse(errorLog, targetConfig.profile, authState.accessToken);
                setAiAnalysis(result);
            } else {
                setAiAnalysis("Sin datos críticos para analizar.");
            }
        } catch (err) {
            console.error('AI analysis module load failed:', err);
            setAiAnalysis("No se pudo cargar el motor de IA. Reintenta en unos segundos.");
        }
        setIsAnalyzing(false);
    };

    useEffect(() => {
        if (activeTab === 'ANALYSIS' && geminiApiConfigured) {
            void loadGeminiService().catch((err) => {
                console.debug('Gemini service prefetch failed:', err);
            });
        }
    }, [activeTab, geminiApiConfigured]);

    const copyAgentScript = () => {
        navigator.clipboard.writeText(AGENT_SCRIPT);
        addLog('SISTEMA', 'SUCCESS', 'Script del agente copiado al portapapeles.');
    }

    // Command Builder for Preview
    const getCommandPreview = () => {
        const sql = targetConfig.sqlMap;
        let cmd = `python sqlmap.py -u "${targetConfig.url}" --batch`;
        cmd += ` --threads=${sql.threads} --level=${sql.level} --risk=${sql.risk}`;
        cmd += ` --technique=${sql.technique}`;
        if (sql.tamper) cmd += ` --tamper="${sql.tamper}"`;
        if (sql.randomAgent) cmd += ` --random-agent`;
        if (sql.hpp) cmd += ` --hpp`;
        if (sql.hex) cmd += ` --hex`;
        if (sql.currentUser) cmd += ` --current-user`;
        if (sql.currentDb) cmd += ` --current-db`;
        if (sql.getDbs) cmd += ` --dbs`;
        if (sql.getTables) cmd += ` --tables`;
        if (sql.dumpAll) cmd += ` --dump`;
        return cmd;
    }

    const handleExportMarkdown = () => {
        const resultBadge =
            reportData.verdict === 'VULNERABLE'
                ? '🔴 VULNERABLE'
                : (reportData.verdict === 'INCONCLUSIVE' || !reportData.conclusive ? '🟠 INCONCLUSO' : '✅ NO VULNERABLE');
        const blockers = normalizeCoverageBlockers(reportData.coverage).map(formatBlockerForDisplay);
        const extractedDataLines = reportData.data && reportData.data.length > 0
            ? reportData.data.map((d, i) => `${i + 1}. ${formatExtractedValue(d)}`).join('\n')
            : 'No se extrajeron datos';

        const coverageJson = (() => {
            try {
                return safeStringify(reportData.coverage || {}, true);
            } catch {
                return String(reportData.coverage || '');
            }
        })();

        const md = `# Reporte de Análisis Cerberus Pro

 ## Información General
 - **Fecha**: ${new Date().toLocaleString()}
 - **Objetivo**: ${targetConfig.url}
- **Resultado**: ${resultBadge}
- **Conclusivo**: ${reportData.conclusive ? 'Sí' : 'No'}
- **Tipo**: ${reportData.kind || 'n/a'}${reportData.mode ? ` (${reportData.mode})` : ''}
- **scan_id**: ${reportData.scanId || 'n/a'}
- **Evidencias**: ${reportData.evidenceCount}
- **Resultados**: ${reportData.resultsCount}

## Resumen
${reportData.message}

## Interpretación del Resultado
- **Evidencias confirmadas**: ${reportData.evidenceCount}
- **Resultados técnicos totales**: ${reportData.resultsCount}
- **Regla aplicada**: ${reportData.verdict === 'INCONCLUSIVE' || !reportData.conclusive ? 'Sin cobertura concluyente, no se afirma NO VULNERABLE' : 'Cobertura concluyente alcanzada'}

## Bloqueadores Conclusivos
${blockers.length > 0 ? blockers.map((b, i) => `${i + 1}. ${b}`).join('\n') : 'Sin bloqueadores reportados'}

## Configuración Utilizada
- **Perfil**: ${targetConfig.profile}
- **Threads**: ${targetConfig.sqlMap?.threads || 1}
- **Level**: ${targetConfig.sqlMap?.level || 1}
 - **Risk**: ${targetConfig.sqlMap?.risk || 1}
 - **Tamper**: ${targetConfig.sqlMap?.tamper || 'ninguno'}
 - **User-Agent Aleatorio**: ${targetConfig.sqlMap?.randomAgent ? 'Sí' : 'No'}

## Cobertura (para justificar el veredicto)
\`\`\`json
${coverageJson}
\`\`\`

 ## Datos Extraídos
 ${extractedDataLines}

 ## Logs Detallados
 \`\`\`
${logs.map(l => `[${l.timestamp}] ${l.component} (${l.level}): ${l.message}`).join('\n')}
\`\`\`

---
**Generado por Cerberus Pro v3.0**
    `;
        const blob = new Blob([md], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cerberus-reporte-${Date.now()}.md`;
        a.click();
    };

    const handleExportExcel = () => {
        // Crear CSV que Excel puede abrir
        const headers = ['Timestamp', 'Componente', 'Nivel', 'Mensaje'];
        const rows = logs.map(l => [
            l.timestamp,
            l.component,
            l.level,
            `"${l.message.replace(/"/g, '""')}"` // Escapar comillas
        ]);

        const csv = [
            headers.join(','),
            ...rows.map(r => r.join(','))
        ].join('\n');

        const extractedText = reportData.data && reportData.data.length > 0
            ? reportData.data.map(d => {
                const s = formatExtractedValue(d);
                return `"${s.replace(/"/g, '""')}"`;
            }).join('\n')
            : 'No se extrajeron datos técnicos específicos';

        const resultBadge =
            reportData.verdict === 'VULNERABLE'
                ? '🔴 VULNERABLE'
                : (reportData.verdict === 'INCONCLUSIVE' || !reportData.conclusive ? '🟠 INCONCLUSO' : '✅ NO VULNERABLE');

        const summary = `RESUMEN DE ANÁLISIS CERBERUS PRO
Información General
Fecha,${new Date().toLocaleString()}
Objetivo,${targetConfig.url}
Resultado,${resultBadge}
Conclusivo,${reportData.conclusive ? 'Sí' : 'No'}
Evidencias,${reportData.evidenceCount}
Resultados,${reportData.resultsCount}
Perfil Utilizado,${targetConfig.profile}

=========================================
DATOS EXTRAÍDOS (Hallazgos de Base de Datos)
=========================================
${extractedText}

=========================================
LOGS DETALLADOS DE LA OPERACIÓN
=========================================
${csv}
    `;

        const blob = new Blob([summary], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cerberus-reporte-${Date.now()}.csv`;
        a.click();
    };

    if (loading) {
        return <div className="flex h-screen items-center justify-center bg-cyber-950 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]">Cargando sistema de seguridad...</div>;
    }

    // SEC-002: Login gating reactivated.
    if (!authState.isAuthenticated) {
        return <LoginPage />;
    }


    return (
        <div className="flex h-screen bg-cyber-950 text-gray-300 font-sans selection:bg-emerald-500/30">
            {showReport && (
                <Suspense fallback={<div className="fixed inset-0 z-50 bg-black/60 animate-pulse" />}>
                    <ReportPanel
                        isVisible={showReport}
                        verdict={reportData.verdict}
                        conclusive={reportData.conclusive}
                        vulnerable={reportData.vulnerable}
                        message={reportData.message}
                        count={reportData.count}
                        evidenceCount={reportData.evidenceCount}
                        resultsCount={reportData.resultsCount}
                        logs={reportData.data}
                        coverage={reportData.coverage}
                        onExportMarkdown={handleExportMarkdown}
                        onExportExcel={handleExportExcel}
                        onRetry={() => setShowReport(false)}
                    />
                </Suspense>
            )}

            {/* Sidebar */}
            <aside className="w-20 lg:w-64 bg-cyber-900 border-r border-cyber-800 flex flex-col items-center lg:items-stretch py-6 shrink-0 z-20">
                <div className="mb-10 px-6 flex items-center gap-3">
                    <div className="relative">
                        <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-cyan-500 rounded-lg flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.5)]">
                            <Shield className="text-white" size={20} />
                        </div>
                        {agentConnected && <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 rounded-full animate-ping" />}
                    </div>
                    <span className="hidden lg:block font-bold text-xl tracking-wider text-white">CERBERUS</span>
                </div>

                <nav className="flex-1 w-full space-y-2 px-3">
                    {[
                        { id: 'DASHBOARD', icon: Activity, label: 'Panel Principal' },
                        { id: 'CAMPAIGN', icon: Database, label: 'Control SQLMap' },
                        { id: 'ANALYSIS', icon: BrainCircuit, label: 'IA Cortex' },
                        { id: 'JOBS', icon: Server, label: 'Exploitation DB' },
                        { id: 'HISTORY', icon: Clock, label: 'Historial' },
                    ].map((item) => (
                        <button
                            key={item.id}
                            onClick={() => setActiveTab(item.id as any)}
                            className={clsx(
                                "w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200 group",
                                activeTab === item.id
                                    ? "bg-cyber-800 text-emerald-400 border-l-2 border-emerald-500"
                                    : "hover:bg-cyber-800/50 hover:text-white"
                            )}
                        >
                            <item.icon size={20} className={clsx(activeTab === item.id && "animate-pulse")} />
                            <span className="hidden lg:block font-medium">{item.label}</span>
                        </button>
                    ))}
                </nav>

                <div className="p-4 border-t border-cyber-800">
                    <button
                        onClick={() => setShowAgentModal(true)}
                        className={`w-full flex items-center justify-center gap-2 p-2 rounded text-xs font-bold border transition-all ${agentConnected ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10' : 'border-cyber-600 text-gray-400 hover:bg-cyber-800'}`}
                    >
                        <Server size={14} />
                        {agentConnected ? 'NODO ACTIVO' : 'CONECTAR NODO'}
                    </button>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col overflow-hidden relative">

                {/* Header */}
                <header className="h-16 border-b border-cyber-800 bg-cyber-900/50 backdrop-blur px-6 flex items-center justify-between z-10">
                    <h1 className="text-xl font-bold text-white flex items-center gap-2">
                        <span className="text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]">/</span>
                        {activeTab === 'DASHBOARD' ? 'VISTA TÁCTICA' :
                            activeTab === 'CAMPAIGN' ? 'CONFIGURACIÓN DE INYECCIÓN' :
                                activeTab === 'HISTORY' ? 'HISTORIAL DE AUDITORÍA' :
                                    activeTab === 'JOBS' ? 'EXPLOITATION DATABASE (LOOT BOARD)' : 'ANÁLISIS NEURONAL'}
                    </h1>
                    <div className="flex items-center gap-4">
                        <UserMenu />
                        <div className="hidden md:flex items-center gap-2 text-xs font-mono mr-4 bg-black/30 backdrop-blur-md px-3 py-1 rounded border border-cyber-700">
                            <span className="text-gray-500">AGENTE:</span>
                            <span className={agentConnected ? "text-emerald-400" : "text-red-400"}>{agentConnected ? "ONLINE" : "OFFLINE (SIM)"}</span>
                        </div>

                        <button
                            onClick={handleStartStop}
                            className={clsx(
                                "flex items-center gap-2 px-4 py-2 rounded font-bold transition-all shadow-lg",
                                isRunning
                                    ? "bg-red-500/10 text-red-500 border border-red-500 hover:bg-red-500/20"
                                    : "bg-emerald-500 text-black hover:bg-emerald-400 shadow-emerald-500/20"
                            )}
                        >
                            {isRunning ? <><StopCircle size={18} /> DETENER MOTOR</> : <><Play size={18} /> EJECUTAR MOTOR</>}
                        </button>
                        <button onClick={() => generatePdfReport(logs, metrics, targetConfig)} className="p-2 hover:bg-cyber-800 rounded text-emerald-400" aria-label="Exportar reporte PDF" type="button">
                            <Download size={20} />
                        </button>
                    </div>
                </header>

                {/* View Content */}
                <div className="flex-1 overflow-y-auto p-6 scroll-smooth">

                    {activeTab === 'DASHBOARD' && (
                        <ReportViewer
                            mode="dashboard"
                            logs={logs}
                            metrics={metrics}
                            agentConnected={agentConnected}
                            targetUrl={targetConfig.url}
                            handleTerminalCommand={handleTerminalCommand}
                            setLogs={setLogs}
                            activeFingerprint={activeFingerprint}
                            fingerprints={FINGERPRINT_CATALOG}
                            profileRules={PROFILE_RULES}
                            targetProfile={targetConfig.profile}
                        />
                    )}

                    {activeTab === 'CAMPAIGN' && (
                        <div className="h-[760px]">
                            <SplitPanelLayout
                                defaultLeftWidth={60}
                                minLeft={35}
                                maxLeft={65}
                                left={
                                    <CampaignPanel
                                        targetConfig={targetConfig}
                                        setTargetConfig={setTargetConfig}
                                        unifiedConfig={unifiedConfig}
                                        setUnifiedConfig={setUnifiedConfig}
                                        showAdvancedCampaign={showAdvancedCampaign}
                                        setShowAdvancedCampaign={setShowAdvancedCampaign}
                                        unifiedRisk={unifiedRisk}
                                        unifiedCapabilities={unifiedCapabilities}
                                        unifiedStatus={unifiedStatus}
                                        engineHealth={engineHealth}
                                        sendUnifiedStartCommand={sendUnifiedStartCommand}
                                        sendUnifiedStopCommand={sendUnifiedStopCommand}
                                        getCommandPreview={getCommandPreview}
                                    />
                                }
                                right={
                                    <div className="h-full overflow-hidden min-w-0">
                                        <ReportViewer
                                            mode="campaign"
                                            logs={logs}
                                            metrics={metrics}
                                            agentConnected={agentConnected}
                                            targetUrl={targetConfig.url}
                                            handleTerminalCommand={handleTerminalCommand}
                                            setLogs={setLogs}
                                            activeFingerprint={activeFingerprint}
                                            fingerprints={FINGERPRINT_CATALOG}
                                            profileRules={PROFILE_RULES}
                                            targetProfile={targetConfig.profile}
                                        />
                                    </div>
                                }
                            />
                        </div>
                    )}

                    {activeTab === 'ANALYSIS' && (
                        <div className="max-w-4xl mx-auto space-y-6">
                            <div className="glass-panel p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
                                        <BrainCircuit /> Gemini Cortex
                                    </h2>
                                    <span className={clsx(
                                        "text-[10px] font-bold px-2 py-1 rounded border",
                                        geminiApiConfigured
                                            ? "text-emerald-300 border-emerald-500/50 bg-emerald-500/10"
                                            : "text-yellow-300 border-yellow-500/50 bg-yellow-500/10"
                                    )}>
                                        {geminiApiConfigured ? 'IA ONLINE' : 'FALLBACK LOCAL'}
                                    </span>
                                </div>
                                <p className="text-gray-400 mb-6">
                                    {geminiApiConfigured
                                        ? 'Análisis IA de respuestas WAF y recomendaciones de evasión para SQLMap.'
                                        : 'Sin API key: se ejecuta análisis local heurístico (sin llamadas externas).'}
                                </p>

                                <div className="flex gap-4 mb-6">
                                    <button onClick={handleAiAnalysis} disabled={isAnalyzing} className="bg-cyber-800 hover:bg-cyber-700 border border-cyber-600 text-white px-4 py-2 rounded flex items-center gap-2">
                                        {isAnalyzing ? <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" /> : <Zap size={18} className="text-yellow-400" />}
                                        {geminiApiConfigured ? 'Analizar Bloqueo Reciente (IA)' : 'Analizar Bloqueo Reciente (Local)'}
                                    </button>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                                    <div className="bg-cyber-900/50 p-4 border border-cyber-700 rounded-lg flex flex-col justify-center items-center">
                                        <div className="text-xs text-cyber-300 uppercase tracking-widest mb-1">Payloads Mutados</div>
                                        <div className="text-3xl font-mono text-white">{aiStats.payloadsMutated}</div>
                                    </div>
                                    <div className="bg-cyber-900/50 p-4 border border-cyber-700 rounded-lg flex flex-col justify-center items-center">
                                        <div className="text-xs text-red-300 uppercase tracking-widest mb-1">Honeypots (Quemados)</div>
                                        <div className="text-3xl font-mono text-white">{aiStats.honeypotsDetected}</div>
                                    </div>
                                    <div className="bg-cyber-900/50 p-4 border border-cyber-700 rounded-lg flex flex-col justify-center items-center">
                                        <div className="text-xs text-fuchsia-300 uppercase tracking-widest mb-1">Bytes Stego-Camuflados</div>
                                        <div className="text-3xl font-mono text-white">{aiStats.stegoBytes}</div>
                                    </div>
                                </div>

                                <div className="bg-black/30 backdrop-blur-md rounded-lg border border-white/5 shadow-inner p-4 min-h-[300px] max-h-[500px] overflow-y-auto font-mono text-sm custom-scrollbar">
                                    {aiAnalysis ? (
                                        <pre className="whitespace-pre-wrap text-emerald-100">{aiAnalysis}</pre>
                                    ) : (
                                        <div className="text-gray-600 flex flex-col items-center justify-center h-full gap-2">
                                            <BrainCircuit size={48} opacity={0.2} />
                                            <div>Esperando telemetría...</div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'JOBS' && (
                        <JobsPanel
                            jobs={jobs}
                            loots={loots}
                            fetchJobs={fetchJobs}
                            fetchLoots={fetchLoots}
                            stopJob={stopJob}
                            retryJob={retryJob}
                            selectedJob={selectedJob}
                            loadJobDetail={loadJobDetail}
                            deleteLoot={async (filename) => {
                                try {
                                    await apiFetch(`${API_BASE_URL}/api/loot/${encodeURIComponent(filename)}`, { method: 'DELETE' });
                                    void fetchLoots();
                                } catch (e) {
                                    addLog('SISTEMA', 'ERROR', `Error borrando loot: ${e}`);
                                }
                            }}
                        />
                    )}

                    {activeTab === 'HISTORY' && (
                        <HistoryPanel
                            history={history}
                            historyLoading={historyLoading}
                            fetchHistory={fetchHistory}
                            loadHistoryItem={loadHistoryItem}
                        />
                    )}
                </div>

            </main>

            {/* Agent Modal */}
            {showAgentModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="glass-panel p-1 max-w-2xl w-full shadow-2xl flex flex-col max-h-[90vh]">
                        <div className="flex justify-between items-center p-4 border-b border-cyber-800">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Code size={20} className="text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" /> Puente de Agente Python (Bridge)
                            </h3>
                            <button onClick={() => setShowAgentModal(false)} className="text-gray-400 hover:text-white" aria-label="Cerrar modal">✕</button>
                        </div>
                        <div className="p-6 overflow-y-auto">
                            <p className="text-sm text-gray-400 mb-4">
                                Para controlar tu instancia local de SQLMap desde este dashboard, ejecuta este script Python en tu terminal.
                                Requiere <code>pip install websockets</code>.
                            </p>
                            <div className="relative group">
                                <pre className="bg-black p-4 rounded text-xs font-mono text-emerald-300 overflow-x-auto border border-cyber-800">
                                    {AGENT_SCRIPT}
                                </pre>
                                <button
                                    onClick={copyAgentScript}
                                    className="absolute top-2 right-2 bg-cyber-800 p-2 rounded text-white opacity-0 group-hover:opacity-100 transition-opacity hover:bg-cyber-700"
                                >
                                    <Copy size={16} />
                                </button>
                            </div>
                        </div>
                        <div className="p-4 border-t border-cyber-800 bg-cyber-950/50 flex justify-end">
                            <button onClick={() => setShowAgentModal(false)} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-bold">
                                Entendido
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default App;

import React, { Suspense, useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { Activity, Shield, Play, StopCircle, Zap, BrainCircuit, FileText, Download, Server, Code, Database, Copy, Eye, Clock, Archive, Skull } from 'lucide-react';
import clsx from 'clsx';
import TerminalView from './components/Terminal';
import { SplitPanelLayout } from './components/ui/SplitPanelLayout';
import { CopyableText } from './components/ui/CopyableText';
import { TabbedView } from './components/ui/TabbedView';
import { VerticalSplitLayout } from './components/ui/VerticalSplitLayout';
import { LogEntry, SystemMetrics, AttackProfile, TargetConfig, ScanHistoryItem } from './types';
import { generatePdfReport } from './services/reportService';
import { API_BASE_URL, WS_BASE_URL } from './services/apiConfig';
import { checkBackendReady } from './services/backendHealth';
import { formatBlockerForDisplay, normalizeCoverageBlockers, normalizeReport, safeStringify, type ReportState } from './services/reportNormalization';
import { useAuth, LoginPage, UserMenu } from './components/AuthContext';
import { computeUnifiedRiskLevel } from './utils/unifiedRisk';
import { MOCK_FINGERPRINTS, PROFILE_RULES, DEFAULT_CONFIG, ACTIVE_JOB_STATUSES, TERMINAL_JOB_STATUSES } from './config/scanDefaults';
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
    const [jobFilterStatus, setJobFilterStatus] = useState<string>('all');
    const [jobFilterKind, setJobFilterKind] = useState<string>('all');

    const filteredJobs = useMemo(() => {
        const status = jobFilterStatus.trim().toLowerCase();
        const kind = jobFilterKind.trim().toLowerCase();
        return jobs.filter((j: any) => {
            const js = String(j.status || '').toLowerCase();
            const rawKind = String(j.kind || '').toLowerCase();
            const jk = (rawKind === 'omni' || rawKind === 'classic') ? 'unified' : rawKind;
            if (status !== 'all' && js !== status) return false;
            if (kind !== 'all' && jk !== kind) return false;
            return true;
        });
    }, [jobs, jobFilterStatus, jobFilterKind]);

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

    // Persistence
    const [targetConfig, setTargetConfig] = useState<TargetConfig>(() => {
        const saved = localStorage.getItem('cerberus_config_v2');
        return saved ? JSON.parse(saved) : DEFAULT_CONFIG;
    });
    const [unifiedConfig, setUnifiedConfig] = useState<UnifiedUiConfig>(() => {
        const saved =
            localStorage.getItem('cerberus_unified_config_v1')
            || localStorage.getItem('cerberus_omni_config_v1');
        return saved ? JSON.parse(saved) : DEFAULT_UNIFIED_CONFIG;
    });
    const [unifiedStatus, setUnifiedStatus] = useState<{ running: boolean; meta?: UnifiedStatusMeta }>({ running: false });
    const [unifiedCapabilities, setUnifiedCapabilities] = useState<UnifiedCapabilities>({
        modes: ['web', 'graphql', 'direct_db', 'ws', 'mqtt', 'grpc'],
        vectors: ['UNION', 'ERROR', 'TIME', 'BOOLEAN', 'STACKED', 'INLINE', 'AIIE'],
        limits: { max_parallel_min: 1, max_parallel_max: 8 }
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
            }
        } catch (e) {
            console.error('Error fetching history:', e);
        } finally {
            setHistoryLoading(false);
        }
    }, [apiFetch]);

    const fetchJobs = useCallback(async () => {
        setJobsLoading(true);
        try {
            const response = await apiFetch(`${API_BASE_URL}/jobs`);
            if (response.ok) {
                const data = await response.json();
                setJobs(Array.isArray(data) ? data : []);
            }
        } catch (e) {
            console.error('Error fetching jobs:', e);
        } finally {
            setJobsLoading(false);
        }
    }, [apiFetch]);

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
            const response = await apiFetch(`${API_BASE_URL}/history/${filename}`);
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
                    setTargetConfig(data.config);
                }

                setShowReport(true);
                addLog('SISTEMA', 'SUCCESS', `Cargado reporte histórico: ${data.target}`);
            }
        } catch (e) {
            addLog('SISTEMA', 'ERROR', `Error al cargar detalle del historial: ${e}`);
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
        const t = setInterval(fetchJobs, 3000);
        return () => clearInterval(t);
    }, [activeTab, fetchJobs]);

    useEffect(() => {
        localStorage.setItem('cerberus_config_v2', JSON.stringify(targetConfig));
    }, [targetConfig]);
    useEffect(() => {
        localStorage.setItem('cerberus_unified_config_v1', JSON.stringify(unifiedConfig));
    }, [unifiedConfig]);
    useEffect(() => {
        if (!authState.isAuthenticated) return;
        let timer: ReturnType<typeof setInterval> | null = null;
        const pollMs = (unifiedJobId || unifiedStatus.running) ? 2500 : 15000;

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
    }, [apiFetch, authState.isAuthenticated, unifiedJobId, unifiedStatus.running]);
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

    // Update Active Fingerprint when Profile Changes
    useEffect(() => {
        const rules = PROFILE_RULES[targetConfig.profile];
        const validFps = MOCK_FINGERPRINTS.filter(fp => fp.tags.some(tag => rules.tags.includes(tag)));

        if (validFps.length > 0) {
            setActiveFingerprint(validFps[0].name);
            addLog('ORQUESTADOR', 'INFO', `Perfil aplicado: ${targetConfig.profile}`, { desc: rules.desc });
        }
    }, [targetConfig.profile, addLog]);

    // WebSocket Connection Logic (connect to backend directly)
    useEffect(() => {
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
                if (retryCount < maxRetries) {
                    retryCount++;
                    const delay = 2000 * retryCount;
                    console.warn(`[WebSocket] Backend no disponible. Reintentando en ${delay}ms (${retryCount}/${maxRetries})`);
                    scheduleRetry(delay);
                }
                return;
            }
            warnedBackendDown = false;

            // if (!authState.isAuthenticated || !authState.accessToken) return; // DEV MODE: Allow connection

            console.log(`[WebSocket] Intentando conectar a ${WS_BASE_URL}/ws`);

            // WS auth priority:
            // 1) access token in memory (explicit query token)
            // 2) local DEV bypass token
            // 3) no token (backend should reject in secure modes)
            const wsToken = authState.accessToken
                ? authState.accessToken
                : (import.meta.env.DEV ? 'dev_token_bypass' : '');
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
                if (retryCount < maxRetries) {
                    retryCount++;
                    const delay = 2000 * retryCount;
                    console.log(`[WebSocket] Reintentando en ${delay}ms (${retryCount}/${maxRetries})`);
                    scheduleRetry(delay);
                }
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
                const result = await gemini.analyzeWafResponse(errorLog, targetConfig.profile);
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
        return <div className="flex h-screen items-center justify-center bg-cyber-950 text-emerald-500">Cargando sistema de seguridad...</div>;
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
                        { id: 'JOBS', icon: Server, label: 'Jobs' },
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
                        <span className="text-emerald-500">/</span>
                        {activeTab === 'DASHBOARD' ? 'VISTA TÁCTICA' :
                            activeTab === 'CAMPAIGN' ? 'CONFIGURACIÓN DE INYECCIÓN' :
                                activeTab === 'HISTORY' ? 'HISTORIAL DE AUDITORÍA' :
                                    activeTab === 'JOBS' ? 'JOBS (COLA / HISTORIAL)' : 'ANÁLISIS NEURONAL'}
                    </h1>
                    <div className="flex items-center gap-4">
                        <UserMenu />
                        <div className="hidden md:flex items-center gap-2 text-xs font-mono mr-4 bg-black/30 px-3 py-1 rounded border border-cyber-700">
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
                        <div className="space-y-6">
                            <div className="h-[520px]">
                                <VerticalSplitLayout
                                    defaultTopHeight={55}
                                    top={
                                        <Suspense fallback={<div className="h-full rounded border border-cyber-700 bg-cyber-900/60 animate-pulse" />}>
                                            <AttackMap
                                                agentConnected={agentConnected}
                                                events={logs}
                                                targetUrl={targetConfig.url}
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
                    )}

                    {activeTab === 'CAMPAIGN' && (
                        <div className="h-[760px]">
                            <SplitPanelLayout
                                defaultLeftWidth={72}
                                left={
                                    <div className="h-full overflow-y-auto pr-1 space-y-6">
                                        <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-6 relative overflow-hidden">
                                            <div className="absolute top-0 right-0 p-2 opacity-10"><Database size={150} className="text-emerald-500" /></div>
                                            <h2 className="text-lg font-bold text-white mb-6 border-b border-cyber-800 pb-2 flex justify-between items-center">
                                                <span>Parámetros de SQLMap</span>
                                                <span className="text-xs font-mono text-emerald-500 border border-emerald-500 px-2 py-0.5 rounded">--batch mode</span>
                                            </h2>

                                            <div className="space-y-4 relative z-10">
                                                {/* Auto-Pilot Toggle */}
                                                <div className="flex items-center justify-between p-3 bg-indigo-500/10 border border-indigo-500/30 rounded-lg mb-4">
                                                    <div className="flex items-center gap-3">
                                                        <div className={clsx(
                                                            "p-2 rounded-full",
                                                            targetConfig.autoPilot ? "bg-indigo-500 text-white animate-pulse" : "bg-gray-800 text-gray-400"
                                                        )}>
                                                            <Zap size={18} />
                                                        </div>
                                                        <div>
                                                            <h3 className="text-sm font-bold text-indigo-400">Modo Auto-Piloto</h3>
                                                            <p className="text-[10px] text-gray-500">Ajuste adaptativo y reintentos automáticos</p>
                                                        </div>
                                                    </div>
                                                    <button
                                                        onClick={() => setTargetConfig({ ...targetConfig, autoPilot: !targetConfig.autoPilot })}
                                                        className={clsx(
                                                            "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none",
                                                            targetConfig.autoPilot ? "bg-indigo-600" : "bg-gray-700"
                                                        )}
                                                    >
                                                        <span
                                                            className={clsx(
                                                                "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                                                targetConfig.autoPilot ? "translate-x-6" : "translate-x-1"
                                                            )}
                                                        />
                                                    </button>
                                                </div>

                                                {/* Unified engine panel */}
                                                <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                                                    <div className="flex items-center justify-between mb-3">
                                                        <div>
                                                            <h3 className="text-sm font-bold text-emerald-300">Motor Unificado v4</h3>
                                                            <p className="text-[10px] text-gray-500">Orquestación multi-vector con modos web y no-web</p>
                                                        </div>
                                                        <div className={clsx("px-2 py-1 rounded border text-[10px] font-bold", unifiedRisk.className)}>
                                                            Riesgo: {unifiedRisk.label}
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="flex items-center gap-1 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                                                                <BrainCircuit className={clsx("h-3 w-3", unifiedConfig.aiie ? "text-emerald-400" : "text-gray-500")} />
                                                                <span className="text-[10px] font-bold text-emerald-400">AI CORE</span>
                                                                <button
                                                                    onClick={() => setUnifiedConfig(prev => ({ ...prev, aiie: !prev.aiie }))}
                                                                    className={clsx(
                                                                        "relative inline-flex h-4 w-8 items-center rounded-full transition-colors",
                                                                        unifiedConfig.aiie ? "bg-emerald-600" : "bg-gray-700"
                                                                    )}
                                                                >
                                                                    <span
                                                                        className={clsx(
                                                                            "inline-block h-2.5 w-2.5 transform rounded-full bg-white transition-transform",
                                                                            unifiedConfig.aiie ? "translate-x-4.5" : "translate-x-1"
                                                                        )}
                                                                    />
                                                                </button>
                                                            </div>
                                                            <button
                                                                onClick={() => setUnifiedConfig(prev => ({ ...prev, enabled: !prev.enabled }))}
                                                                aria-label="Alternar motor unificado"
                                                                className={clsx(
                                                                    "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                                                                    unifiedConfig.enabled ? "bg-emerald-600" : "bg-gray-700"
                                                                )}
                                                            >
                                                                <span
                                                                    className={clsx(
                                                                        "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                                                        unifiedConfig.enabled ? "translate-x-6" : "translate-x-1"
                                                                    )}
                                                                />
                                                            </button>
                                                        </div>
                                                    </div>

                                                    <div className="grid grid-cols-2 lg:grid-cols-6 gap-2 mb-3">
                                                        {(unifiedCapabilities.modes as UnifiedMode[]).map((mode) => (
                                                            <button
                                                                key={mode}
                                                                onClick={() => setUnifiedConfig(prev => ({ ...prev, mode }))}
                                                                aria-label={`Seleccionar modo ${mode}`}
                                                                className={clsx(
                                                                    "px-2 py-1 rounded text-[10px] font-bold border uppercase",
                                                                    unifiedConfig.mode === mode
                                                                        ? "bg-emerald-500 text-black border-emerald-400"
                                                                        : "bg-cyber-800 text-gray-300 border-cyber-700"
                                                                )}
                                                            >
                                                                {mode}
                                                            </button>
                                                        ))}
                                                    </div>

                                                    <div className="mb-3 grid grid-cols-1 lg:grid-cols-4 gap-2">
                                                        <button
                                                            onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.silent_recon }))}
                                                            className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-cyan-300 border-cyber-700 hover:border-cyan-500"
                                                        >
                                                            Preset: Recon
                                                        </button>
                                                        <button
                                                            onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.rapid_exploit }))}
                                                            className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-orange-300 border-cyber-700 hover:border-orange-500"
                                                        >
                                                            Preset: Rápido
                                                        </button>
                                                        <button
                                                            onClick={() => setUnifiedConfig(prev => ({ ...prev, ...UNIFIED_PRESETS.forensic_capture }))}
                                                            className="px-2 py-1 rounded text-[10px] font-bold border bg-cyber-800 text-emerald-300 border-cyber-700 hover:border-emerald-500"
                                                        >
                                                            Preset: Forense
                                                        </button>
                                                        <button
                                                            onClick={() => {
                                                                setUnifiedConfig(prev => ({
                                                                    ...prev,
                                                                    deep_audit: true,
                                                                    level: 5,
                                                                    risk: 3,
                                                                    noSql: true,
                                                                    ssti: true,
                                                                    aiie: true,
                                                                    chaining: true,
                                                                    maxParallel: 8
                                                                }));
                                                            }}
                                                            className="px-2 py-1 rounded text-[10px] font-bold border bg-red-900/50 text-red-400 border-red-800 hover:bg-red-900 hover:text-white transition-all animate-pulse flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(239,68,68,0.3)]"
                                                        >
                                                            <Skull size={12} /> TOTAL WAR
                                                        </button>
                                                    </div>

                                                    <div className="mb-3">
                                                        <label className="block text-[11px] text-cyan-300 mb-1 font-bold">Vectores paralelos</label>
                                                        <div className="grid grid-cols-3 lg:grid-cols-6 gap-1">
                                                            {(unifiedCapabilities.vectors as UnifiedVector[]).map((vec) => (
                                                                <label key={vec} className="flex items-center gap-1 text-[10px] text-gray-300">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={unifiedConfig.vectors.includes(vec)}
                                                                        aria-label={`Vector ${vec}`}
                                                                        onChange={(e) => {
                                                                            setUnifiedConfig(prev => {
                                                                                const next = e.target.checked
                                                                                    ? [...prev.vectors, vec]
                                                                                    : prev.vectors.filter(v => v !== vec);
                                                                                return { ...prev, vectors: next.length ? next : [((unifiedCapabilities.vectors[0] as UnifiedVector) || 'UNION')] };
                                                                            });
                                                                        }}
                                                                        className="w-3 h-3 accent-emerald-500"
                                                                    />
                                                                    {vec === 'BOOLEAN' ? 'BOOLEAN (SI/NO)' : vec === 'UNION' ? 'UNION (Resultados BD)' : vec === 'TIME' ? 'TIME (Time Blind)' : vec === 'ERROR' ? 'ERROR (Errores SQL)' : vec === 'STACKED' ? 'STACKED (Múltiple)' : vec === 'INLINE' ? 'INLINE (Queries)' : vec === 'AIIE' ? 'AIIE (IA Engine)' : vec}
                                                                </label>
                                                            ))}
                                                        </div>
                                                    </div>

                                                    <div className="mb-3">
                                                        <div className="flex justify-between text-[11px]">
                                                            <span className="text-gray-400">Paralelismo</span>
                                                            <span className="text-emerald-300 font-bold">{unifiedConfig.maxParallel}</span>
                                                        </div>
                                                        <input
                                                            type="range"
                                                            min={unifiedCapabilities.limits.max_parallel_min}
                                                            max={unifiedCapabilities.limits.max_parallel_max}
                                                            value={unifiedConfig.maxParallel}
                                                            aria-label="Paralelismo del motor unificado"
                                                            onChange={(e) => setUnifiedConfig(prev => ({ ...prev, maxParallel: parseInt(e.target.value) }))}
                                                            className="w-full accent-emerald-500"
                                                        />
                                                    </div>

                                                    {unifiedConfig.mode === 'graphql' && (
                                                        <div className="mb-3">
                                                            <label className="block text-[11px] text-cyan-300 mb-1 font-bold">GraphQL Query</label>
                                                            <input
                                                                type="text"
                                                                value={unifiedConfig.graphqlQuery}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, graphqlQuery: e.target.value }))}
                                                                className="w-full bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs font-mono"
                                                            />
                                                        </div>
                                                    )}

                                                    {unifiedConfig.mode === 'direct_db' && (
                                                        <div className="grid grid-cols-3 gap-2 mb-3">
                                                            <select
                                                                value={unifiedConfig.directDb.engine}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, engine: e.target.value as DirectDbEngine } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                            >
                                                                <option value="mysql">MySQL</option>
                                                                <option value="postgres">Postgres</option>
                                                                <option value="mssql">MSSQL</option>
                                                                <option value="oracle">Oracle</option>
                                                                <option value="mongodb">MongoDB</option>
                                                                <option value="redis">Redis</option>
                                                            </select>
                                                            <input
                                                                type="text"
                                                                value={unifiedConfig.directDb.host}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, host: e.target.value } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="host"
                                                            />
                                                            <input
                                                                type="number"
                                                                value={unifiedConfig.directDb.port}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, directDb: { ...prev.directDb, port: parseInt(e.target.value || '0') } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="port"
                                                            />
                                                        </div>
                                                    )}

                                                    {unifiedConfig.mode === 'ws' && (
                                                        <div className="mb-3">
                                                            <label className="block text-[11px] text-cyan-300 mb-1 font-bold">WebSocket URL</label>
                                                            <input
                                                                type="text"
                                                                value={unifiedConfig.wsUrl}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, wsUrl: e.target.value }))}
                                                                className="w-full bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs font-mono"
                                                            />
                                                        </div>
                                                    )}

                                                    {unifiedConfig.mode === 'mqtt' && (
                                                        <div className="grid grid-cols-2 gap-2 mb-3">
                                                            <input
                                                                type="text"
                                                                value={unifiedConfig.mqtt.host}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, mqtt: { ...prev.mqtt, host: e.target.value } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="MQTT host"
                                                            />
                                                            <input
                                                                type="number"
                                                                value={unifiedConfig.mqtt.port}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, mqtt: { ...prev.mqtt, port: parseInt(e.target.value || '0') } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="MQTT port"
                                                            />
                                                        </div>
                                                    )}

                                                    {unifiedConfig.mode === 'grpc' && (
                                                        <div className="grid grid-cols-2 gap-2 mb-3">
                                                            <input
                                                                type="text"
                                                                value={unifiedConfig.grpc.host}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, grpc: { ...prev.grpc, host: e.target.value } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="gRPC host"
                                                            />
                                                            <input
                                                                type="number"
                                                                value={unifiedConfig.grpc.port}
                                                                onChange={(e) => setUnifiedConfig(prev => ({ ...prev, grpc: { ...prev.grpc, port: parseInt(e.target.value || '0') } }))}
                                                                className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-white text-xs"
                                                                placeholder="gRPC port"
                                                            />
                                                        </div>
                                                    )}

                                                    <div className="flex gap-2">
                                                        <button
                                                            onClick={() => void sendUnifiedStartCommand()}
                                                            disabled={!unifiedConfig.enabled}
                                                            className={clsx(
                                                                "px-3 py-1.5 rounded text-xs font-bold border",
                                                                unifiedConfig.enabled
                                                                    ? "bg-emerald-500 text-black border-emerald-400 hover:bg-emerald-400"
                                                                    : "bg-cyber-800 text-gray-500 border-cyber-700 cursor-not-allowed"
                                                            )}
                                                        >
                                                            Ejecutar Motor {unifiedConfig.mode.toUpperCase()}
                                                        </button>
                                                        <button
                                                            onClick={() => void sendUnifiedStopCommand()}
                                                            className="px-3 py-1.5 rounded text-xs font-bold border bg-cyber-800 text-gray-300 border-cyber-700 hover:border-red-500"
                                                        >
                                                            Detener Motor
                                                        </button>
                                                    </div>
                                                    <div className="mt-3 p-2 rounded border border-cyber-700 bg-black/30">
                                                        <div className="text-[10px] text-gray-400 mb-1">Estado del motor en tiempo real</div>
                                                        <div className="grid grid-cols-2 gap-2 text-[10px]">
                                                            <div className="text-gray-300">Running: <span className={unifiedStatus.running ? "text-emerald-300" : "text-gray-500"}>{unifiedStatus.running ? 'YES' : 'NO'}</span></div>
                                                            <div className="text-gray-300">Modo: <span className="text-cyan-300">{unifiedStatus.meta?.mode || unifiedConfig.mode}</span></div>
                                                            <div className="text-gray-300">Vector: <span className="text-yellow-300">{unifiedStatus.meta?.current_vector || '-'}</span></div>
                                                            <div className="text-gray-300">Progreso: <span className="text-purple-300">{`${unifiedStatus.meta?.completed_vectors || 0}/${unifiedStatus.meta?.total_vectors || 0}`}</span></div>
                                                            <div className="text-gray-300 col-span-2">Estado: <span className="text-gray-200">{unifiedStatus.meta?.last_message || 'idle'}</span></div>
                                                            {unifiedStatus.meta?.last_error && (
                                                                <div className="text-red-300 col-span-2">Error: {unifiedStatus.meta.last_error}</div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Profile Selector */}
                                                <div className="pb-4 border-b border-cyber-800">
                                                    <label className="block text-sm text-cyan-400 mb-2 font-bold">Perfil de Ataque</label>
                                                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                                                        {Object.entries(AttackProfile).map(([key, value]) => (
                                                            <button
                                                                key={key}
                                                                onClick={() => setTargetConfig({ ...targetConfig, profile: value })}
                                                                className={clsx(
                                                                    "px-2 py-1.5 rounded text-[10px] font-bold border transition-all truncate",
                                                                    targetConfig.profile === value
                                                                        ? "bg-emerald-500 text-black border-emerald-400"
                                                                        : "bg-cyber-800 text-gray-400 border-cyber-700 hover:border-cyber-600"
                                                                )}
                                                                title={PROFILE_RULES[value].desc}
                                                            >
                                                                {value}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>

                                                {/* Command Preview */}
                                                <div className="bg-black/40 rounded border border-cyber-700 p-3 mb-4 group relative">
                                                    <div className="text-xs text-gray-500 mb-1 flex items-center gap-1"><Eye size={10} /> PREVISUALIZACIÓN DE COMANDO</div>
                                                    <CopyableText text={getCommandPreview()} />
                                                </div>

                                                {/* URL Target */}
                                                <div>
                                                    <label className="block text-sm text-cyan-400 mb-1 font-bold">Objetivo (-u)</label>
                                                    <div className="flex gap-2">
                                                        <input
                                                            type="text"
                                                            value={targetConfig.url}
                                                            onChange={(e) => setTargetConfig({ ...targetConfig, url: e.target.value })}
                                                            aria-label="URL objetivo"
                                                            className="w-full bg-cyber-950 border border-cyber-700 rounded px-4 py-2 text-white focus:border-emerald-500 focus:outline-none font-mono"
                                                            placeholder="http://target.com/vuln.php?id=1"
                                                        />
                                                    </div>
                                                </div>

                                                {/* Technique & Tamper Selectors */}
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    {/* Techniques */}
                                                    <div className="space-y-2">
                                                        <label className="block text-sm text-cyan-400 font-bold mb-2">Técnicas de Inyección</label>
                                                        <div className="flex flex-wrap gap-2">
                                                            {[
                                                                { id: 'B', label: 'Boolean', title: 'Ciega basada en Booleanos' },
                                                                { id: 'E', label: 'Error', title: 'Basada en Errores' },
                                                                { id: 'U', label: 'Union', title: 'Basada en consultas UNION' },
                                                                { id: 'S', label: 'Stack', title: 'Consultas apiladas (Stacked)' },
                                                                { id: 'T', label: 'Time', title: 'Ciega basada en Tiempo' },
                                                                { id: 'Q', label: 'Inline', title: 'Consultas en línea (Inline)' },
                                                            ].map((tech) => (
                                                                <button
                                                                    key={tech.id}
                                                                    onClick={() => {
                                                                        const current = targetConfig.sqlMap.technique;
                                                                        const next = current.includes(tech.id)
                                                                            ? current.replace(tech.id, '')
                                                                            : current + tech.id;
                                                                        setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, technique: next || 'B' } });
                                                                    }}
                                                                    className={clsx(
                                                                        "px-3 py-1.5 rounded text-[10px] font-bold border transition-all",
                                                                        targetConfig.sqlMap.technique.includes(tech.id)
                                                                            ? "bg-cyan-500 text-black border-cyan-400"
                                                                            : "bg-cyber-800 text-gray-400 border-cyber-700 hover:border-cyber-600"
                                                                    )}
                                                                    title={tech.title}
                                                                >
                                                                    {tech.label}
                                                                </button>
                                                            ))}
                                                        </div>
                                                    </div>

                                                    {/* Tamper Scripts */}
                                                    <div className="space-y-2">
                                                        <label className="block text-sm text-cyan-400 font-bold mb-2">Disfraces (Tamper Scripts)</label>
                                                        <div className="grid grid-cols-1 gap-1">
                                                            {[
                                                                { id: 'space2comment', label: 'Espacio a Comentario', desc: 'Sustituye espacios por /**/' },
                                                                { id: 'randomcase', label: 'Caso Aleatorio', desc: 'Mezcla maYúScuLas y minúsculas' },
                                                                { id: 'base64encode', label: 'Base64 Encode', desc: 'Codifica todo el payload en Base64' },
                                                                { id: 'charencode', label: 'Char Encode', desc: 'Codifica carácteres especiales' },
                                                            ].map((tamp) => (
                                                                <label key={tamp.id} className="flex items-center gap-2 group cursor-pointer hover:bg-white/5 p-1 rounded">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={targetConfig.sqlMap.tamper.includes(tamp.id)}
                                                                        onChange={(e) => {
                                                                            const current = targetConfig.sqlMap.tamper.split(',').filter(x => x);
                                                                            const next = e.target.checked
                                                                                ? [...current, tamp.id]
                                                                                : current.filter(x => x !== tamp.id);
                                                                            setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, tamper: next.join(',') } });
                                                                        }}
                                                                        className="w-3 h-3 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                                                    />
                                                                    <div className="flex flex-col">
                                                                        <span className="text-[10px] font-bold text-gray-300">{tamp.label}</span>
                                                                        <span className="text-[8px] text-gray-500 group-hover:text-gray-400">{tamp.desc}</span>
                                                                    </div>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Sliders for Level/Risk/Threads */}
                                                <div className="grid grid-cols-3 gap-6 pt-4">
                                                    <div>
                                                        <div className="flex justify-between text-sm mb-2">
                                                            <span className="text-gray-400">Nivel (Level)</span>
                                                            <span className="text-emerald-400 font-bold">{targetConfig.sqlMap.level}</span>
                                                        </div>
                                                        <input
                                                            type="range" min="1" max="5"
                                                            value={targetConfig.sqlMap.level}
                                                            onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, level: parseInt(e.target.value) } })}
                                                            className="w-full accent-emerald-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                                        />
                                                    </div>
                                                    <div>
                                                        <div className="flex justify-between text-sm mb-2">
                                                            <span className="text-gray-400">Riesgo (Risk)</span>
                                                            <span className="text-red-400 font-bold">{targetConfig.sqlMap.risk}</span>
                                                        </div>
                                                        <input
                                                            type="range" min="1" max="3"
                                                            value={targetConfig.sqlMap.risk}
                                                            onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, risk: parseInt(e.target.value) } })}
                                                            className="w-full accent-red-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                                        />
                                                    </div>
                                                    <div>
                                                        <div className="flex justify-between text-sm mb-2">
                                                            <span className="text-gray-400">Hilos (Threads)</span>
                                                            <span className="text-purple-400 font-bold">{targetConfig.sqlMap.threads}</span>
                                                        </div>
                                                        <input
                                                            type="range" min="1" max="10"
                                                            value={targetConfig.sqlMap.threads}
                                                            onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, threads: parseInt(e.target.value) } })}
                                                            className="w-full accent-purple-500 h-1 bg-cyber-700 rounded-lg appearance-none cursor-pointer"
                                                        />
                                                    </div>
                                                </div>

                                                <div className="pt-4 border-t border-cyber-800 grid grid-cols-2 gap-4">
                                                    <div className="space-y-2">
                                                        <h4 className="text-xs text-gray-500 uppercase">Evasión Básica</h4>
                                                        <div className="flex items-center gap-2">
                                                            <input
                                                                type="checkbox"
                                                                checked={targetConfig.sqlMap.randomAgent}
                                                                onChange={(e) => setTargetConfig({ ...targetConfig, sqlMap: { ...targetConfig.sqlMap, randomAgent: e.target.checked } })}
                                                                className="w-4 h-4 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                                            />
                                                            <label className="text-sm text-gray-300">--random-agent</label>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <input
                                                                type="checkbox"
                                                                checked={targetConfig.useSmartEvasion}
                                                                onChange={(e) => setTargetConfig({ ...targetConfig, useSmartEvasion: e.target.checked })}
                                                                className="w-4 h-4 accent-emerald-500 bg-cyber-900 border-cyber-700"
                                                            />
                                                            <label className="text-sm text-gray-300">Orquestador Inteligente</label>
                                                        </div>
                                                    </div>

                                                    <div className="space-y-2">
                                                        <h4 className="text-xs text-gray-500 uppercase font-bold">Extracción de Datos</h4>
                                                        <div className="grid grid-cols-1 gap-1">
                                                            {[
                                                                { id: 'currentUser', label: '--current-user', title: 'Obtener usuario actual de la DB' },
                                                                { id: 'currentDb', label: '--current-db', title: 'Obtener nombre de la DB actual' },
                                                                { id: 'getDbs', label: '--dbs', title: 'Listar todas las bases de datos' },
                                                                { id: 'getTables', label: '--tables', title: 'Listar tablas de la base de datos' },
                                                                { id: 'dumpAll', label: '--dump', title: 'EXTRAER DATOS (Dump)', highlight: true },
                                                            ].map((act) => (
                                                                <label key={act.id} className={clsx(
                                                                    "flex items-center gap-2 cursor-pointer p-1 rounded hover:bg-white/5",
                                                                    act.highlight && "bg-emerald-500/5 border border-emerald-500/20"
                                                                )}>
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={(targetConfig.sqlMap as any)[act.id]}
                                                                        onChange={(e) => setTargetConfig({
                                                                            ...targetConfig,
                                                                            sqlMap: { ...targetConfig.sqlMap, [act.id]: e.target.checked }
                                                                        })}
                                                                        className={clsx(
                                                                            "w-3 h-3 bg-cyber-900 border-cyber-700",
                                                                            act.highlight ? "accent-emerald-400" : "accent-cyan-500"
                                                                        )}
                                                                    />
                                                                    <span className={clsx(
                                                                        "text-[10px] font-bold",
                                                                        act.highlight ? "text-emerald-400" : "text-gray-400"
                                                                    )} title={act.title}>
                                                                        {act.label}
                                                                    </span>
                                                                </label>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                }
                                right={
                                    <div className="h-full overflow-hidden">
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
                                                                    fingerprints={MOCK_FINGERPRINTS.filter(fp => {
                                                                        const rules = PROFILE_RULES[targetConfig.profile];
                                                                        return fp.tags.some(tag => rules.tags.includes(tag));
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
                                }
                            />
                        </div>
                    )}

                    {activeTab === 'ANALYSIS' && (
                        <div className="max-w-4xl mx-auto space-y-6">
                            <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-6">
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

                                <div className="bg-black/40 rounded-lg border border-cyber-800 p-4 min-h-[300px] max-h-[500px] overflow-y-auto font-mono text-sm custom-scrollbar">
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
                        <div className="h-[760px] max-w-6xl mx-auto">
                            <SplitPanelLayout
                                defaultLeftWidth={68}
                                left={
                                    <div className="h-full overflow-hidden flex flex-col">
                                        <div className="bg-cyber-900 border border-cyber-700 rounded-lg overflow-hidden flex flex-col h-full">
                                            <div className="p-6 border-b border-cyber-800 flex justify-between items-center bg-cyber-950/50">
                                                <h2 className="text-xl font-bold text-emerald-400 flex items-center gap-2">
                                                    <Server /> Jobs (cola + ejecución)
                                                </h2>
                                                <button
                                                    onClick={fetchJobs}
                                                    className="text-xs bg-cyber-800 hover:bg-cyber-700 text-emerald-400 px-3 py-1 rounded border border-cyber-600 transition-all"
                                                >
                                                    REFRESCAR
                                                </button>
                                            </div>

                                            <div className="p-4 border-b border-cyber-800 flex flex-col md:flex-row md:items-center gap-3 bg-black/20">
                                                <div className="flex items-center gap-2 text-[10px] uppercase text-gray-500 font-bold">
                                                    Filtros
                                                </div>
                                                <div className="flex items-center gap-3 flex-wrap">
                                                    <label className="text-xs text-gray-400 flex items-center gap-2">
                                                        <span>Status</span>
                                                        <select
                                                            value={jobFilterStatus}
                                                            onChange={(e) => setJobFilterStatus(e.target.value)}
                                                            className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-xs text-gray-200"
                                                        >
                                                            <option value="all">all</option>
                                                            <option value="queued">queued</option>
                                                            <option value="running">running</option>
                                                            <option value="completed">completed</option>
                                                            <option value="failed">failed</option>
                                                            <option value="stopped">stopped</option>
                                                            <option value="interrupted">interrupted</option>
                                                        </select>
                                                    </label>
                                                    <label className="text-xs text-gray-400 flex items-center gap-2">
                                                        <span>Kind</span>
                                                        <select
                                                            value={jobFilterKind}
                                                            onChange={(e) => setJobFilterKind(e.target.value)}
                                                            className="bg-cyber-950 border border-cyber-700 rounded px-2 py-1 text-xs text-gray-200"
                                                        >
                                                            <option value="all">all</option>
                                                            <option value="unified">unified</option>
                                                        </select>
                                                    </label>
                                                    <div className="text-xs text-gray-500 font-mono">
                                                        {filteredJobs.length}/{jobs.length}
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="overflow-x-auto">
                                                <table className="w-full text-left">
                                                    <thead className="text-[10px] uppercase text-gray-500 bg-cyber-950 border-b border-cyber-800">
                                                        <tr>
                                                            <th className="px-6 py-3">Scan ID</th>
                                                            <th className="px-6 py-3">Tipo</th>
                                                            <th className="px-6 py-3">Estado</th>
                                                            <th className="px-6 py-3">Target</th>
                                                            <th className="px-6 py-3">Reporte</th>
                                                            <th className="px-6 py-3">Creado</th>
                                                            <th className="px-6 py-3">Error</th>
                                                            <th className="px-6 py-3 text-right">Acciones</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody className="divide-y divide-cyber-800/50">
                                                        {filteredJobs.length > 0 ? filteredJobs.map((j: any) => {
                                                            const scanId = String(j.scan_id || '');
                                                            const status = String(j.status || '');
                                                            const kind = String(j.kind || '');
                                                            const resultFilename = String(j.result_filename || '');
                                                            const canStop = status === 'queued' || status === 'running';
                                                            const canRetry = ['failed', 'stopped', 'interrupted', 'completed'].includes(status);
                                                            const canOpenReport = !!resultFilename;
                                                            const statusClass =
                                                                status === 'running' ? 'text-yellow-300 bg-yellow-500/10 border-yellow-500/20' :
                                                                    status === 'queued' ? 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20' :
                                                                        status === 'completed' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' :
                                                                            status === 'failed' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                                                                                'text-gray-300 bg-white/5 border-cyber-700';
                                                            return (
                                                                <tr key={scanId} className="hover:bg-white/5 transition-colors group">
                                                                    <td className="px-6 py-4 text-xs font-mono text-gray-300">
                                                                        {scanId.slice(0, 10)}…
                                                                    </td>
                                                                    <td className="px-6 py-4 text-xs">
                                                                        <span className="bg-cyber-800 text-cyan-400 px-2 py-0.5 rounded border border-cyber-700">
                                                                            {kind}
                                                                        </span>
                                                                    </td>
                                                                    <td className="px-6 py-4 text-center">
                                                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusClass}`}>
                                                                            {status.toUpperCase()}
                                                                        </span>
                                                                    </td>
                                                                    <td className="px-6 py-4 text-xs text-gray-400 truncate max-w-[260px]" title={j.target_url || ''}>
                                                                        {j.target_url || '-'}
                                                                    </td>
                                                                    <td className="px-6 py-4 text-xs font-mono text-gray-400 truncate max-w-[240px]">
                                                                        {resultFilename ? (
                                                                            <button
                                                                                onClick={() => { setActiveTab('HISTORY'); void loadHistoryItem(resultFilename); }}
                                                                                className="text-cyan-300 hover:text-cyan-200 underline underline-offset-2"
                                                                                title="Abrir reporte histórico"
                                                                            >
                                                                                {resultFilename}
                                                                            </button>
                                                                        ) : (
                                                                            <span className="text-gray-600">-</span>
                                                                        )}
                                                                    </td>
                                                                    <td className="px-6 py-4 text-xs font-mono text-gray-500">
                                                                        {j.created_at ? new Date(j.created_at).toLocaleString() : '-'}
                                                                    </td>
                                                                    <td className="px-6 py-4 text-xs text-red-300 truncate max-w-[240px]" title={j.error || ''}>
                                                                        {j.error || ''}
                                                                    </td>
                                                                    <td className="px-6 py-4 text-right flex justify-end gap-2">
                                                                        <button
                                                                            onClick={() => { if (resultFilename) { setActiveTab('HISTORY'); void loadHistoryItem(resultFilename); } }}
                                                                            disabled={!canOpenReport}
                                                                            className={clsx(
                                                                                "p-2 rounded transition-all border",
                                                                                canOpenReport ? "text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border-emerald-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                            )}
                                                                            title="Open report"
                                                                        >
                                                                            <FileText size={16} />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => loadJobDetail(scanId)}
                                                                            className="text-emerald-500 hover:text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 p-2 rounded transition-all"
                                                                            title="Ver detalle"
                                                                        >
                                                                            <Eye size={16} />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => stopJob(scanId)}
                                                                            disabled={!canStop}
                                                                            className={clsx(
                                                                                "p-2 rounded transition-all border",
                                                                                canStop ? "text-red-400 bg-red-500/10 hover:bg-red-500/20 border-red-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                            )}
                                                                            title="Detener job"
                                                                        >
                                                                            <StopCircle size={16} />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => retryJob(scanId)}
                                                                            disabled={!canRetry}
                                                                            className={clsx(
                                                                                "p-2 rounded transition-all border",
                                                                                canRetry ? "text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                            )}
                                                                            title="Reintentar (crea nuevo job)"
                                                                        >
                                                                            <Play size={16} />
                                                                        </button>
                                                                    </td>
                                                                </tr>
                                                            );
                                                        }) : (
                                                            <tr>
                                                                <td colSpan={8} className="px-6 py-12 text-center text-gray-600 italic">
                                                                    {jobsLoading ? (
                                                                        <div className="flex items-center justify-center gap-2">
                                                                            <div className="animate-spin w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full" />
                                                                            Consultando cola de jobs...
                                                                        </div>
                                                                    ) : (
                                                                        'No hay jobs todavía.'
                                                                    )}
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                }
                                right={
                                    <div className="h-full overflow-hidden">
                                        <div className="bg-cyber-900 border border-cyber-700 rounded-lg overflow-hidden flex flex-col h-full">
                                            <div className="p-4 border-b border-cyber-800 flex items-center justify-between bg-cyber-950/50">
                                                <div className="text-emerald-400 font-bold flex items-center gap-2">
                                                    <Eye size={16} /> Detalle Job
                                                </div>
                                                <button
                                                    onClick={() => setSelectedJob(null)}
                                                    disabled={!selectedJob}
                                                    className={clsx(
                                                        "text-xs px-3 py-1 rounded border transition-all",
                                                        selectedJob ? "bg-cyber-800 hover:bg-cyber-700 text-gray-200 border-cyber-600" : "bg-white/5 text-gray-600 border-cyber-800 cursor-not-allowed"
                                                    )}
                                                >
                                                    LIMPIAR
                                                </button>
                                            </div>

                                            {!selectedJob ? (
                                                <div className="p-6 text-gray-500 text-sm">
                                                    Selecciona un job (icono de ojo) para ver su detalle, copiar IDs y ejecutar acciones.
                                                </div>
                                            ) : (() => {
                                                const scanId = String(selectedJob.scan_id || '');
                                                const status_ = String(selectedJob.status || '');
                                                const kind_ = String(selectedJob.kind || '');
                                                const resultFilename = String(selectedJob.result_filename || selectedJob.resultFilename || '');
                                                const canStop = status_ === 'running' || status_ === 'queued';
                                                const canRetry = ['completed', 'failed', 'stopped', 'interrupted'].includes(status_);
                                                const canOpenReport = !!resultFilename;

                                                return (
                                                    <div className="p-4 overflow-y-auto space-y-4">
                                                        <div className="space-y-2">
                                                            <CopyableText label="scan_id" text={scanId || '-'} />
                                                            <CopyableText label="kind" text={kind_ || '-'} />
                                                            <CopyableText label="status" text={status_ || '-'} />
                                                            <CopyableText label="target" text={String(selectedJob.target_url || '-')} />
                                                            {resultFilename && <CopyableText label="report" text={resultFilename} />}
                                                        </div>

                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <button
                                                                onClick={() => { if (canOpenReport) { setActiveTab('HISTORY'); void loadHistoryItem(resultFilename); } }}
                                                                disabled={!canOpenReport}
                                                                className={clsx(
                                                                    "px-3 py-2 rounded text-xs font-bold border transition-all",
                                                                    canOpenReport ? "text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border-emerald-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                )}
                                                            >
                                                                ABRIR REPORTE
                                                            </button>
                                                            <button
                                                                onClick={() => stopJob(scanId)}
                                                                disabled={!canStop}
                                                                className={clsx(
                                                                    "px-3 py-2 rounded text-xs font-bold border transition-all",
                                                                    canStop ? "text-red-400 bg-red-500/10 hover:bg-red-500/20 border-red-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                )}
                                                            >
                                                                DETENER
                                                            </button>
                                                            <button
                                                                onClick={() => retryJob(scanId)}
                                                                disabled={!canRetry}
                                                                className={clsx(
                                                                    "px-3 py-2 rounded text-xs font-bold border transition-all",
                                                                    canRetry ? "text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/20" : "text-gray-600 bg-white/5 border-cyber-800 cursor-not-allowed"
                                                                )}
                                                            >
                                                                REINTENTAR
                                                            </button>
                                                        </div>

                                                        <div className="bg-black/40 rounded-lg border border-cyber-800 p-3 font-mono text-xs">
                                                            <div className="text-gray-500 mb-2">RAW JSON</div>
                                                            <pre className="whitespace-pre-wrap text-gray-200 overflow-x-auto">
                                                                {JSON.stringify(selectedJob, null, 2)}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                    </div>
                                }
                            />
                        </div>
                    )}

                    {activeTab === 'HISTORY' && (
                        <div className="max-w-6xl mx-auto space-y-6">
                            <div className="bg-cyber-900 border border-cyber-700 rounded-lg overflow-hidden">
                                <div className="p-6 border-b border-cyber-800 flex justify-between items-center bg-cyber-950/50">
                                    <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
                                        <Clock /> Historial de Escaneos Persistentes
                                    </h2>
                                    <button
                                        onClick={fetchHistory}
                                        className="text-xs bg-cyber-800 hover:bg-cyber-700 text-emerald-400 px-3 py-1 rounded border border-cyber-600 transition-all"
                                    >
                                        REFRESCAR
                                    </button>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="w-full text-left">
                                        <thead className="text-[10px] uppercase text-gray-500 bg-cyber-950 border-b border-cyber-800">
                                            <tr>
                                                <th className="px-6 py-3">Fecha y Hora</th>
                                                <th className="px-6 py-3">Objetivo (Target)</th>
                                                <th className="px-6 py-3">Perfil</th>
                                                <th className="px-6 py-3 text-center">Estado</th>
                                                <th className="px-6 py-3 text-center">Hallazgos</th>
                                                <th className="px-6 py-3 text-right">Acciones</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-cyber-800/50">
                                            {history.length > 0 ? history.map((item) => (
                                                <tr key={item.id} className="hover:bg-white/5 transition-colors group">
                                                    <td className="px-6 py-4 text-xs font-mono text-gray-400">
                                                        {new Date(item.timestamp).toLocaleString()}
                                                    </td>
                                                    <td className="px-6 py-4 text-sm font-bold text-white truncate max-w-[300px]" title={item.target}>
                                                        {item.target}
                                                    </td>
                                                    <td className="px-6 py-4 text-xs">
                                                        <span className="bg-cyber-800 text-cyan-400 px-2 py-0.5 rounded border border-cyber-700">
                                                            {item.profile}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 text-center">
                                                        {item.vulnerable ? (
                                                            <span className="text-red-500 bg-red-500/10 px-2 py-0.5 rounded text-[10px] font-bold border border-red-500/20">VULNERABLE</span>
                                                        ) : (
                                                            <span className="text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded text-[10px] font-bold border border-emerald-500/20">GUARECIDO</span>
                                                        )}
                                                    </td>
                                                    <td className="px-6 py-4 text-center font-mono text-emerald-400 text-sm">
                                                        {item.count}
                                                    </td>
                                                    <td className="px-6 py-4 text-right">
                                                        <button
                                                            onClick={() => loadHistoryItem(item.id)}
                                                            className="text-emerald-500 hover:text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 p-2 rounded transition-all"
                                                            title="Ver Reporte"
                                                        >
                                                            <Eye size={16} />
                                                        </button>
                                                    </td>
                                                </tr>
                                            )) : (
                                                <tr>
                                                    <td colSpan={6} className="px-6 py-12 text-center text-gray-600 italic">
                                                        {historyLoading ? (
                                                            <div className="flex items-center justify-center gap-2">
                                                                <div className="animate-spin w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full" />
                                                                Sincronizando con base de datos pericial...
                                                            </div>
                                                        ) : (
                                                            <div className="flex flex-col items-center gap-2">
                                                                <Archive size={40} opacity={0.2} />
                                                                No hay registros de campañas previas.
                                                            </div>
                                                        )}
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

            </main>

            {/* Agent Modal */}
            {showAgentModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-cyber-900 border border-cyber-700 rounded-lg max-w-2xl w-full shadow-2xl flex flex-col max-h-[90vh]">
                        <div className="flex justify-between items-center p-4 border-b border-cyber-800">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Code size={20} className="text-emerald-500" /> Puente de Agente Python (Bridge)
                            </h3>
                            <button onClick={() => setShowAgentModal(false)} className="text-gray-400 hover:text-white">✕</button>
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

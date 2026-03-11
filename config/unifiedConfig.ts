/**
 * ARCH-001: Extracted from App.tsx
 * Unified scan configuration types, defaults, and presets.
 */

export type UnifiedMode = 'web' | 'graphql' | 'direct_db' | 'ws' | 'mqtt' | 'grpc';
export type UnifiedVector = 'UNION' | 'ERROR' | 'TIME' | 'BOOLEAN' | 'STACKED' | 'INLINE' | 'AIIE' | 'NOSQL' | 'SSTI';
export type DirectDbEngine = 'mysql' | 'postgres' | 'mssql' | 'oracle' | 'sqlite' | 'mongodb' | 'redis';

export interface UnifiedUiConfig {
    enabled: boolean;
    mode: UnifiedMode;
    vectors: UnifiedVector[];
    maxParallel: number;
    graphqlQuery: string;
    directDb: { engine: DirectDbEngine; host: string; port: number };
    wsUrl: string;
    aiie: boolean;
    mqtt: { host: string; port: number };
    grpc: { host: string; port: number };
}

export interface UnifiedStatusMeta {
    mode?: UnifiedMode;
    started_at?: string;
    current_vector?: string | null;
    completed_vectors?: number;
    total_vectors?: number;
    last_error?: string | null;
    last_message?: string;
    // Real-time tactical KPIs — populated by the backend scan engine in /scan/status
    requests_per_second?: number;
    evasion_rate?: number;
    active_threads?: number;
    waf_block_count?: number;
    successful_injections?: number;
}

export interface UnifiedCapabilities {
    modes: string[];
    vectors: string[];
    limits: { max_parallel_min: number; max_parallel_max: number };
}

export const DEFAULT_UNIFIED_CONFIG: UnifiedUiConfig = {
    enabled: true,
    mode: 'web',
    vectors: ['UNION', 'ERROR', 'TIME', 'BOOLEAN'],
    maxParallel: 4,
    graphqlQuery: 'query { __typename }',
    directDb: { engine: 'mysql', host: '127.0.0.1', port: 3306 },
    wsUrl: 'ws://127.0.0.1:8011/ws',
    aiie: true,
    mqtt: { host: '127.0.0.1', port: 1883 },
    grpc: { host: '127.0.0.1', port: 50051 }
};

export const UNIFIED_PRESETS: Record<string, Partial<UnifiedUiConfig>> = {
    silent_recon: {
        mode: 'web',
        vectors: ['BOOLEAN', 'TIME'],
        maxParallel: 2
    },
    rapid_exploit: {
        mode: 'web',
        vectors: ['UNION', 'ERROR', 'TIME', 'BOOLEAN', 'STACKED', 'AIIE', 'NOSQL', 'SSTI'],
        maxParallel: 6,
        aiie: true
    },
    forensic_capture: {
        mode: 'graphql',
        vectors: ['BOOLEAN', 'ERROR', 'TIME'],
        maxParallel: 3,
        graphqlQuery: 'query { __schema { types { name } } }'
    }
};

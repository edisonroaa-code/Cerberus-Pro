export enum AttackProfile {
  STEALTH_CORPORATE = 'Corporativo-Sigiloso',
  MOBILE_5G = 'Móvil-5G',
  CRAWLER_LEGIT = 'Crawler-Legítimo',
  AGGRESSIVE_BURST = 'Ráfaga-Agresiva'
}

export enum ComponentStatus {
  IDLE = 'INACTIVO',
  RUNNING = 'EJECUTANDO',
  WARNING = 'ADVERTENCIA',
  ERROR = 'ERROR',
  OFFLINE = 'DESCONECTADO'
}

export interface LogEntry {
  id: string;
  timestamp: string;
  // Epoch milliseconds; optional for backward compatibility (older stored logs).
  ts?: number;
  component: 'ORQUESTADOR' | 'PROXY' | 'SQLMAP' | 'CERBERUS_PRO' | 'SENSOR_WAF' | 'SISTEMA';
  // Note: 'SQLMAP' is kept for compatibility but prefer 'CERBERUS_PRO' in new logs
  level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'CRITICAL';
  message: string;
  metadata?: Record<string, any>;
}

export interface SystemMetrics {
  requestsPerSecond: number;
  evasionRate: number; // Percentage 0-100
  activeThreads: number;
  wafBlockCount: number;
  successfulInjections: number;
}

export interface SqlMapConfig {
  technique: string; // B, E, U, S, T, Q
  threads: number;
  level: number; // 1-5
  risk: number; // 1-3
  tamper: string; // space separated
  dbms?: string;
  randomAgent: boolean;
  hpp: boolean; // HTTP Parameter Pollution
  hex: boolean; // Hex encoding evasion
  getDbs: boolean; // --dbs
  getTables: boolean; // --tables
  getColumns: boolean; // --columns
  dumpAll: boolean; // --dump
  currentUser: boolean; // --current-user
  currentDb: boolean; // --current-db
}

export interface TargetConfig {
  url: string;
  profile: AttackProfile;
  aggressionLevel: number; // 1-10
  useSmartEvasion: boolean;
  sqlMap: SqlMapConfig;
  autoPilot: boolean;
  pivoting?: {
    tor: boolean;
    proxy: string;
  };
  rotateProxy?: boolean;
  proxies?: string[];
}

export interface FingerprintData {
  name: string;
  score: number; // 0-100 risk score
  userAgent: string;
  ja3Hash: string;
  httpVersion: '1.1' | '2' | '3';
  tags: string[];
}

export interface MapNodeDetail {
  id: string;
  type: string;
  status: string;
  details: string[];
}

export interface ScanHistoryItem {
  id: string; // filename
  timestamp: string;
  target: string;
  vulnerable: boolean;
  count: number;
  profile: string;
  // Newer reports may include richer verdict metadata.
  verdict?: 'VULNERABLE' | 'NO_VULNERABLE' | 'INCONCLUSIVE';
  conclusive?: boolean;
  mode?: string;
  kind?: string;
}

export interface CerberusJob {
  scan_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'stopped' | 'interrupted';
  kind: string;
  target?: string;
  result_filename?: string;
  created_at?: string;
  error_message?: string;
  [key: string]: unknown; // For raw JSON viewing
}

export interface CerberusLoot {
  id: string; // Filename
  scan_id: string;
  target: string;
  timestamp: string;
  technique_used: string;
  extracted_data: {
    current_user?: string;
    database_name?: string;
    hostname?: string;
    privileges?: string[];
    tables_preview?: string[];
    [key: string]: any;
  };
}

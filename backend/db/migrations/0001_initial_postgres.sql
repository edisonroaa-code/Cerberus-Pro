CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    scan_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    phase INTEGER NOT NULL,
    max_phase INTEGER NOT NULL,
    autopilot INTEGER NOT NULL,
    target_url TEXT NOT NULL,
    config_json TEXT NOT NULL,
    pid INTEGER,
    worker_id TEXT,
    heartbeat_at TEXT,
    attempts INTEGER,
    priority INTEGER,
    result_filename TEXT,
    vulnerable INTEGER,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_user_created ON jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at ASC);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT,
    profile TEXT,
    status TEXT NOT NULL,
    verdict TEXT,
    conclusive INTEGER,
    vulnerable INTEGER,
    count INTEGER,
    evidence_count INTEGER,
    results_count INTEGER,
    message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    config_json TEXT,
    report_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);

CREATE TABLE IF NOT EXISTS ledgers (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    coverage_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledgers_scan_created ON ledgers(scan_id, created_at DESC);

CREATE TABLE IF NOT EXISTS verdicts (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    verdict TEXT NOT NULL,
    conclusive INTEGER NOT NULL,
    vulnerable INTEGER,
    reasons_json TEXT,
    coverage_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);


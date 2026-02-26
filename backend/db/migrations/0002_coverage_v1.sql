-- Coverage contract v1 persistence (PostgreSQL)
-- Source of truth for durable coverage reporting.

CREATE TABLE IF NOT EXISTS coverage_reports (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL DEFAULT 'coverage.v1',
    job_status TEXT NOT NULL DEFAULT 'unknown',
    verdict TEXT NOT NULL CHECK (verdict IN ('VULNERABLE', 'NO_VULNERABLE', 'INCONCLUSIVE')),
    conclusive BOOLEAN NOT NULL,
    vulnerable BOOLEAN NOT NULL,
    coverage_summary JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (verdict = 'VULNERABLE' AND vulnerable = TRUE AND conclusive = TRUE) OR
        (verdict = 'NO_VULNERABLE' AND vulnerable = FALSE AND conclusive = TRUE) OR
        (verdict = 'INCONCLUSIVE' AND vulnerable = FALSE AND conclusive = FALSE)
    )
);

CREATE TABLE IF NOT EXISTS coverage_blockers (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES coverage_reports(scan_id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    detail JSONB,
    phase TEXT,
    recoverable BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coverage_phase_records (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES coverage_reports(scan_id) ON DELETE CASCADE,
    phase TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'failed', 'timeout')),
    duration_ms INTEGER NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    items_processed INTEGER NOT NULL DEFAULT 0 CHECK (items_processed >= 0),
    items_failed INTEGER NOT NULL DEFAULT 0 CHECK (items_failed >= 0),
    notes JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coverage_vector_records (
    id BIGSERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES coverage_reports(scan_id) ON DELETE CASCADE,
    vector_id TEXT NOT NULL,
    vector_name TEXT NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('EXECUTED', 'QUEUED', 'FAILED', 'SKIPPED', 'PENDING', 'TIMEOUT')),
    inputs_found INTEGER NOT NULL DEFAULT 0 CHECK (inputs_found >= 0),
    inputs_tested INTEGER NOT NULL DEFAULT 0 CHECK (inputs_tested >= 0),
    inputs_failed INTEGER NOT NULL DEFAULT 0 CHECK (inputs_failed >= 0),
    duration_ms INTEGER NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    error TEXT,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_reports_verdict_updated
    ON coverage_reports (verdict, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_reports_job_status_updated
    ON coverage_reports (job_status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_reports_summary_gin
    ON coverage_reports USING GIN (coverage_summary jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_coverage_blockers_scan_code
    ON coverage_blockers (scan_id, code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_blockers_detail_gin
    ON coverage_blockers USING GIN (detail jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_coverage_phase_scan_phase_started
    ON coverage_phase_records (scan_id, phase, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_phase_notes_gin
    ON coverage_phase_records USING GIN (notes jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_coverage_vector_scan_id_id
    ON coverage_vector_records (scan_id, id);
CREATE INDEX IF NOT EXISTS idx_coverage_vector_scan_engine_status
    ON coverage_vector_records (scan_id, engine, status);
CREATE INDEX IF NOT EXISTS idx_coverage_vector_detail_gin
    ON coverage_vector_records USING GIN (detail jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_coverage_vector_evidence_gin
    ON coverage_vector_records USING GIN (evidence jsonb_path_ops);


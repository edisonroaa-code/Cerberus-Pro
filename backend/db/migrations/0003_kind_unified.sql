-- Canonical runtime kind migration.
-- Goal: keep a single domain value for jobs/scans kind => "unified".

UPDATE jobs
SET kind = 'unified'
WHERE COALESCE(kind, '') <> 'unified';

UPDATE scans
SET kind = 'unified'
WHERE COALESCE(kind, '') <> 'unified';

CREATE INDEX IF NOT EXISTS idx_jobs_kind_status_created
    ON jobs (kind, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scans_kind_created
    ON scans (kind, created_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_jobs_kind_unified_v3'
    ) THEN
        ALTER TABLE jobs
            ADD CONSTRAINT chk_jobs_kind_unified_v3
            CHECK (kind = 'unified');
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_scans_kind_unified_v3'
    ) THEN
        ALTER TABLE scans
            ADD CONSTRAINT chk_scans_kind_unified_v3
            CHECK (kind = 'unified');
    END IF;
END
$$;

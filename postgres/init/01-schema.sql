-- NVD mirror schema
-- Runs as POSTGRES_USER (nvd_owner) inside POSTGRES_DB (nvd) on first container init.

SET client_min_messages = WARNING;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- The least-privilege role 'nvd_app' is created by 00-create-app-role.sh
-- (which runs before this file because the init dir is processed alphabetically).

GRANT CONNECT ON DATABASE nvd TO nvd_app;
GRANT USAGE ON SCHEMA public TO nvd_app;

-- =============================================================================
-- Core CVE table
-- raw: full NVD payload (forward-compatible with schema additions)
-- extracted columns: hot fields for fast filtering / indexing
-- =============================================================================
CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    source_identifier   TEXT,
    published           TIMESTAMPTZ NOT NULL,
    last_modified       TIMESTAMPTZ NOT NULL,
    vuln_status         TEXT,
    description_en      TEXT,
    cvss_v31_score      NUMERIC(3,1),
    cvss_v31_severity   TEXT,
    cvss_v31_vector     TEXT,
    cvss_v30_score      NUMERIC(3,1),
    cvss_v2_score       NUMERIC(3,1),
    cwe_ids             TEXT[],
    raw                 JSONB NOT NULL,
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Filtering / sorting indexes
CREATE INDEX IF NOT EXISTS idx_cves_last_modified ON cves (last_modified DESC);
CREATE INDEX IF NOT EXISTS idx_cves_published     ON cves (published DESC);
CREATE INDEX IF NOT EXISTS idx_cves_severity      ON cves (cvss_v31_severity);
CREATE INDEX IF NOT EXISTS idx_cves_score         ON cves (cvss_v31_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_status        ON cves (vuln_status);

-- Array and JSONB indexes
CREATE INDEX IF NOT EXISTS idx_cves_cwe_gin       ON cves USING GIN (cwe_ids);
CREATE INDEX IF NOT EXISTS idx_cves_raw_gin       ON cves USING GIN (raw jsonb_path_ops);

-- Description full-text-ish search (trigram for substring matches)
CREATE INDEX IF NOT EXISTS idx_cves_description_trgm
    ON cves USING GIN (description_en gin_trgm_ops);

-- =============================================================================
-- Sync state: one row per sync stream (currently just 'nvd_cves')
-- Tracks the high-water mark of last_modified we have ingested.
-- =============================================================================
CREATE TABLE IF NOT EXISTS sync_state (
    sync_type            TEXT PRIMARY KEY,
    last_mod_end_date    TIMESTAMPTZ,
    last_sync_at         TIMESTAMPTZ,
    last_total_results   INTEGER,
    status               TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO sync_state (sync_type, status)
VALUES ('nvd_cves', 'pending')
ON CONFLICT (sync_type) DO NOTHING;

-- =============================================================================
-- Sync runs: audit log of every sync execution (success and failure)
-- =============================================================================
CREATE TABLE IF NOT EXISTS sync_runs (
    id                   BIGSERIAL PRIMARY KEY,
    sync_type            TEXT NOT NULL,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at          TIMESTAMPTZ,
    window_start         TIMESTAMPTZ,
    window_end           TIMESTAMPTZ,
    pages_fetched        INTEGER NOT NULL DEFAULT 0,
    cves_upserted        INTEGER NOT NULL DEFAULT 0,
    total_results        INTEGER,
    status               TEXT NOT NULL DEFAULT 'running',
    error_message        TEXT
);

CREATE INDEX IF NOT EXISTS idx_sync_runs_started ON sync_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sync_runs_status  ON sync_runs (status);

-- =============================================================================
-- updated_at trigger on cves
-- =============================================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cves_updated_at ON cves;
CREATE TRIGGER trg_cves_updated_at
    BEFORE UPDATE ON cves
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =============================================================================
-- Grant least-privilege rights to the application role
-- =============================================================================
GRANT SELECT, INSERT, UPDATE ON cves       TO nvd_app;
GRANT SELECT, INSERT, UPDATE ON sync_state TO nvd_app;
GRANT SELECT, INSERT, UPDATE ON sync_runs  TO nvd_app;
GRANT USAGE, SELECT ON SEQUENCE sync_runs_id_seq TO nvd_app;
-- Note: no DELETE, no DDL, no superuser.

-- =============================================================================
-- CyberSentinel — Supabase PostgreSQL Migration
-- Run this in the Supabase SQL Editor or via psql.
-- =============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- USERS
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         TEXT NOT NULL UNIQUE,
    full_name     TEXT,
    role          TEXT NOT NULL DEFAULT 'analyst',   -- analyst | admin | viewer
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PACKETS
-- =============================================================================
CREATE TABLE IF NOT EXISTS packets (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id          TEXT,
    source_ip           TEXT NOT NULL,
    destination_ip      TEXT,
    source_port         INTEGER,
    destination_port    INTEGER,
    protocol            TEXT,
    packet_size         INTEGER,
    flow_duration       FLOAT,
    -- ML features (Model 1 input)
    fwd_packet_length_mean   FLOAT,
    bwd_packet_length_mean   FLOAT,
    flow_bytes_per_sec       FLOAT,
    flow_packets_per_sec     FLOAT,
    -- Model 1 output
    ml_prediction       TEXT,           -- Normal | Suspicious | Malicious
    ml_confidence       FLOAT,
    -- Model 2 output
    anomaly_score       FLOAT,
    -- Final
    threat_score        FLOAT,
    severity            TEXT,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip);
CREATE INDEX IF NOT EXISTS idx_packets_severity ON packets(severity);
CREATE INDEX IF NOT EXISTS idx_packets_captured_at ON packets(captured_at DESC);

-- =============================================================================
-- FIREWALL LOGS
-- =============================================================================
CREATE TABLE IF NOT EXISTS firewall_logs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        TEXT,
    action          TEXT NOT NULL,      -- ALLOW | BLOCK | DROP
    rule_id         TEXT,
    rule_name       TEXT,
    bytes_sent      BIGINT DEFAULT 0,
    bytes_received  BIGINT DEFAULT 0,
    -- Anomaly detection
    anomaly_score   FLOAT,
    is_anomalous    BOOLEAN DEFAULT FALSE,
    -- Context
    interface       TEXT,
    direction       TEXT,               -- inbound | outbound
    logged_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fw_logs_source_ip ON firewall_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_fw_logs_action ON firewall_logs(action);
CREATE INDEX IF NOT EXISTS idx_fw_logs_logged_at ON firewall_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_fw_logs_anomalous ON firewall_logs(is_anomalous);

-- =============================================================================
-- VIRUS SCANS
-- =============================================================================
CREATE TABLE IF NOT EXISTS virus_scans (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_target         TEXT NOT NULL,  -- file hash, URL, or IP
    scan_type           TEXT NOT NULL,  -- file | url | ip
    file_name           TEXT,
    file_hash_sha256    TEXT,
    file_size_bytes     BIGINT,
    -- VirusTotal results
    vt_scan_id          TEXT,
    vt_malicious        INTEGER DEFAULT 0,
    vt_suspicious       INTEGER DEFAULT 0,
    vt_harmless         INTEGER DEFAULT 0,
    vt_undetected       INTEGER DEFAULT 0,
    vt_total_engines    INTEGER DEFAULT 0,
    vt_permalink        TEXT,
    -- Computed
    threat_level        TEXT,           -- clean | low | medium | high | critical
    threat_score        FLOAT,
    -- Status
    status              TEXT NOT NULL DEFAULT 'pending',  -- pending | complete | failed
    scanned_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_virus_scans_target ON virus_scans(scan_target);
CREATE INDEX IF NOT EXISTS idx_virus_scans_threat ON virus_scans(threat_level);

-- =============================================================================
-- IP INTELLIGENCE
-- =============================================================================
CREATE TABLE IF NOT EXISTS ip_intelligence (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address              TEXT NOT NULL UNIQUE,
    -- AbuseIPDB
    abuse_confidence_score  INTEGER DEFAULT 0,
    abuse_total_reports     INTEGER DEFAULT 0,
    abuse_distinct_users    INTEGER DEFAULT 0,
    is_tor                  BOOLEAN DEFAULT FALSE,
    is_whitelisted          BOOLEAN DEFAULT FALSE,
    -- VirusTotal
    vt_malicious            INTEGER DEFAULT 0,
    vt_suspicious           INTEGER DEFAULT 0,
    vt_total_engines        INTEGER DEFAULT 0,
    vt_last_analysis_date   TIMESTAMPTZ,
    -- GeoIP
    country                 TEXT,
    country_code            CHAR(2),
    city                    TEXT,
    asn                     TEXT,
    organization            TEXT,
    isp                     TEXT,
    latitude                FLOAT,
    longitude               FLOAT,
    is_proxy                BOOLEAN DEFAULT FALSE,
    is_hosting              BOOLEAN DEFAULT FALSE,
    -- Computed
    intel_score             INTEGER DEFAULT 0,
    intel_severity          TEXT,       -- Safe | Low | High | Critical
    -- Cache metadata
    last_queried_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_intel_ip ON ip_intelligence(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_intel_severity ON ip_intelligence(intel_severity);

-- =============================================================================
-- THREAT SCORES  (Model 4 Decision Engine outputs)
-- =============================================================================
CREATE TABLE IF NOT EXISTS threat_scores (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id              TEXT,
    source_ip               TEXT,
    -- Model inputs
    model1_prediction       TEXT,
    model1_confidence       FLOAT,
    model2_anomaly_score    FLOAT,
    model3_intel_score      FLOAT,
    -- Score breakdown
    model1_contribution     FLOAT,
    model2_contribution     FLOAT,
    model3_contribution     FLOAT,
    -- Final decision
    threat_score            FLOAT NOT NULL,
    severity                TEXT NOT NULL,
    recommendation          TEXT NOT NULL,
    reasoning               TEXT[],     -- array of reason strings
    -- Metadata
    model3_available        BOOLEAN DEFAULT TRUE,
    scored_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_scores_ip ON threat_scores(source_ip);
CREATE INDEX IF NOT EXISTS idx_threat_scores_severity ON threat_scores(severity);
CREATE INDEX IF NOT EXISTS idx_threat_scores_scored_at ON threat_scores(scored_at DESC);

-- =============================================================================
-- RESPONSE ACTIONS
-- =============================================================================
CREATE TABLE IF NOT EXISTS response_actions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_score_id UUID REFERENCES threat_scores(id) ON DELETE SET NULL,
    source_ip       TEXT,
    action_type     TEXT NOT NULL,  -- block | monitor | allow | investigate
    action_status   TEXT NOT NULL DEFAULT 'pending',  -- pending | executed | failed | cancelled
    triggered_by    TEXT NOT NULL DEFAULT 'system',   -- system | analyst
    executed_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    notes           TEXT,
    executed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_ip ON response_actions(source_ip);
CREATE INDEX IF NOT EXISTS idx_response_status ON response_actions(action_status);

-- =============================================================================
-- REPORTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_type     TEXT NOT NULL,   -- daily | weekly | incident | custom
    title           TEXT NOT NULL,
    period_start    TIMESTAMPTZ,
    period_end      TIMESTAMPTZ,
    generated_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    file_path       TEXT,            -- server-side PDF path
    file_size_bytes BIGINT,
    status          TEXT NOT NULL DEFAULT 'generating',  -- generating | ready | failed
    metadata        JSONB DEFAULT '{}',
    generated_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);

-- =============================================================================
-- COPILOT CONVERSATIONS
-- =============================================================================
CREATE TABLE IF NOT EXISTS copilot_conversations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id      TEXT NOT NULL,
    role            TEXT NOT NULL,   -- user | assistant
    content         TEXT NOT NULL,
    context_used    JSONB DEFAULT '{}',   -- what RAG context was injected
    tokens_used     INTEGER DEFAULT 0,
    model_used      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_session ON copilot_conversations(session_id);
CREATE INDEX IF NOT EXISTS idx_copilot_user ON copilot_conversations(user_id);

-- =============================================================================
-- AUDIT LOGS
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    resource_id TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    payload     JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

-- Phase 11 Migration: Analyst Notes & Demo Columns

-- 1. Create Analyst Notes Table (if not exists)
CREATE TABLE IF NOT EXISTS analyst_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id TEXT NOT NULL REFERENCES threat_alerts(alert_id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT analyst_notes_content_length CHECK (char_length(content) BETWEEN 1 AND 1000)
);

-- We assume a staged migration for analyst_id
ALTER TABLE analyst_notes ADD COLUMN IF NOT EXISTS analyst_id UUID;

-- Since this is technically a fresh deployment of Phase 11, we can just enforce NOT NULL
ALTER TABLE analyst_notes ALTER COLUMN analyst_id SET NOT NULL;

-- Remove the old author column if it exists from previous attempts
ALTER TABLE analyst_notes DROP COLUMN IF EXISTS author;

-- Note: The original table used TEXT for alert_id, but the user plan recommended UUID. 
-- However, threat_alerts uses alert_id TEXT as primary/unique key conceptually in some places, 
-- or id UUID. Our existing threat_alerts uses alert_id (TEXT).
-- The foreign key matches the existing schema.

-- Create index for deterministic sorting
CREATE INDEX IF NOT EXISTS idx_analyst_notes_alert_created ON analyst_notes(alert_id, created_at, id);


-- 2. Demo Columns for existing tables
ALTER TABLE packets ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE packets ADD COLUMN IF NOT EXISTS demo_scenario TEXT;
ALTER TABLE packets ADD COLUMN IF NOT EXISTS demo_run_id UUID;

ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS demo_scenario TEXT;
ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS demo_run_id UUID;

ALTER TABLE firewall_actions ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE firewall_actions ADD COLUMN IF NOT EXISTS demo_scenario TEXT;
ALTER TABLE firewall_actions ADD COLUMN IF NOT EXISTS demo_run_id UUID;

-- Indexes for demo columns
CREATE INDEX IF NOT EXISTS idx_packets_demo_run ON packets(is_demo, demo_run_id);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_demo_run ON threat_alerts(is_demo, demo_run_id);
CREATE INDEX IF NOT EXISTS idx_firewall_actions_demo_run ON firewall_actions(is_demo, demo_run_id);

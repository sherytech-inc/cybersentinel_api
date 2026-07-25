-- Stage 14: Firewall Log Import 
-- Add Firewall Log Imports table and import_id to Firewall Logs

CREATE TABLE IF NOT EXISTS firewall_log_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_sha256 TEXT NOT NULL UNIQUE,
    source_filename TEXT,
    source_format TEXT NOT NULL,
    imported_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    imported_by UUID NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Safely add columns if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'firewall_logs' AND column_name = 'import_id'
    ) THEN
        ALTER TABLE firewall_logs ADD COLUMN import_id UUID REFERENCES firewall_log_imports(id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'firewall_logs' AND column_name = 'source_line_number'
    ) THEN
        ALTER TABLE firewall_logs ADD COLUMN source_line_number INTEGER;
    END IF;
END $$;

-- Drop existing RPC if we need to replace it
DROP FUNCTION IF EXISTS import_firewall_batch_atomic;

-- Create an RPC to perform the atomic import
CREATE OR REPLACE FUNCTION import_firewall_batch_atomic(
    p_file_sha256 TEXT,
    p_source_filename TEXT,
    p_source_format TEXT,
    p_imported_count INTEGER,
    p_rejected_count INTEGER,
    p_imported_by UUID,
    p_entries JSONB
) RETURNS UUID AS $$
DECLARE
    v_import_id UUID;
    v_entry JSONB;
BEGIN
    -- 1. Create the import batch record
    -- This will raise a unique_violation (23505) if the hash already exists.
    INSERT INTO firewall_log_imports (
        file_sha256, source_filename, source_format, 
        imported_count, rejected_count, imported_by
    )
    VALUES (
        p_file_sha256, p_source_filename, p_source_format,
        p_imported_count, p_rejected_count, p_imported_by
    )
    RETURNING id INTO v_import_id;

    -- 2. Insert all the firewall log entries
    -- The p_entries JSONB array must contain objects matching the firewall_logs table schema.
    -- We map them to the table columns.
    FOR v_entry IN SELECT * FROM jsonb_array_elements(p_entries)
    LOOP
        INSERT INTO firewall_logs (
            logged_at, source_ip, destination_ip, source_port, destination_port,
            protocol, action, interface, import_id, source_line_number
        )
        VALUES (
            (v_entry->>'logged_at')::TIMESTAMPTZ,
            v_entry->>'source_ip',
            v_entry->>'destination_ip',
            (v_entry->>'source_port')::INTEGER,
            (v_entry->>'destination_port')::INTEGER,
            v_entry->>'protocol',
            v_entry->>'action',
            v_entry->>'interface',
            v_import_id,
            (v_entry->>'source_line_number')::INTEGER
        );
    END LOOP;

    -- 3. Insert an audit log record for the transaction
    INSERT INTO audit_logs (
        action, resource, actor_id, details, created_at
    )
    VALUES (
        'IMPORT_FIREWALL_LOG',
        'FIREWALL_LOG',
        p_imported_by,
        jsonb_build_object(
            'format', p_source_format, 
            'imported', p_imported_count, 
            'import_id', v_import_id
        ),
        now()
    );

    -- Return the new import_id
    RETURN v_import_id;
END;
$$ LANGUAGE plpgsql;

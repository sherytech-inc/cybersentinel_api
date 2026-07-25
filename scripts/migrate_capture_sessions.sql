-- Durable capture-session history. REVIEWED BUT NEVER APPLIED AUTOMATICALLY.
BEGIN;

DO $$
DECLARE
    unexpected_policy_count INTEGER;
BEGIN
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='packets' AND column_name='session_id') IS DISTINCT FROM 'text' THEN
        RAISE EXCEPTION 'Expected packets.session_id text';
    END IF;
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='threat_scores' AND column_name='session_id') IS DISTINCT FROM 'text' THEN
        RAISE EXCEPTION 'Expected threat_scores.session_id text';
    END IF;
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='packets' AND column_name='captured_at') IS DISTINCT FROM 'timestamp with time zone' THEN
        RAISE EXCEPTION 'Expected packets.captured_at timestamptz';
    END IF;
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='threat_scores' AND column_name='scored_at') IS DISTINCT FROM 'timestamp with time zone' THEN
        RAISE EXCEPTION 'Expected threat_scores.scored_at timestamptz';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='packets' AND column_name='workspace_id' AND data_type='uuid') THEN
        RAISE EXCEPTION 'Expected packets.workspace_id UUID';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='threat_scores' AND column_name='workspace_id' AND data_type='uuid') THEN
        RAISE EXCEPTION 'Expected threat_scores.workspace_id UUID';
    END IF;
    SELECT count(*) INTO unexpected_policy_count
    FROM pg_policies
    WHERE schemaname='public' AND tablename IN ('packets','threat_scores')
      AND policyname NOT IN (
        'workspace_isolation_policy','packets_select_workspace',
        'packets_insert_capture_session','packets_delete_creator_session',
        'threat_scores_select_workspace','threat_scores_insert_capture_session'
      );
    IF unexpected_policy_count > 0 THEN
        RAISE EXCEPTION 'Unexpected packet/threat-score RLS policy detected';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.capture_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    analyst_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at TIMESTAMPTZ,
    interface TEXT,
    capture_mode TEXT NOT NULL DEFAULT 'live',
    status TEXT NOT NULL DEFAULT 'starting',
    captured_count INTEGER NOT NULL DEFAULT 0,
    analyzed_count INTEGER NOT NULL DEFAULT 0,
    pending_count INTEGER NOT NULL DEFAULT 0,
    complete_count INTEGER NOT NULL DEFAULT 0,
    partial_count INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    deferred_count INTEGER NOT NULL DEFAULT 0,
    not_analyzed_count INTEGER NOT NULL DEFAULT 0,
    normal_count INTEGER NOT NULL DEFAULT 0,
    suspicious_count INTEGER NOT NULL DEFAULT 0,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,
    last_reliable_score NUMERIC,
    highest_severity TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT capture_sessions_mode_check CHECK (capture_mode IN ('live','replay')),
    CONSTRAINT capture_sessions_status_check CHECK (status IN ('starting','running','stopping','stopped','completed','failed')),
    CONSTRAINT capture_sessions_nonnegative_check CHECK (
      captured_count>=0 AND analyzed_count>=0 AND pending_count>=0 AND
      complete_count>=0 AND partial_count>=0 AND failed_count>=0 AND
      deferred_count>=0 AND not_analyzed_count>=0 AND normal_count>=0 AND
      suspicious_count>=0 AND malicious_count>=0 AND unknown_count>=0
    ),
    CONSTRAINT capture_sessions_analyzed_partition_check CHECK (analyzed_count=complete_count+partial_count),
    CONSTRAINT capture_sessions_captured_partition_check CHECK (
      captured_count=complete_count+partial_count+failed_count+deferred_count+not_analyzed_count+pending_count
    ),
    CONSTRAINT capture_sessions_classification_partition_check CHECK (
      normal_count+suspicious_count+malicious_count+unknown_count=analyzed_count
    ),
    CONSTRAINT capture_sessions_terminal_pending_check CHECK (
      status NOT IN ('stopped','completed','failed') OR pending_count=0
    ),
    CONSTRAINT capture_sessions_analyzed_limit_check CHECK (analyzed_count<=captured_count),
    CONSTRAINT capture_sessions_score_check CHECK (last_reliable_score IS NULL OR last_reliable_score BETWEEN 0 AND 100)
);

ALTER TABLE public.packets
  ADD COLUMN IF NOT EXISTS flow_id TEXT,
  ADD COLUMN IF NOT EXISTS packet_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS analysis_status TEXT,
  ADD COLUMN IF NOT EXISTS action TEXT,
  ADD COLUMN IF NOT EXISTS model3_available BOOLEAN,
  ADD COLUMN IF NOT EXISTS model3_intelligence_score DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_capture_sessions_workspace_started ON public.capture_sessions(workspace_id,started_at DESC);
CREATE INDEX IF NOT EXISTS idx_capture_sessions_workspace_stopped ON public.capture_sessions(workspace_id,stopped_at DESC) WHERE stopped_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_capture_sessions_workspace_status ON public.capture_sessions(workspace_id,status);
CREATE INDEX IF NOT EXISTS idx_packets_workspace_session_captured ON public.packets(workspace_id,session_id,captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_packets_workspace_session_flow ON public.packets(workspace_id,session_id,flow_id);
CREATE INDEX IF NOT EXISTS idx_threat_scores_workspace_session_scored ON public.threat_scores(workspace_id,session_id,scored_at DESC);

CREATE OR REPLACE FUNCTION public.set_capture_session_updated_at() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=public AS $$
BEGIN NEW.updated_at=now(); RETURN NEW; END; $$;
DROP TRIGGER IF EXISTS capture_sessions_set_updated_at ON public.capture_sessions;
CREATE TRIGGER capture_sessions_set_updated_at BEFORE UPDATE ON public.capture_sessions
FOR EACH ROW EXECUTE FUNCTION public.set_capture_session_updated_at();

REVOKE ALL ON public.capture_sessions FROM anon, authenticated;
GRANT SELECT,INSERT ON public.capture_sessions TO authenticated;
GRANT UPDATE(stopped_at,status,captured_count,analyzed_count,pending_count,
  complete_count,partial_count,failed_count,deferred_count,not_analyzed_count,
  normal_count,suspicious_count,malicious_count,unknown_count,
  last_reliable_score,highest_severity) ON public.capture_sessions TO authenticated;
REVOKE UPDATE,TRUNCATE,TRIGGER,REFERENCES ON public.packets FROM authenticated;
REVOKE DELETE,UPDATE,TRUNCATE,TRIGGER,REFERENCES ON public.threat_scores FROM authenticated;
GRANT SELECT,INSERT,DELETE ON public.packets TO authenticated;
GRANT SELECT,INSERT ON public.threat_scores TO authenticated;

ALTER TABLE public.capture_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS capture_sessions_select_workspace ON public.capture_sessions;
CREATE POLICY capture_sessions_select_workspace ON public.capture_sessions FOR SELECT TO authenticated
USING (private.is_workspace_member(workspace_id));
DROP POLICY IF EXISTS capture_sessions_insert_workspace_creator ON public.capture_sessions;
CREATE POLICY capture_sessions_insert_workspace_creator ON public.capture_sessions FOR INSERT TO authenticated
WITH CHECK (private.is_workspace_member(workspace_id) AND analyst_id=auth.uid());
DROP POLICY IF EXISTS capture_sessions_update_workspace ON public.capture_sessions;
DROP POLICY IF EXISTS capture_sessions_update_creator ON public.capture_sessions;
CREATE POLICY capture_sessions_update_creator ON public.capture_sessions FOR UPDATE TO authenticated
USING (private.is_workspace_member(workspace_id) AND analyst_id=auth.uid())
WITH CHECK (private.is_workspace_member(workspace_id) AND analyst_id=auth.uid());

ALTER TABLE public.packets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workspace_isolation_policy ON public.packets;
DROP POLICY IF EXISTS packets_select_workspace ON public.packets;
CREATE POLICY packets_select_workspace ON public.packets FOR SELECT TO authenticated
USING (private.is_workspace_member(workspace_id));
DROP POLICY IF EXISTS packets_insert_capture_session ON public.packets;
CREATE POLICY packets_insert_capture_session ON public.packets FOR INSERT TO authenticated
WITH CHECK (private.is_workspace_member(workspace_id) AND EXISTS (
  SELECT 1 FROM public.capture_sessions cs
  WHERE cs.session_id::text=packets.session_id AND cs.workspace_id=packets.workspace_id
    AND cs.analyst_id=auth.uid() AND private.is_workspace_member(cs.workspace_id)
));
DROP POLICY IF EXISTS packets_delete_workspace ON public.packets;
DROP POLICY IF EXISTS packets_delete_creator_session ON public.packets;
CREATE POLICY packets_delete_creator_session ON public.packets FOR DELETE TO authenticated
USING (private.is_workspace_member(workspace_id) AND EXISTS (
  SELECT 1 FROM public.capture_sessions cs
  WHERE cs.session_id::text=packets.session_id AND cs.workspace_id=packets.workspace_id
    AND cs.analyst_id=auth.uid() AND private.is_workspace_member(cs.workspace_id)
));

ALTER TABLE public.threat_scores ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workspace_isolation_policy ON public.threat_scores;
DROP POLICY IF EXISTS threat_scores_select_workspace ON public.threat_scores;
CREATE POLICY threat_scores_select_workspace ON public.threat_scores FOR SELECT TO authenticated
USING (private.is_workspace_member(workspace_id));
DROP POLICY IF EXISTS threat_scores_insert_capture_session ON public.threat_scores;
CREATE POLICY threat_scores_insert_capture_session ON public.threat_scores FOR INSERT TO authenticated
WITH CHECK (private.is_workspace_member(workspace_id) AND EXISTS (
  SELECT 1 FROM public.capture_sessions cs
  WHERE cs.session_id::text=threat_scores.session_id AND cs.workspace_id=threat_scores.workspace_id
    AND cs.analyst_id=auth.uid() AND private.is_workspace_member(cs.workspace_id)
));

CREATE OR REPLACE FUNCTION public.checkpoint_capture_session(
  p_session_id UUID,p_status TEXT,p_stopped_at TIMESTAMPTZ,
  p_captured_count INTEGER,p_analyzed_count INTEGER,p_pending_count INTEGER,
  p_complete_count INTEGER,p_partial_count INTEGER,p_failed_count INTEGER,
  p_deferred_count INTEGER,p_not_analyzed_count INTEGER,p_normal_count INTEGER,
  p_suspicious_count INTEGER,p_malicious_count INTEGER,p_unknown_count INTEGER,
  p_last_reliable_score NUMERIC,p_highest_severity TEXT
) RETURNS SETOF public.capture_sessions LANGUAGE sql SECURITY INVOKER SET search_path=public AS $$
UPDATE public.capture_sessions SET status=p_status,stopped_at=p_stopped_at,
 captured_count=p_captured_count,analyzed_count=p_analyzed_count,pending_count=p_pending_count,
 complete_count=p_complete_count,partial_count=p_partial_count,failed_count=p_failed_count,
 deferred_count=p_deferred_count,not_analyzed_count=p_not_analyzed_count,
 normal_count=p_normal_count,suspicious_count=p_suspicious_count,
 malicious_count=p_malicious_count,unknown_count=p_unknown_count,
 last_reliable_score=p_last_reliable_score,highest_severity=p_highest_severity
WHERE session_id=p_session_id RETURNING *; $$;
REVOKE ALL ON FUNCTION public.checkpoint_capture_session(UUID,TEXT,TIMESTAMPTZ,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,NUMERIC,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.checkpoint_capture_session(UUID,TEXT,TIMESTAMPTZ,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,INTEGER,NUMERIC,TEXT) TO authenticated;

COMMIT;

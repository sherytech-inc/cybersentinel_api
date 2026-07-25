-- Conservative rollback: restore the reviewed pre-migration packet/threat-score
-- access model without deleting capture history or newly added columns.
BEGIN;

DROP POLICY IF EXISTS packets_select_workspace ON public.packets;
DROP POLICY IF EXISTS packets_insert_capture_session ON public.packets;
DROP POLICY IF EXISTS packets_delete_creator_session ON public.packets;
CREATE POLICY workspace_isolation_policy ON public.packets
FOR ALL TO authenticated
USING (private.is_workspace_member(workspace_id))
WITH CHECK (private.is_workspace_member(workspace_id));

DROP POLICY IF EXISTS threat_scores_select_workspace ON public.threat_scores;
DROP POLICY IF EXISTS threat_scores_insert_capture_session ON public.threat_scores;
CREATE POLICY workspace_isolation_policy ON public.threat_scores
FOR ALL TO authenticated
USING (private.is_workspace_member(workspace_id))
WITH CHECK (private.is_workspace_member(workspace_id));

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER
ON public.packets TO authenticated;
GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER
ON public.threat_scores TO authenticated;

-- Deliberately retain capture_sessions and its data for diagnosis/recovery.
-- The previous application build ignores this additive table.

COMMIT;

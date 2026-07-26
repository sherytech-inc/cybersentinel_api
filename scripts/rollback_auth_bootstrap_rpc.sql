-- Roll back the CyberSentinel authenticated profile bootstrap RPC.
--
-- Apply manually only if the compatible backend and Flutter authentication
-- deployment must be reverted.

BEGIN;

REVOKE ALL
ON FUNCTION public.bootstrap_current_user_profile()
FROM authenticated, anon, PUBLIC;

DROP FUNCTION public.bootstrap_current_user_profile();

COMMIT;

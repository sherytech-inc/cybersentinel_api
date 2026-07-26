-- CyberSentinel authenticated profile bootstrap RPC.
--
-- Apply manually in the Supabase SQL Editor before deploying the compatible
-- backend and Flutter authentication changes. This script intentionally adds
-- no direct table grants and changes no RLS policies.

BEGIN;

CREATE FUNCTION public.bootstrap_current_user_profile()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
    caller_id uuid := auth.uid();
    caller_email text :=
        lower(trim(coalesce(auth.jwt() ->> 'email', '')));

    authorization_record public.authorized_users%ROWTYPE;
    profile_record public.profiles%ROWTYPE;
BEGIN
    IF caller_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'authentication_required';
    END IF;

    IF caller_email = '' THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'authenticated_email_missing';
    END IF;

    SELECT au.*
    INTO authorization_record
    FROM public.authorized_users AS au
    WHERE lower(trim(au.email)) = caller_email
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'account_not_authorized';
    END IF;

    IF authorization_record.is_active IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'account_disabled';
    END IF;

    IF authorization_record.role NOT IN ('analyst', 'admin') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid_authorization_role';
    END IF;

    INSERT INTO public.profiles (
        user_id,
        email,
        display_name,
        role,
        is_active,
        updated_at
    )
    VALUES (
        caller_id,
        authorization_record.email,
        authorization_record.display_name,
        authorization_record.role,
        true,
        now()
    )
    ON CONFLICT (user_id) DO UPDATE
    SET
        email = EXCLUDED.email,
        display_name = EXCLUDED.display_name,
        role = EXCLUDED.role,
        is_active = EXCLUDED.is_active,
        updated_at = now()
    RETURNING *
    INTO profile_record;

    RETURN jsonb_build_object(
        'user_id', profile_record.user_id,
        'email', profile_record.email,
        'display_name', profile_record.display_name,
        'role', profile_record.role,
        'is_active', profile_record.is_active
    );
END;
$function$;

ALTER FUNCTION public.bootstrap_current_user_profile()
OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.bootstrap_current_user_profile()
FROM PUBLIC;

REVOKE ALL
ON FUNCTION public.bootstrap_current_user_profile()
FROM anon;

GRANT EXECUTE
ON FUNCTION public.bootstrap_current_user_profile()
TO authenticated;

COMMIT;

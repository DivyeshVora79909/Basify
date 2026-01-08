CREATE OR REPLACE FUNCTION public.get_user_session_context()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_user_id uuid;
    v_role_record RECORD;
    v_cached_perms text[];
BEGIN
    v_user_id := auth.uid();
    SELECT 
        r.name, 
        r.path::text as path, 
        rd.key as role_key, 
        p.tenant_id,
        p.cached_permissions
    INTO v_role_record
    FROM public.profiles p
    JOIN public.roles r ON p.role_id = r.id
    LEFT JOIN public.role_definitions rd ON r.definition_id = rd.id
    WHERE p.id = v_user_id;

    RETURN jsonb_build_object(
        'tenant_id', v_role_record.tenant_id,
        'role', jsonb_build_object(
            'name', v_role_record.name, 
            'key', v_role_record.role_key, 
            'path', v_role_record.path
        ),
        'permissions', COALESCE(v_role_record.cached_permissions, '{}'::text[])
    );
END;
$$;
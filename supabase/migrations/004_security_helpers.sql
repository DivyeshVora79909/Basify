-- 1. Utility: Get Current Tenant
CREATE OR REPLACE FUNCTION app_internal.current_tenant_id()
RETURNS uuid LANGUAGE sql STABLE
AS $$ SELECT (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid; $$;

-- 2. Utility: Get My Role Path
CREATE OR REPLACE FUNCTION app_internal.get_my_role_path()
RETURNS ltree
LANGUAGE sql STABLE SECURITY DEFINER
AS $$
    SELECT r.path 
    FROM public.profiles p
    JOIN public.roles r ON p.role_id = r.id
    WHERE p.id = auth.uid();
$$;

-- 3. CACHE BUILDER (The Logic Engine)
CREATE OR REPLACE FUNCTION app_internal.build_user_permissions(p_user_id uuid)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_perms text[];
BEGIN
    SELECT ARRAY_AGG(DISTINCT p.slug)
    INTO v_perms
    FROM public.profiles prof
    JOIN public.roles r ON prof.role_id = r.id
    -- 1. Definition Permissions
    LEFT JOIN public.role_definitions rd ON r.definition_id = rd.id
    LEFT JOIN public.role_definition_permissions rdp ON rd.id = rdp.role_definition_id
    LEFT JOIN public.permissions perm_def ON rdp.permission_id = perm_def.id
    -- 2. Custom Role Permissions
    LEFT JOIN public.role_permissions rp ON r.id = rp.role_id
    LEFT JOIN public.permissions perm_cust ON rp.permission_id = perm_cust.id
    WHERE prof.id = p_user_id;

    RETURN COALESCE(v_perms, '{}'::text[]);
END;
$$;

-- 4. CHECK PERMISSION (Optimized O(1))
CREATE OR REPLACE FUNCTION app_internal.has_permission(p_perm_slug text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
AS $$
    SELECT (cached_permissions @> ARRAY[p_perm_slug])
    FROM public.profiles
    WHERE id = auth.uid();
$$;
-- 1. Utility: Get Current Tenant
CREATE OR REPLACE FUNCTION app_internal.current_tenant_id()
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY DEFINER
AS $$
DECLARE
    v_jwt_tenant_id uuid;
    v_profile_tenant_id uuid;
BEGIN
    v_jwt_tenant_id := (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid;
    SELECT tenant_id INTO v_profile_tenant_id FROM public.profiles WHERE id = auth.uid();
    
    IF v_jwt_tenant_id IS NULL OR v_jwt_tenant_id != v_profile_tenant_id THEN
        RETURN NULL;
    END IF;
    
    RETURN v_profile_tenant_id;
END;
$$;

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
    SELECT ARRAY_AGG(DISTINCT slug)
    INTO v_perms
    FROM (
        -- 1. Get permissions from the Role Definition (e.g. "Tenant Owner" defaults)
        SELECT p.slug
        FROM public.profiles prof
        JOIN public.roles r ON prof.role_id = r.id
        JOIN public.role_definitions rd ON r.definition_id = rd.id
        JOIN public.role_definition_permissions rdp ON rd.id = rdp.role_definition_id
        JOIN public.permissions p ON rdp.permission_id = p.id
        WHERE prof.id = p_user_id
        
        UNION
        
        -- 2. Get permissions from Custom Role Overrides (Specific to this role instance)
        SELECT p.slug
        FROM public.profiles prof
        JOIN public.roles r ON prof.role_id = r.id
        JOIN public.role_permissions rp ON r.id = rp.role_id
        JOIN public.permissions p ON rp.permission_id = p.id
        WHERE prof.id = p_user_id
    ) combined_perms;

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
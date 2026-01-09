CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    v_claims jsonb;
    v_tenant_id uuid;
    v_user_id uuid;
BEGIN
    v_claims := event -> 'claims';
    v_user_id := (event ->> 'user_id')::uuid;

    SELECT tenant_id INTO v_tenant_id 
    FROM public.profiles 
    WHERE id = v_user_id;
    
    IF v_tenant_id IS NULL THEN
        RAISE EXCEPTION 'Access Denied: User does not belong to a valid tenant.';
    END IF;

    -- Only add Tenant ID. Hierarchy is checked via Database Index, not JWT.
    v_claims := jsonb_set(v_claims, '{app_metadata, tenant_id}', to_jsonb(v_tenant_id));
    RETURN jsonb_set(event, '{claims}', v_claims);
END;
$$;

GRANT EXECUTE ON FUNCTION public.custom_access_token_hook TO supabase_auth_admin;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook FROM authenticated, anon, public;
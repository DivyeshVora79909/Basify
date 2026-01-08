CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_claims jsonb;
    v_tenant_id uuid;
BEGIN
    v_claims := event -> 'claims';
    SELECT tenant_id INTO v_tenant_id FROM public.profiles WHERE id = (event ->> 'user_id')::uuid;
    
    -- Only add Tenant ID. Hierarchy is checked via Database Index, not JWT.
    v_claims := jsonb_set(v_claims, '{app_metadata, tenant_id}', to_jsonb(v_tenant_id));
    RETURN jsonb_set(event, '{claims}', v_claims);
END;
$$;
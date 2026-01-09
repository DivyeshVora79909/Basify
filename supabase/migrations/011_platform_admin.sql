-- 1. SECURITY CHECKER: Platform Admin Guard
-- Centralizes the logic for "Who is a Super Admin?"
-- Currently checks for the 'service_role' key (Standard Supabase Backend Admin)
CREATE OR REPLACE FUNCTION app_internal.is_platform_admin()
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- Check if the request is signed by the Service Role (Supabase Admin)
    IF (auth.jwt() ->> 'role') = 'service_role' THEN
        RETURN true;
    END IF;
    
    -- Future Proofing: You can add specific User IDs here if you want manual admin users
    -- IF auth.uid() IN ('...uuid...') THEN RETURN true; END IF;

    RETURN false;
END;
$$;

-- 2. RPC: PROVISION TENANT (Infrastructure + Defaults)
-- Creates the Tenant, The Owner Role, and Default CRM Pipelines
CREATE OR REPLACE FUNCTION public.admin_provision_tenant(
    p_name text,
    p_slug text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER -- Bypasses RLS
AS $$
DECLARE
    v_tenant_id uuid;
    v_def_id uuid;
    v_role_id uuid;
    v_path text;
    v_pipeline_id uuid;
BEGIN
    -- 1. Security Gate
    IF NOT app_internal.is_platform_admin() THEN
        RAISE EXCEPTION 'Access Denied: Platform Admin only.';
    END IF;

    -- 2. Create Tenant
    INSERT INTO public.tenants (name, slug) VALUES (p_name, p_slug) 
    RETURNING id INTO v_tenant_id;

    -- 3. Create Root Role (Tenant Owner)
    SELECT id INTO v_def_id FROM public.role_definitions WHERE key = 'TENANT_OWNER';

    INSERT INTO public.roles (id, tenant_id, definition_id, name, path)
    VALUES (gen_random_uuid(), v_tenant_id, v_def_id, 'Owner', 'root') 
    RETURNING id INTO v_role_id;

    -- 4. Fix Ltree Path (root.owner_uuid)
    v_path := app_internal.uuid_to_ltree(v_role_id);
    UPDATE public.roles SET path = v_path::ltree WHERE id = v_role_id;

    -- 5. SEED DEFAULT DATA (Responsible Setup)
    -- Don't give them an empty system. Create a default Sales Pipeline.
    INSERT INTO public.crm_pipelines (tenant_id, name, is_default)
    VALUES (v_tenant_id, 'Sales Pipeline', true)
    RETURNING id INTO v_pipeline_id;

    INSERT INTO public.crm_stages (tenant_id, pipeline_id, name, category, position) VALUES
    (v_tenant_id, v_pipeline_id, 'Discovery', 'OPEN', 10),
    (v_tenant_id, v_pipeline_id, 'Proposal', 'OPEN', 20),
    (v_tenant_id, v_pipeline_id, 'Negotiation', 'OPEN', 30),
    (v_tenant_id, v_pipeline_id, 'Closed Won', 'WON', 40),
    (v_tenant_id, v_pipeline_id, 'Closed Lost', 'LOST', 50);

    -- 6. Return Data for the next step (Invite)
    RETURN jsonb_build_object(
        'tenant_id', v_tenant_id,
        'owner_role_id', v_role_id,
        'message', 'Tenant infrastructure and defaults provisioned.'
    );
END;
$$;

-- 3. RPC: ADMIN INVITE (Bypassing Tenant Isolation)
-- Allows the Admin to send the initial invite to the CEO/Owner
CREATE OR REPLACE FUNCTION public.admin_invite_user(
    p_tenant_id uuid,
    p_role_id uuid,
    p_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_invite_id uuid;
BEGIN
    -- 1. Security Gate
    IF NOT app_internal.is_platform_admin() THEN
        RAISE EXCEPTION 'Access Denied: Platform Admin only.';
    END IF;

    -- 2. Validation
    PERFORM 1 FROM public.tenants WHERE id = p_tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Tenant not found'; END IF;

    PERFORM 1 FROM public.roles WHERE id = p_role_id AND tenant_id = p_tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Role not found or does not belong to tenant'; END IF;

    -- 3. Create Invitation
    -- We allow invited_by to be NULL here, signifying a System Invite
    INSERT INTO public.invitations (tenant_id, target_role_id, email, status, invited_by)
    VALUES (p_tenant_id, p_role_id, p_email, 'pending', NULL) 
    RETURNING id INTO v_invite_id;

    RETURN jsonb_build_object(
        'invitation_id', v_invite_id,
        'email', p_email,
        'message', 'User invited successfully.'
    );
END;
$$;
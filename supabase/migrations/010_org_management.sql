-- 1. RPC: CREATE SUB-ROLE (Building the Hierarchy)
CREATE OR REPLACE FUNCTION public.create_role(
    p_name text,
    p_parent_role_id uuid,
    p_definition_key text -- e.g. 'MANAGER'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tenant_id uuid;
    v_def_id uuid;
    v_parent_path ltree;
    v_new_role_id uuid;
    v_new_path ltree;
BEGIN
    -- 1. Check Permissions
    IF NOT app_internal.has_permission('sys.roles.manage') THEN 
        RAISE EXCEPTION 'Access Denied'; 
    END IF;

    v_tenant_id := app_internal.current_tenant_id();

    -- 2. Get Parent Context (Ensure parent belongs to tenant)
    SELECT path INTO v_parent_path 
    FROM public.roles 
    WHERE id = p_parent_role_id AND tenant_id = v_tenant_id;

    IF v_parent_path IS NULL THEN RAISE EXCEPTION 'Parent role not found'; END IF;

    -- 3. Get Definition ID
    SELECT id INTO v_def_id FROM public.role_definitions WHERE key = p_definition_key;
    IF v_def_id IS NULL THEN RAISE EXCEPTION 'Invalid Role Definition'; END IF;

    -- 4. Create Role (Optimistic Path)
    INSERT INTO public.roles (id, tenant_id, definition_id, name, path)
    VALUES (gen_random_uuid(), v_tenant_id, v_def_id, p_name, 'root')
    RETURNING id INTO v_new_role_id;

    -- 5. Calculate and Update Ltree Path (Parent.Child)
    v_new_path := v_parent_path || app_internal.uuid_to_ltree(v_new_role_id)::ltree;
    
    UPDATE public.roles SET path = v_new_path WHERE id = v_new_role_id;

    RETURN jsonb_build_object('id', v_new_role_id);
END;
$$;

-- 2. RPC: INVITE USER
CREATE OR REPLACE FUNCTION public.invite_user(
    p_email text,
    p_role_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tenant_id uuid;
    v_invite_id uuid;
BEGIN
    -- 1. Check Permissions
    -- You might want a specific 'sys.users.invite' permission
    IF NOT app_internal.has_permission('sys.roles.manage') THEN 
        RAISE EXCEPTION 'Access Denied'; 
    END IF;

    v_tenant_id := app_internal.current_tenant_id();

    -- 2. Validate Role belongs to tenant
    PERFORM 1 FROM public.roles WHERE id = p_role_id AND tenant_id = v_tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Invalid Role'; END IF;

    -- 3. Create Invitation
    INSERT INTO public.invitations (tenant_id, target_role_id, email, status, invited_by)
    VALUES (v_tenant_id, p_role_id, p_email, 'pending', auth.uid())
    RETURNING id INTO v_invite_id;

    -- In a real app, you would trigger an Edge Function here to send the email
    
    RETURN jsonb_build_object('id', v_invite_id);
END;
$$;

-- 3. TRIGGER: ENFORCE INVITATION ON SIGNUP
CREATE OR REPLACE FUNCTION public.handle_new_user_signup()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_invite public.invitations%ROWTYPE;
BEGIN
    -- A. Look for PENDING invitation
    SELECT * INTO v_invite FROM public.invitations WHERE email = NEW.email AND status = 'pending';

    -- B. STRICT ENFORCEMENT
    IF v_invite IS NULL THEN
        RAISE EXCEPTION 'Registration not allowed: No valid invitation found for %.', NEW.email;
    END IF;

    -- C. Auto-Create Profile (This prevents the Auth Hook from failing)
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name)
    VALUES (
        NEW.id,
        v_invite.tenant_id,
        v_invite.target_role_id,
        COALESCE(NEW.raw_user_meta_data->>'full_name', 'New User')
    );

    -- D. Close Invite
    UPDATE public.invitations SET status = 'accepted' WHERE id = v_invite.id;

    RETURN NEW;
END;
$$;

-- Bind Trigger
-- DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user_signup();

-- 4. RPC: ACCEPT INVITATION (Legacy/Multi-tenant support)
CREATE OR REPLACE FUNCTION public.accept_invitation(
    p_invite_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_invite public.invitations%ROWTYPE;
BEGIN
    -- 1. Get Invitation
    SELECT * INTO v_invite FROM public.invitations WHERE id = p_invite_id;
    
    IF v_invite IS NULL OR v_invite.status != 'pending' THEN
        RAISE EXCEPTION 'Invalid or expired invitation';
    END IF;

    -- 2. Verify Email matches current auth user
    -- (Optional strict check: IF v_invite.email != auth.email() ...)

    -- 3. Create Profile
    -- This fires the Trigger to build permission cache automatically!
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name)
    VALUES (auth.uid(), v_invite.tenant_id, v_invite.target_role_id, 'New User');

    -- 4. Close Invite
    UPDATE public.invitations SET status = 'accepted' WHERE id = p_invite_id;

    RETURN true;
END;
$$;
-- 1. LOCK DOWN TABLES
REVOKE INSERT, UPDATE, DELETE ON public.crm_deals FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.roles FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.profiles FROM authenticated;

-- 2. TRIGGER FUNCTION: AUTO-REFRESH CACHE (Per User)
CREATE OR REPLACE FUNCTION public.trigger_refresh_permission_cache()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE public.profiles
    SET cached_permissions = app_internal.build_user_permissions(NEW.id)
    WHERE id = NEW.id;
    RETURN NEW;
END;
$$;

-- Apply Trigger: Whenever a profile is created or the role changes
DROP TRIGGER IF EXISTS on_profile_role_change ON public.profiles;
CREATE TRIGGER on_profile_role_change
AFTER INSERT OR UPDATE OF role_id ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.trigger_refresh_permission_cache();

-- A. Handle "Global Rule" Changes (Role Definition Permissions)
CREATE OR REPLACE FUNCTION public.propagate_definition_perm_change()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_def_id uuid;
BEGIN
    v_def_id := COALESCE(NEW.role_definition_id, OLD.role_definition_id);
    
    -- Find all users who have a role linked to this definition and refresh them
    UPDATE public.profiles p
    SET cached_permissions = app_internal.build_user_permissions(p.id)
    FROM public.roles r
    WHERE p.role_id = r.id AND r.definition_id = v_def_id;
    
    RETURN NULL;
END;
$$;

CREATE TRIGGER on_def_perm_change
AFTER INSERT OR UPDATE OR DELETE ON public.role_definition_permissions
FOR EACH ROW EXECUTE FUNCTION public.propagate_definition_perm_change();

-- B. Handle "Custom Role" Changes (Role Permissions)
CREATE OR REPLACE FUNCTION public.propagate_custom_perm_change()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_role_id uuid;
BEGIN
    v_role_id := COALESCE(NEW.role_id, OLD.role_id);
    
    -- Find all users with this specific role and refresh them
    UPDATE public.profiles
    SET cached_permissions = app_internal.build_user_permissions(id)
    WHERE role_id = v_role_id;
    
    RETURN NULL;
END;
$$;

CREATE TRIGGER on_custom_perm_change
AFTER INSERT OR UPDATE OR DELETE ON public.role_permissions
FOR EACH ROW EXECUTE FUNCTION public.propagate_custom_perm_change();

-- ---------------------------------------------------------

-- 3. ONBOARDING RPC (Updated)
CREATE OR REPLACE FUNCTION public.create_tenant(p_name text, p_slug text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tenant_id uuid;
    v_def_id uuid;
    v_role_id uuid;
    v_path text;
BEGIN
    INSERT INTO public.tenants (name, slug) VALUES (p_name, p_slug) RETURNING id INTO v_tenant_id;
    SELECT id INTO v_def_id FROM public.role_definitions WHERE key = 'TENANT_OWNER';
    
    INSERT INTO public.roles (id, tenant_id, definition_id, name, path)
    VALUES (gen_random_uuid(), v_tenant_id, v_def_id, 'Owner', 'root') 
    RETURNING id INTO v_role_id;
    
    v_path := app_internal.uuid_to_ltree(v_role_id);
    UPDATE public.roles SET path = v_path::ltree WHERE id = v_role_id;
    
    -- Inserting here fires 'on_profile_role_change', setting the cache.
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name)
    VALUES (auth.uid(), v_tenant_id, v_role_id, 'Admin');
    
    RETURN jsonb_build_object('tenant_id', v_tenant_id);
END;
$$;

-- 4. CREATE DEAL RPC
CREATE OR REPLACE FUNCTION public.create_deal(
    p_title text, p_amount numeric, p_visibility visibility_mode, 
    p_pipeline_id uuid, p_stage_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_path ltree;
    v_new_id uuid;
BEGIN
    IF NOT app_internal.has_permission('crm.deals.create') THEN RAISE EXCEPTION 'Access Denied'; END IF;

    v_path := app_internal.get_my_role_path();

    INSERT INTO public.crm_deals (
        tenant_id, title, amount, visibility, pipeline_id, stage_id, 
        owner_id, owner_role_path
    )
    VALUES (
        app_internal.current_tenant_id(), p_title, p_amount, p_visibility, p_pipeline_id, p_stage_id,
        auth.uid(), v_path
    )
    RETURNING id INTO v_new_id;

    RETURN jsonb_build_object('id', v_new_id);
END;
$$;

-- 5. UPDATE DEAL RPC
CREATE OR REPLACE FUNCTION public.update_deal(p_deal_id uuid, p_updates jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_deal public.crm_deals%ROWTYPE;
    v_my_path ltree;
    v_can_edit boolean := false;
BEGIN
    SELECT * INTO v_deal FROM public.crm_deals WHERE id = p_deal_id;
    v_my_path := app_internal.get_my_role_path();

    IF NOT app_internal.has_permission('crm.deals.update') THEN RAISE EXCEPTION 'No Permission'; END IF;

    IF v_deal.owner_id = auth.uid() THEN v_can_edit := true;
    ELSIF v_deal.visibility = 'PUBLIC' THEN v_can_edit := true;
    ELSIF v_deal.visibility IN ('CONTROLLED', 'PRIVATE') THEN
        IF (v_my_path @> v_deal.owner_role_path) THEN v_can_edit := true; END IF;
    END IF;

    IF NOT v_can_edit THEN RAISE EXCEPTION 'Access Denied'; END IF;

    UPDATE public.crm_deals
    SET 
        title = COALESCE((p_updates->>'title'), title),
        amount = COALESCE((p_updates->>'amount')::numeric, amount),
        visibility = COALESCE((p_updates->>'visibility')::visibility_mode, visibility),
        updated_at = now()
    WHERE id = p_deal_id;

    RETURN true;
END;
$$;
-- Enable RLS
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crm_deals ENABLE ROW LEVEL SECURITY;

-- Basic Tenant Isolation
CREATE POLICY "Tenants: View Own" ON public.tenants FOR SELECT USING (id = app_internal.current_tenant_id());
CREATE POLICY "Roles: View Tenant" ON public.roles FOR SELECT USING (tenant_id = app_internal.current_tenant_id());
CREATE POLICY "Profiles: View Own" ON public.profiles FOR SELECT USING (id = auth.uid());
CREATE POLICY "Profiles: View Tenant" ON public.profiles FOR SELECT USING (tenant_id = app_internal.current_tenant_id());

-- SCALABLE RESOURCE ACCESS (The "State Machine" Read Layer)
CREATE POLICY "Deals: Select Access" ON public.crm_deals
    FOR SELECT
    USING (
        tenant_id = app_internal.current_tenant_id()
        AND (
            -- A. Visibility: Public/Controlled
            visibility IN ('PUBLIC', 'CONTROLLED')
            OR
            -- B. Ownership: It's mine
            owner_id = auth.uid()
            OR
            -- C. Hierarchy: It belongs to a subordinate (O(1) Index Scan)
            (app_internal.get_my_role_path() @> owner_role_path)
        )
    );

-- NOTE: No Insert/Update policies. We force RPCs.

-- 1. Enable RLS on Config Tables
ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_definition_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.crm_pipelines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crm_stages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY;

-- 2. Add READ-ONLY Policies (So the App can fetch config)

-- Global Config (Readable by all authenticated users)
CREATE POLICY "Read Global Perms" ON public.permissions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Read Global Definitions" ON public.role_definitions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Read Global Def Perms" ON public.role_definition_permissions FOR SELECT TO authenticated USING (true);

-- Tenant Config (Readable only by Tenant Members)
CREATE POLICY "Read Tenant Pipelines" ON public.crm_pipelines FOR SELECT USING (tenant_id = app_internal.current_tenant_id());
CREATE POLICY "Read Tenant Stages" ON public.crm_stages FOR SELECT USING (tenant_id = app_internal.current_tenant_id());
CREATE POLICY "Read Tenant Invitations" ON public.invitations FOR SELECT USING (tenant_id = app_internal.current_tenant_id());

-- Role Permissions (Readable if the role belongs to your tenant)
CREATE POLICY "Read Tenant Role Perms" ON public.role_permissions FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.roles WHERE id = role_permissions.role_id AND tenant_id = app_internal.current_tenant_id())
);

-- 3. Lock Down Writes (Force RPCs or Service Role only)
REVOKE INSERT, UPDATE, DELETE ON public.permissions FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.role_definitions FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.crm_pipelines FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.crm_stages FROM authenticated;
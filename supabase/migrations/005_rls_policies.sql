-- Enable RLS
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crm_deals ENABLE ROW LEVEL SECURITY;

-- Basic Tenant Isolation
CREATE POLICY "Tenants: View Own" ON public.tenants FOR SELECT USING (id = app_internal.current_tenant_id());
CREATE POLICY "Roles: View Tenant" ON public.roles FOR SELECT USING (tenant_id = app_internal.current_tenant_id());
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
-- 1. PIPELINES
CREATE TABLE public.crm_pipelines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. STAGES
CREATE TABLE public.crm_stages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    pipeline_id UUID NOT NULL REFERENCES public.crm_pipelines(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category crm_stage_category NOT NULL DEFAULT 'OPEN',
    position INTEGER NOT NULL DEFAULT 0
);

-- 3. DEALS (The Resource)
CREATE TABLE public.crm_deals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    
    title TEXT NOT NULL,
    amount NUMERIC DEFAULT 0,
    pipeline_id UUID REFERENCES public.crm_pipelines(id),
    stage_id UUID REFERENCES public.crm_stages(id),
    
    -- Security & ReBAC Fields
    visibility visibility_mode NOT NULL DEFAULT 'PRIVATE',
    owner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    
    -- DENORMALIZATION: Snapshot of owner's path at creation/update
    owner_role_path ltree, 
    
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Critical Indexes for RLS Performance
CREATE INDEX idx_deals_tenant ON public.crm_deals(tenant_id);
CREATE INDEX idx_deals_owner ON public.crm_deals(owner_id);
-- This index makes the hierarchy check instant
CREATE INDEX idx_deals_path ON public.crm_deals USING GIST (owner_role_path);
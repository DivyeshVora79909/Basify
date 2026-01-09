-- 1. TENANTS
CREATE TABLE public.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. PERMISSIONS CATALOG
CREATE TABLE public.permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT UNIQUE NOT NULL,
    description TEXT
);

-- 3. ROLE DEFINITIONS
CREATE TABLE public.role_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    is_system BOOLEAN DEFAULT false,
    allow_hierarchy_manage BOOLEAN DEFAULT false,
    is_protected BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. DEFAULT PERMISSIONS
CREATE TABLE public.role_definition_permissions (
    role_definition_id UUID REFERENCES public.role_definitions(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES public.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_definition_id, permission_id)
);

-- 5. ROLES
CREATE TABLE public.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    definition_id UUID REFERENCES public.role_definitions(id),
    name TEXT NOT NULL,
    path ltree NOT NULL, -- Materialized Path
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_roles_path ON public.roles USING GIST (path);
CREATE INDEX idx_roles_tenant ON public.roles(tenant_id);

-- 5.1 PREVENT TENANT REASSIGNMENT
CREATE OR REPLACE FUNCTION public.prevent_role_tenant_change()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id != OLD.tenant_id THEN
        RAISE EXCEPTION 'Cannot change tenant_id on a role';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_role_tenant_change
BEFORE UPDATE OF tenant_id ON public.roles
FOR EACH ROW EXECUTE FUNCTION public.prevent_role_tenant_change();

-- 6. ROLE PERMISSIONS
CREATE TABLE public.role_permissions (
    role_id UUID REFERENCES public.roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES public.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 7. PROFILES (Updated with Cache)
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE RESTRICT,
    
    first_name TEXT,
    last_name TEXT,
    cached_permissions TEXT[] DEFAULT '{}', 
    created_at TIMESTAMPTZ DEFAULT now()
);

-- GIN Index allows incredibly fast "Does User Have Permission X?" checks
CREATE INDEX idx_profiles_permissions ON public.profiles USING GIN (cached_permissions);

-- 8. INVITATIONS
CREATE TABLE public.invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    target_role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    status invitation_status NOT NULL DEFAULT 'pending',
    invited_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);
-- 1. Create Permissions
INSERT INTO public.permissions (slug, description) VALUES
('crm.deals.read', 'View Deals'),
('crm.deals.create', 'Create Deals'),
('crm.deals.update', 'Update Deals'),
('crm.deals.delete', 'Delete Deals'),
('sys.roles.manage', 'Manage Tenant Roles');

-- 2. Define State Machine Rules
INSERT INTO public.role_definitions (key, name, is_system, allow_hierarchy_manage, is_protected) VALUES
('TENANT_OWNER', 'Tenant Owner', true, true, true),
('MANAGER', 'Manager', false, false, false),
('EMPLOYEE', 'Employee', false, false, false);

-- 3. Link Default Perms
INSERT INTO public.role_definition_permissions (role_definition_id, permission_id)
SELECT rd.id, p.id FROM public.role_definitions rd, public.permissions p
WHERE rd.key = 'TENANT_OWNER'; -- Owner gets everything
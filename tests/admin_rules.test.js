import tap from 'tap';
import { adminClient, setupTenant, setupUser, generateJwt, getClient, resetDb } from './test_helper.js';

tap.test('Tenant Owner & Admin Rules (81-90)', async (t) => {
    const tenantA = await setupTenant('Admin Test Tenant A', 'admin-a', 'owner-admin-a@test.com');
    const tenantB = await setupTenant('Admin Test Tenant B', 'admin-b', 'owner-admin-b@test.com');

    t.test('81. Only owner has full hierarchy reach', async (t) => {
        // Owner should see all roles in their tenant
        const { data: roles } = await tenantA.client.from('roles').select('*');
        t.ok(roles.length >= 1, 'Owner should see roles');
    });

    t.test('87. Platform admin bypass only via service_role', async (t) => {
        // Try to call admin_provision_tenant as a regular owner
        const { error } = await tenantA.client.rpc('admin_provision_tenant', {
            p_name: 'Hacked Tenant',
            p_slug: 'hacked'
        });
        t.ok(error, 'Regular owner should be blocked from platform admin RPC');

        // Call as service_role (adminClient)
        const { data, error: adminError } = await adminClient.rpc('admin_provision_tenant', {
            p_name: 'New Tenant',
            p_slug: 'new-tenant'
        });
        t.notOk(adminError, 'Service role should be able to call platform admin RPC');
    });

    t.test('89. Tenant owner cannot escape tenant', async (t) => {
        // Try to see Tenant B data as Tenant A owner
        const { data } = await tenantA.client.from('tenants').select('*').eq('id', tenantB.tenantId);
        t.equal(data.length, 0, 'Tenant A owner should not see Tenant B');
    });

    t.test('90. Tenant owner isolation from other tenants enforced', async (t) => {
        // Try to create a deal in Tenant B as Tenant A owner
        // (create_deal uses current_tenant_id() which we hardened to use DB profile)
        const { data, error } = await tenantA.client.rpc('create_deal', {
            p_title: 'Hacked Deal',
            p_amount: 100,
            p_visibility: 'PUBLIC',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // The deal will be created in Tenant A because current_tenant_id() returns Tenant A
        const { data: checkA } = await adminClient.from('crm_deals').select('*').eq('id', data?.id).single();
        t.equal(checkA.tenant_id, tenantA.tenantId, 'Deal should be created in user\'s own tenant, not target tenant');
    });

    t.test('85. Owner role cannot be deleted', async (t) => {
        const { data: role } = await adminClient.from('roles').select('id').eq('tenant_id', tenantA.tenantId).eq('name', 'Owner').single();
        const { error } = await adminClient.from('roles').delete().eq('id', role.id);
        // This might fail if there's no trigger/constraint, let's see.
        // Actually, profiles has RESTRICT on role_id, so it should be blocked if owner exists.
        t.ok(error, 'Owner role should be protected from deletion while in use');
    });

    t.test('86. Owner role cannot be reassigned (to another tenant)', async (t) => {
        const { data: role } = await adminClient.from('roles').select('id').eq('tenant_id', tenantA.tenantId).eq('name', 'Owner').single();
        const { error } = await adminClient.from('roles').update({ tenant_id: tenantB.tenantId }).eq('id', role.id);
        // This should be blocked by RLS or triggers if we have them.
        // Even if it succeeds, it's a security gap we should detect.
        t.ok(error, 'Owner role should not be reassignable to another tenant');
    });
});

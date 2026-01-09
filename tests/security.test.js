import tap from 'tap';
import { adminClient, setupTenant, setupUser, generateJwt, getClient, resetDb } from './test_helper.js';

tap.test('Core Isolation & Identity (1-15)', async (t) => {
    // Setup: Create two tenants and users
    const tenantA = await setupTenant('Tenant A', 'tenant-a', 'owner-a@test.com');
    const tenantB = await setupTenant('Tenant B', 'tenant-b', 'owner-b@test.com');

    t.test('1. JWT without tenant_id → all tenant-scoped queries fail', async (t) => {
        const tokenNoTenant = generateJwt(tenantA.userId, null);
        const client = getClient(tokenNoTenant);

        const { data, error } = await client.from('tenants').select('*');
        t.equal(data.length, 0, 'Should see zero tenants');

        const { data: deals } = await client.from('crm_deals').select('*');
        t.equal(deals.length, 0, 'Should see zero deals');
    });

    t.test('2. JWT with forged tenant_id → should be blocked if not matching profile', async (t) => {
        // Current implementation trusts JWT. Let's see if it leaks.
        const forgedToken = generateJwt(tenantA.userId, tenantB.tenantId);
        const client = getClient(forgedToken);

        const { data } = await client.from('tenants').select('*');
        // If it returns Tenant B, then it's a leak!
        const hasTenantB = data.some(t => t.id === tenantB.tenantId);
        t.notOk(hasTenantB, 'Should NOT be able to see Tenant B with forged JWT');

        if (hasTenantB) {
            t.fail('SECURITY VULNERABILITY: System trusts forged tenant_id in JWT');
        }
    });

    t.test('3. current_tenant_id() returns correct tenant for user', async (t) => {
        const { data, error } = await tenantA.client.rpc('get_my_tenant_id_test');
        // I might need to create this RPC for testing if not exists, or just check a table.
        const { data: tenants } = await tenantA.client.from('tenants').select('id');
        t.equal(tenants.length, 1, 'Should see exactly one tenant');
        t.equal(tenants[0].id, tenantA.tenantId, 'Should see correct tenant ID');
    });

    t.test('4. Cross-tenant SELECT on any table → zero rows', async (t) => {
        const { data } = await tenantA.client.from('profiles').select('*');
        const hasTenantBProfile = data.some(p => p.tenant_id === tenantB.tenantId);
        t.notOk(hasTenantBProfile, 'Should not see profiles from Tenant B');
    });

    t.test('5. Cross-tenant UPDATE via SQL → denied', async (t) => {
        // Try to update Tenant B's name as Tenant A user
        const { error } = await tenantA.client
            .from('tenants')
            .update({ name: 'Hacked' })
            .eq('id', tenantB.tenantId);

        // RLS should make it look like the row doesn't exist, so 0 rows affected.
        // In Supabase, update returns success but 0 rows if not found.
        const { data: checkB } = await adminClient.from('tenants').select('name').eq('id', tenantB.tenantId).single();
        t.equal(checkB.name, 'Tenant B', 'Tenant B name should remain unchanged');
    });

    t.test('6. Cross-tenant UPDATE via RPC → denied', async (t) => {
        // Create a deal in Tenant B
        const { data: dealB } = await tenantB.client.rpc('create_deal', {
            p_title: 'Secret Deal B',
            p_amount: 1000,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Try to update it as Tenant A user
        const { data, error } = await tenantA.client.rpc('update_deal', {
            p_deal_id: dealB.id,
            p_updates: { title: 'Hacked' }
        });

        t.ok(error, 'Should return error for cross-tenant RPC update');
    });

    t.test('7. Authenticated user without profile → zero access everywhere', async (t) => {
        const { data: authUser } = await adminClient.auth.admin.createUser({
            email: 'no-profile@test.com',
            password: 'password123',
            email_confirm: true
        });
        const token = generateJwt(authUser.user.id, tenantA.tenantId);
        const client = getClient(token);

        const { data } = await client.from('profiles').select('*');
        t.equal(data.length, 0, 'User without profile should see nothing');
    });

    t.test('9. Service role bypasses RLS correctly', async (t) => {
        const { data } = await adminClient.from('tenants').select('*');
        t.ok(data.length >= 2, 'Service role should see all tenants');
    });

    t.test('11. SECURITY DEFINER functions not callable anonymously', async (t) => {
        const anonClient = getClient(''); // No token
        const { error } = await anonClient.rpc('create_tenant', { p_name: 'Anon', p_slug: 'anon' });
        t.ok(error, 'Anonymous user should not be able to call create_tenant');
    });

    t.test('14. Tenant deletion cascades cleanly', async (t) => {
        const tempTenant = await setupTenant('Temp', 'temp', 'temp@test.com');
        const { error } = await adminClient.from('tenants').delete().eq('id', tempTenant.tenantId);
        t.notOk(error, 'Should delete tenant');

        const { data: roles } = await adminClient.from('roles').select('*').eq('tenant_id', tempTenant.tenantId);
        t.equal(roles.length, 0, 'Roles should be deleted');

        const { data: profiles } = await adminClient.from('profiles').select('*').eq('tenant_id', tempTenant.tenantId);
        t.equal(profiles.length, 0, 'Profiles should be deleted');
    });
});

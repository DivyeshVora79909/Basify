import tap from 'tap';
import { adminClient, setupTenant, setupUser, generateJwt, getClient, resetDb } from './test_helper.js';

tap.test('Role Hierarchy Engine (16-30)', async (t) => {
    // Setup: Create tenant and hierarchy
    // Owner (Root)
    //  -> Manager (Child)
    //      -> Employee (Grandchild)
    //  -> Other Manager (Sibling)

    const tenant = await setupTenant('Hierarchy Tenant', 'hierarchy-tenant', 'owner-h@test.com');

    // Get Owner Role ID
    const { data: ownerRole } = await adminClient.from('roles').select('id, path').eq('tenant_id', tenant.tenantId).eq('name', 'Owner').single();

    // Create Manager Role
    const { data: managerRoleData, error: managerError } = await tenant.client.rpc('create_role', {
        p_name: 'Manager A',
        p_parent_role_id: ownerRole.id,
        p_definition_key: 'MANAGER'
    });
    if (managerError) throw managerError;
    const managerRoleId = managerRoleData.id;

    // Create Employee Role
    const { data: employeeRoleData, error: employeeError } = await tenant.client.rpc('create_role', {
        p_name: 'Employee A',
        p_parent_role_id: managerRoleId,
        p_definition_key: 'EMPLOYEE'
    });
    if (employeeError) throw employeeError;
    const employeeRoleId = employeeRoleData.id;

    // Create Sibling Manager
    const { data: managerBData } = await tenant.client.rpc('create_role', {
        p_name: 'Manager B',
        p_parent_role_id: ownerRole.id,
        p_definition_key: 'MANAGER'
    });
    const managerBId = managerBData.id;

    // Setup Users for each role
    const managerA = await setupUser(tenant.tenantId, 'manager-a@test.com', 'Manager A');
    const employeeA = await setupUser(tenant.tenantId, 'employee-a@test.com', 'Employee A');
    const managerB = await setupUser(tenant.tenantId, 'manager-b@test.com', 'Manager B');

    // Grant Permissions to Roles
    const { data: perms } = await adminClient.from('permissions').select('id, slug');
    const createPerm = perms.find(p => p.slug === 'crm.deals.create').id;
    const updatePerm = perms.find(p => p.slug === 'crm.deals.update').id;

    await adminClient.from('role_permissions').insert([
        { role_id: managerA.roleId, permission_id: createPerm },
        { role_id: managerA.roleId, permission_id: updatePerm },
        { role_id: employeeA.roleId, permission_id: createPerm },
        { role_id: managerB.roleId, permission_id: createPerm }
    ]);

    // We need to wait a bit or trigger a refresh if the cache doesn't update immediately.
    // The trigger 'on_custom_perm_change' should handle it.
    // But let's wait a bit just in case.
    await new Promise(resolve => setTimeout(resolve, 500));

    t.test('16. Root role path = single node', async (t) => {
        const { data } = await adminClient.from('roles').select('path').eq('id', ownerRole.id).single();
        t.equal(data.path.split('.').length, 1, 'Owner path should be a single node');
    });

    t.test('17. Child role path = parent.child', async (t) => {
        const { data: manager } = await adminClient.from('roles').select('path').eq('id', managerRoleId).single();
        const { data: owner } = await adminClient.from('roles').select('path').eq('id', ownerRole.id).single();
        t.ok(manager.path.startsWith(owner.path + '.'), 'Manager path should start with owner path');
    });

    t.test('19. Parent @> child works', async (t) => {
        // Create a deal as Employee A
        const { data: deal } = await employeeA.client.rpc('create_deal', {
            p_title: 'Employee Deal',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Manager A should see it
        const { data: managerSee } = await managerA.client.from('crm_deals').select('*').eq('id', deal.id);
        t.equal(managerSee.length, 1, 'Manager A should see Employee A deal');

        // Owner should see it
        const { data: ownerSee } = await tenant.client.from('crm_deals').select('*').eq('id', deal.id);
        t.equal(ownerSee.length, 1, 'Owner should see Employee A deal');
    });

    t.test('21. Two siblings cannot access each other', async (t) => {
        // Create a deal as Manager A
        const { data: dealA } = await managerA.client.rpc('create_deal', {
            p_title: 'Manager A Deal',
            p_amount: 500,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Manager B should NOT see it
        const { data: managerBSee } = await managerB.client.from('crm_deals').select('*').eq('id', dealA.id);
        t.equal(managerBSee.length, 0, 'Manager B should NOT see Manager A deal');
    });

    t.test('23. Descendant cannot access ancestor', async (t) => {
        // Create a deal as Manager A
        const { data: dealA } = await managerA.client.rpc('create_deal', {
            p_title: 'Manager A Deal 2',
            p_amount: 500,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Employee A should NOT see it
        const { data: employeeSee } = await employeeA.client.from('crm_deals').select('*').eq('id', dealA.id);
        t.equal(employeeSee.length, 0, 'Employee A should NOT see Manager A deal');
    });

    t.test('25. Role path immutable without RPC', async (t) => {
        // Try to update path directly
        const { error } = await managerA.client.from('roles').update({ path: 'hacked' }).eq('id', managerRoleId);
        // Should be blocked by REVOKE in 006_write_rpcs.sql
        t.ok(error, 'Direct update to roles should be blocked');
    });
});

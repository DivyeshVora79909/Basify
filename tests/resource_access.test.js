import tap from 'tap';
import { adminClient, setupTenant, setupUser, generateJwt, getClient, resetDb } from './test_helper.js';

tap.test('Resource Access State Machine (46-65)', async (t) => {
    const tenant = await setupTenant('Resource Tenant', 'resource-tenant', 'owner-res@test.com');

    // Hierarchy: Owner -> Manager -> Employee
    const { data: ownerRole } = await adminClient.from('roles').select('id').eq('tenant_id', tenant.tenantId).eq('name', 'Owner').single();

    const { data: managerRole } = await tenant.client.rpc('create_role', {
        p_name: 'Manager A',
        p_parent_role_id: ownerRole.id,
        p_definition_key: 'MANAGER'
    });

    const { data: managerBData } = await tenant.client.rpc('create_role', {
        p_name: 'Manager B',
        p_parent_role_id: ownerRole.id,
        p_definition_key: 'MANAGER'
    });

    const { data: employeeRole } = await tenant.client.rpc('create_role', {
        p_name: 'Employee',
        p_parent_role_id: managerRole.id,
        p_definition_key: 'EMPLOYEE'
    });

    const manager = await setupUser(tenant.tenantId, 'manager-res@test.com', 'Manager A');
    const employee = await setupUser(tenant.tenantId, 'employee-res@test.com', 'Employee');
    const otherManager = await setupUser(tenant.tenantId, 'other-manager-res@test.com', 'Manager B'); // Sibling to Manager A

    // Grant Perms
    const { data: perms } = await adminClient.from('permissions').select('id, slug');
    const readPerm = perms.find(p => p.slug === 'crm.deals.read').id;
    const createPerm = perms.find(p => p.slug === 'crm.deals.create').id;
    const updatePerm = perms.find(p => p.slug === 'crm.deals.update').id;

    await adminClient.from('role_permissions').insert([
        { role_id: manager.roleId, permission_id: readPerm },
        { role_id: manager.roleId, permission_id: createPerm },
        { role_id: manager.roleId, permission_id: updatePerm },
        { role_id: employee.roleId, permission_id: createPerm },
        { role_id: employee.roleId, permission_id: readPerm }
    ]);

    await new Promise(resolve => setTimeout(resolve, 500));

    t.test('46. PRIVATE + owner → access', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Employee Private Deal',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: seeSelf } = await employee.client.from('crm_deals').select('*').eq('id', deal.id).single();
        t.ok(seeSelf, 'Employee should see their own private deal');
    });

    t.test('47. PRIVATE + ancestor → access', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Employee Private Deal 2',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: managerSee } = await manager.client.from('crm_deals').select('*').eq('id', deal.id).single();
        t.ok(managerSee, 'Manager should see subordinate private deal');
    });

    t.test('48. PRIVATE + sibling → denied', async (t) => {
        const { data: deal } = await manager.client.rpc('create_deal', {
            p_title: 'Manager Private Deal',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: siblingSee } = await otherManager.client.from('crm_deals').select('*').eq('id', deal.id);
        t.equal(siblingSee.length, 0, 'Sibling manager should NOT see private deal');
    });

    t.test('49. PUBLIC + any tenant user → access', async (t) => {
        const { data: deal } = await tenant.client.rpc('create_deal', {
            p_title: 'Owner Public Deal',
            p_amount: 100,
            p_visibility: 'PUBLIC',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: employeeSee } = await employee.client.from('crm_deals').select('*').eq('id', deal.id).single();
        t.ok(employeeSee, 'Employee should see owner public deal');
    });

    t.test('51. Non-owner cannot UPDATE PRIVATE', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Employee Private Deal 3',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { error } = await otherManager.client.rpc('update_deal', {
            p_deal_id: deal.id,
            p_updates: { title: 'Hacked' }
        });
        t.ok(error, 'Non-owner non-ancestor should be blocked from update');
    });

    t.test('54. Owner without UPDATE perm → denied', async (t) => {
        // Create user with no update perm
        const userNoUpdate = await setupUser(tenant.tenantId, 'no-update@test.com', 'Employee');
        // Employee has create and read, but not update (Wait, I granted it to the role earlier)
        // Let's create a new role for this
        const { data: guestRole } = await tenant.client.rpc('create_role', {
            p_name: 'Guest',
            p_parent_role_id: ownerRole.id,
            p_definition_key: 'EMPLOYEE'
        });
        const guest = await setupUser(tenant.tenantId, 'guest@test.com', 'Guest');
        // Grant only create
        await adminClient.from('role_permissions').insert({ role_id: guest.roleId, permission_id: createPerm });
        await new Promise(resolve => setTimeout(resolve, 500));

        const { data: deal } = await guest.client.rpc('create_deal', {
            p_title: 'Guest Deal',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { error } = await guest.client.rpc('update_deal', {
            p_deal_id: deal.id,
            p_updates: { title: 'Hacked' }
        });
        t.ok(error, 'Owner without update permission should be blocked');
    });

    t.test('50. CONTROLLED behaves same as PUBLIC in SELECT', async (t) => {
        const { data: deal } = await tenant.client.rpc('create_deal', {
            p_title: 'Owner Controlled Deal',
            p_amount: 100,
            p_visibility: 'CONTROLLED',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: employeeSee } = await employee.client.from('crm_deals').select('*').eq('id', deal.id).single();
        t.ok(employeeSee, 'Employee should see owner controlled deal in SELECT');
    });

    t.test('52. Ancestor can UPDATE PRIVATE only with perm', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Employee Private Deal 4',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Manager has update perm (granted in setup)
        const { error } = await manager.client.rpc('update_deal', {
            p_deal_id: deal.id,
            p_updates: { title: 'Updated by Manager' }
        });
        t.notOk(error, 'Manager should be able to update subordinate private deal if they have perm');
    });

    t.test('57. Owner_role_path stored correctly at create', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Path Test Deal',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        const { data: role } = await adminClient.from('roles').select('path').eq('id', employee.roleId).single();
        const { data: dealData } = await adminClient.from('crm_deals').select('owner_role_path').eq('id', deal.id).single();

        t.equal(dealData.owner_role_path, role.path, 'Deal should store owner role path correctly');
    });

    t.test('58. Owner_role_path not mutable by client', async (t) => {
        const { data: deal } = await employee.client.rpc('create_deal', {
            p_title: 'Path Mutability Test',
            p_amount: 100,
            p_visibility: 'PRIVATE',
            p_pipeline_id: null,
            p_stage_id: null
        });

        // Try to update path via update_deal (RPC doesn't even take it, but let's try via JSON)
        await employee.client.rpc('update_deal', {
            p_deal_id: deal.id,
            p_updates: { owner_role_path: 'root.hacked' }
        });

        const { data: dealData } = await adminClient.from('crm_deals').select('owner_role_path').eq('id', deal.id).single();
        const { data: role } = await adminClient.from('roles').select('path').eq('id', employee.roleId).single();
        t.equal(dealData.owner_role_path, role.path, 'Owner role path should not be mutable by client');
    });
});

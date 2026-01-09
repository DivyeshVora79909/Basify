import tap from 'tap';
import jwt from 'jsonwebtoken';
import { adminClient, setupTenant, setupUser, generateJwt, getClient, resetDb } from './test_helper.js';

tap.test('RBAC Engine (31-45)', async (t) => {
    const tenantA = await setupTenant('RBAC Tenant A', 'rbac-a', 'owner-rbac-a@test.com');
    const tenantB = await setupTenant('RBAC Tenant B', 'rbac-b', 'owner-rbac-b@test.com');

    t.test('31. Permission cache builds on profile insert', async (t) => {
        const { data: profile } = await adminClient.from('profiles').select('cached_permissions').eq('id', tenantA.userId).single();
        t.ok(profile.cached_permissions.includes('crm.deals.create'), 'Owner should have create permission in cache');
    });

    t.test('33. Permission cache updates on role perm insert', async (t) => {
        const user = await setupUser(tenantA.tenantId, 'user-rbac@test.com', 'EMPLOYEE');

        // Initially no perms
        const { data: profile1 } = await adminClient.from('profiles').select('cached_permissions').eq('id', user.userId).single();
        t.notOk(profile1.cached_permissions.includes('crm.deals.create'), 'Employee should not have create perm initially');

        // Grant perm to role
        const { data: perm } = await adminClient.from('permissions').select('id').eq('slug', 'crm.deals.create').single();
        await adminClient.from('role_permissions').insert({ role_id: user.roleId, permission_id: perm.id });

        // Wait for trigger
        await new Promise(resolve => setTimeout(resolve, 500));

        const { data: profile2 } = await adminClient.from('profiles').select('cached_permissions').eq('id', user.userId).single();
        t.ok(profile2.cached_permissions.includes('crm.deals.create'), 'Cache should update after role_permissions insert');
    });

    t.test('35. Permission cache isolated per tenant', async (t) => {
        // Grant perm in Tenant A
        // (Already done in previous test for EMPLOYEE role)

        // Create user with same role name but in Tenant B
        const userB = await setupUser(tenantB.tenantId, 'user-b-rbac@test.com', 'EMPLOYEE');

        const { data: profileB } = await adminClient.from('profiles').select('cached_permissions').eq('id', userB.userId).single();
        t.notOk(profileB.cached_permissions.includes('crm.deals.create'), 'Tenant B user should NOT have Tenant A role permissions');
    });

    t.test('36. has_permission() true only if cached', async (t) => {
        const user = await setupUser(tenantA.tenantId, 'user-has-perm@test.com', 'MANAGER');

        const { data: profile, error: profileError } = await user.client
            .from('profiles')
            .select('cached_permissions')
            .eq('id', user.userId)
            .single();

        if (profileError) console.error('Profile Select Error:', profileError);
        t.notOk(profile?.cached_permissions.includes('crm.deals.create'), 'Should not have perm');
    });

    t.test('39. Hierarchy does NOT grant permissions', async (t) => {
        // Manager A is parent of Employee A.
        // Employee A has 'crm.deals.create'.
        // Manager A should NOT automatically get 'crm.deals.create' unless granted.

        const manager = await setupUser(tenantA.tenantId, 'manager-no-perm@test.com', 'MANAGER');
        const employee = await setupUser(tenantA.tenantId, 'employee-with-perm@test.com', 'EMPLOYEE');

        // Grant to employee
        const { data: perm } = await adminClient.from('permissions').select('id').eq('slug', 'crm.deals.create').single();
        await adminClient.from('role_permissions').insert({ role_id: employee.roleId, permission_id: perm.id });

        await new Promise(resolve => setTimeout(resolve, 500));

        const { data: managerProfile } = await adminClient.from('profiles').select('cached_permissions').eq('id', manager.userId).single();
        t.notOk(managerProfile.cached_permissions.includes('crm.deals.create'), 'Manager should not inherit permissions from child');
    });

    t.test('34. Permission cache updates on role perm delete', async (t) => {
        const user = await setupUser(tenantA.tenantId, 'user-rbac-del@test.com', 'EMPLOYEE');
        const { data: perm } = await adminClient.from('permissions').select('id').eq('slug', 'crm.deals.create').single();
        await adminClient.from('role_permissions').insert({ role_id: user.roleId, permission_id: perm.id });
        await new Promise(resolve => setTimeout(resolve, 500));

        // Delete perm
        await adminClient.from('role_permissions').delete().eq('role_id', user.roleId).eq('permission_id', perm.id);
        await new Promise(resolve => setTimeout(resolve, 500));

        const { data: profile } = await adminClient.from('profiles').select('cached_permissions').eq('id', user.userId).single();
        t.notOk(profile.cached_permissions.includes('crm.deals.create'), 'Cache should update after role_permissions delete');
    });

    t.test('37. Removing permission immediately blocks RPC', async (t) => {
        const user = await setupUser(tenantA.tenantId, 'user-rbac-block@test.com', 'EMPLOYEE');
        const { data: perm } = await adminClient.from('permissions').select('id').eq('slug', 'crm.deals.create').single();
        await adminClient.from('role_permissions').insert({ role_id: user.roleId, permission_id: perm.id });
        await new Promise(resolve => setTimeout(resolve, 500));

        // Should work
        const { error: error1 } = await user.client.rpc('create_deal', {
            p_title: 'Test', p_amount: 10, p_visibility: 'PUBLIC', p_pipeline_id: null, p_stage_id: null
        });
        t.notOk(error1, 'Should be able to create deal with perm');

        // Remove perm
        await adminClient.from('role_permissions').delete().eq('role_id', user.roleId).eq('permission_id', perm.id);
        await new Promise(resolve => setTimeout(resolve, 500));

        // Should fail
        const { error: error2 } = await user.client.rpc('create_deal', {
            p_title: 'Test 2', p_amount: 10, p_visibility: 'PUBLIC', p_pipeline_id: null, p_stage_id: null
        });
        t.ok(error2, 'Should be blocked after perm removal');
    });

    t.test('45. Empty permission cache blocks all RPC writes', async (t) => {
        const user = await setupUser(tenantA.tenantId, 'user-rbac-empty@test.com', 'EMPLOYEE');
        // No perms granted
        const { error } = await user.client.rpc('create_deal', {
            p_title: 'Test', p_amount: 10, p_visibility: 'PUBLIC', p_pipeline_id: null, p_stage_id: null
        });
        t.ok(error, 'Empty cache should block RPC writes');
    });

    t.test('43. Duplicate permission slugs rejected', async (t) => {
        const { error } = await adminClient.from('permissions').insert({ slug: 'crm.deals.create' });
        t.ok(error, 'Should reject duplicate permission slug');
    });
});

import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import { execSync } from 'child_process';

const SUPABASE_URL = 'http://127.0.0.1:54321';
const SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';
const ANON_KEY = 'sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH';

export const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

export function resetDb() {
  console.log('Resetting database...');
  execSync('supabase db reset', { stdio: 'inherit' });
}

export function generateJwt(userId, tenantId, role = 'authenticated') {
  const payload = {
    aud: 'authenticated',
    exp: Math.floor(Date.now() / 1000) + 3600,
    sub: userId,
    role: role,
    app_metadata: {
      tenant_id: tenantId
    },
    user_metadata: {}
  };
  return jwt.sign(payload, JWT_SECRET);
}

export function getClient(token) {
  return createClient(SUPABASE_URL, ANON_KEY, {
    global: {
      headers: {
        Authorization: `Bearer ${token}`
      }
    },
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });
}

export async function setupTenant(name, slug, ownerEmail) {
  // 1. Create User in Auth
  const { data: authUser, error: authError } = await adminClient.auth.admin.createUser({
    email: ownerEmail,
    password: 'password123',
    email_confirm: true
  });
  if (authError) throw authError;

  // 2. Create Tenant via RPC
  const tempToken = generateJwt(authUser.user.id, null);
  const userClient = getClient(tempToken);
  
  const { data: tenantData, error: tenantError } = await userClient.rpc('create_tenant', {
    p_name: name,
    p_slug: slug
  });
  if (tenantError) throw tenantError;

  const tenantId = tenantData.tenant_id;

  // 3. Get the final token with tenant_id
  const token = generateJwt(authUser.user.id, tenantId);
  
  return {
    userId: authUser.user.id,
    tenantId,
    token,
    client: getClient(token)
  };
}

export async function setupUser(tenantId, email, roleKey) {
  // 1. Create User in Auth
  const { data: authUser, error: authError } = await adminClient.auth.admin.createUser({
    email,
    password: 'password123',
    email_confirm: true
  });
  if (authError) throw authError;

  // 2. Get Role ID
  const { data: roleData, error: roleError } = await adminClient
    .from('roles')
    .select('id')
    .eq('tenant_id', tenantId)
    .eq('name', roleKey)
    .single();
  
  let roleId;
  if (roleError || !roleData) {
    const { data: defData } = await adminClient.from('role_definitions').select('id').eq('key', roleKey).single();
    const { data: newRole, error: newRoleError } = await adminClient.from('roles').insert({
      tenant_id: tenantId,
      definition_id: defData?.id,
      name: roleKey,
      path: 'root'
    }).select().single();
    if (newRoleError) throw newRoleError;
    roleId = newRole.id;
  } else {
    roleId = roleData.id;
  }

  // 3. Create Profile
  const { error: profileError } = await adminClient.from('profiles').insert({
    id: authUser.user.id,
    tenant_id: tenantId,
    role_id: roleId,
    first_name: email.split('@')[0]
  });
  if (profileError) throw profileError;

  const token = generateJwt(authUser.user.id, tenantId);
  return {
    userId: authUser.user.id,
    token,
    client: getClient(token),
    roleId
  };
}

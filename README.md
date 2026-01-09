# Basify

A production-grade, multi-tenant SaaS starter kit built on Supabase (PostgreSQL). It features a robust **Hierarchical RBAC (Role-Based Access Control)** system using `ltree` for organizational structure, **ReBAC (Relationship-Based Access Control)** for resources (Deals), and **Permission Caching** for high performance.

---

## 🏛️ Architecture Crash Course

1. **Multi-Tenancy:** Isolated data using `tenant_id` in every table.
2. **Hierarchy (Ltree):** Roles are organized in a tree structure (e.g., Owner > Manager > Employee). We use PostgreSQL's `ltree` extension to store paths like `root.owner_uuid.manager_uuid`.
3. **Resource Security:**
   - **Visibility:** Deals have `PRIVATE`, `PUBLIC`, or `CONTROLLED`.
   - **Inheritance:** A manager can see deals created by their subordinates (downstream visibility).
4. **Performance:**
   - **Permissions:** Calculated and stored in `cached_permissions` array on the `profiles` table. Triggers update this automatically. This allows permission checks to be an O(1) database index lookup.
   - **Hierarchy Checks:** Uses GIST indexes on `ltree` paths for instant ancestor/descendant lookups.

---

## 📂 Project File Breakdown

This section explains the specific function of each migration file in order of execution.

| File                           | Function & Details                                                                                                                                                                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`001_setup.sql`**            | **Core Infrastructure.** Enables `pgcrypto` (UUIDs) and `ltree` (Hierarchy). Creates an internal schema `app_internal` to hide helper logic. Creates `uuid_to_ltree` to sanitize UUIDs for path storage.                            |
| **`002_core_schema.sql`**      | **The Skeleton.** Defines `tenants`, `roles` (with `ltree` path), `profiles`, and `invitations`. Crucially, it adds `cached_permissions` to profiles and indexes it with GIN for fast searching.                                    |
| **`003_resource_schema.sql`**  | **The Business Data.** Defines `crm_pipelines`, `crm_stages`, and `crm_deals`. Includes `owner_role_path` on deals to denormalize the hierarchy for ultra-fast read access (RLS).                                                   |
| **`004_security_helpers.sql`** | **The Brain.** Contains logic to identify the current user (`current_tenant_id`), check permissions (`has_permission`), and build the permission cache (`build_user_permissions`).                                                  |
| **`005_rls_policies.sql`**     | **The Shield.** Enables Row Level Security (RLS). Policies ensure users only see data belonging to their tenant and respect the hierarchy logic (e.g., Managers see Subordinate deals).                                             |
| **`006_write_rpcs.sql`**       | **Controlled Writes.** Revokes direct insert/update permissions. Forces data changes through Stored Procedures (RPCs) like `create_deal` or `update_deal`. Sets up triggers to auto-refresh the permission cache when roles change. |
| **`007_auth_hook.sql`**        | **The Passport.** A Postgres Auth hook that injects the `tenant_id` into the user's JWT (`app_metadata`) upon login.                                                                                                                |
| **`008_frontend_helper.sql`**  | **One-Shot Loader.** `get_user_session_context()` fetches the user's profile, role, permissions, and tenant info in a single query for efficient app initialization.                                                                |
| **`009_seed_data.sql`**        | **Defaults.** Seeds standard permissions (`crm.deals.read`) and role definitions (`TENANT_OWNER`, `MANAGER`).                                                                                                                       |
| **`010_org_management.sql`**   | **HR Logic.** RPCs to create sub-roles (`create_role`) and invite users (`invite_user`). Handles the logic of building the hierarchy tree.                                                                                          |
| **`011_platform_admin.sql`**   | **God Mode.** Functions strictly for the `service_role` (Server Side) to provision new tenants (`admin_provision_tenant`) and send the first invite.                                                                                |
| **`config.toml`**              | **Supabase Config.** Local environment settings, port mappings, and email auth configuration.                                                                                                                                       |
| **`storage_config.json`**      | **Storage Buckets.** Defines private storage for CRM attachments (PDFs, Images).                                                                                                                                                    |

---

## 📚 API Reference (RPC Functions)

These are the functions you can call from your frontend (or backend) via `supabase.rpc()`.

### Organization & Admin

| Function                 | Arguments                                                             | Description                                                                                                                            |
| ------------------------ | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `admin_provision_tenant` | `p_name` (text), `p_slug` (text)                                      | **(Platform Admin Only)** Creates a new tenant, the "Owner" role, and default Sales Pipeline. Returns `tenant_id` and `owner_role_id`. |
| `admin_invite_user`      | `p_tenant_id` (uuid), `p_role_id` (uuid), `p_email` (text)            | **(Platform Admin Only)** Sends an invitation to a user to join a specific tenant as a specific role.                                  |
| `create_role`            | `p_name` (text), `p_parent_role_id` (uuid), `p_definition_key` (text) | Creates a new role (e.g., "Sales Lead") nested under a parent role. Links to a definition like 'MANAGER'.                              |
| `invite_user`            | `p_email` (text), `p_role_id` (uuid)                                  | Invites a user to the current tenant. Requires `sys.roles.manage` permission.                                                          |
| `accept_invitation`      | `p_invite_id` (uuid)                                                  | Called by a user to join a tenant. Creates their profile and sets their permission cache.                                              |

### CRM (Deals)

| Function      | Arguments                                                            | Description                                                                                           |
| ------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `create_deal` | `p_title`, `p_amount`, `p_visibility`, `p_pipeline_id`, `p_stage_id` | Creates a new deal. Sets `owner_id` to current user and `owner_role_path` to user's role path.        |
| `update_deal` | `p_deal_id` (uuid), `p_updates` (jsonb)                              | Updates a deal. Checks hierarchy (can update own deals or subordinate deals depending on visibility). |

### Utilities

| Function                      | Arguments            | Returns   | Description                                                                                                  |
| ----------------------------- | -------------------- | --------- | ------------------------------------------------------------------------------------------------------------ |
| `get_user_session_context`    | None                 | `jsonb`   | Returns user profile, role details, permissions array, and tenant ID. Use this to populate global app state. |
| `has_permission` _(internal)_ | `p_perm_slug` (text) | `boolean` | Checks if the current user's cached permissions contain the specific slug.                                   |

---

## 🚀 Getting Started & First Tenant Creation

Since this is a multi-tenant system with a platform admin layer, you cannot simply "sign up" in the UI to create a tenant initially. You must use the **Platform Admin RPCs**.

### 1\. Start Local Supabase

Ensure you have the CLI installed and run:

    supabase start

Apply the migrations:

    supabase db reset

### 2\. Create the First Tenant (The "Acme Corp" Workflow)

Run this script in your **Supabase SQL Editor** (or via `psql`). This script simulates a "Platform Admin" context to provision the infrastructure and invite the first CEO.

    -- Step 1: PROVISION TENANT
    -- We mock the JWT to pretend we are the Service Role (Super Admin)
    DO $$ DECLARE
        v_provision_result jsonb;
        v_tenant_id uuid;
        v_role_id uuid;
        v_invite_result jsonb;
    BEGIN
        -- 1. MOCK SECURITY CONTEXT
        -- This tricks the DB into thinking the request came from the Service Role key
        PERFORM set_config('request.jwt.claims', '{"role": "service_role"}', true);

        -- 2. PROVISION TENANT
        -- Creates 'Acme Corp', the Owner Role, and Default Pipelines
        v_provision_result := public.admin_provision_tenant('Acme Corp', 'acme');

        -- Extract IDs
        v_tenant_id := (v_provision_result->>'tenant_id')::uuid;
        v_role_id := (v_provision_result->>'owner_role_id')::uuid;

        RAISE NOTICE 'Tenant Created ID: %, Owner Role ID: %', v_tenant_id, v_role_id;

        -- 3. INVITE THE CEO
        -- Invite 'ceo@acme.com' to the Owner Role we just created
        v_invite_result := public.admin_invite_user(v_tenant_id, v_role_id, 'ceo@acme.com');

        RAISE NOTICE 'Invitation sent. Result: %', v_invite_result;

    END $$;

### 3\. Verify the Setup

    -- Check that the tenant, role, and invite exist
    SELECT 'Tenant' as type, name, slug FROM public.tenants WHERE slug = 'acme'
    UNION ALL
    SELECT 'Role', name, path::text FROM public.roles WHERE name = 'Owner'
    UNION ALL
    SELECT 'Invite', email, status::text FROM public.invitations WHERE email = 'ceo@acme.com';

### 4\. Accept Invitation (Simulate User Registration)

When the user clicks the link in the email (frontend), you call `accept_invitation`. To simulate this in the SQL Editor:

    DO $$ DECLARE
        v_user_id uuid := gen_random_uuid(); -- Simulating a new Auth User ID
        v_email text := 'ceo@acme.com';
        v_invite_id uuid;
        v_success boolean;
    BEGIN
        -- 1. Create Mock Auth User
        INSERT INTO auth.users (id, email, aud, role)
        VALUES (v_user_id, v_email, 'authenticated', 'authenticated');

        -- 2. Get the Pending Invite
        SELECT id INTO v_invite_id FROM public.invitations
        WHERE email = v_email AND status = 'pending';

        -- 3. Mock Login Context (Set UID)
        PERFORM set_config('request.jwt.claims', json_build_object('sub', v_user_id, 'role', 'authenticated', 'email', v_email)::text, true);

        -- 4. Accept Invite
        -- This creates the Profile, builds the Role Path, and Caches Permissions automatically via triggers!
        v_success := public.accept_invitation(v_invite_id);

        RAISE NOTICE 'Success! User % is now the Owner of Acme Corp.', v_user_id;
    END $$;

---

## 🛠️ Supabase CLI Cheat Sheet

Useful commands for local development.

Command

Description

`supabase start`

Starts the local Docker stack (DB, Studio, GoTrue, etc.).

`supabase stop`

Stops the stack.

`supabase db reset`

**Dangerous.** Drops the local DB and reapplies all migrations. Great for fresh starts.

`supabase db diff`

Generates a new migration file based on changes made to the local DB (via Studio).

`supabase migration new <name>`

Creates a new empty timestamped migration file.

`supabase gen types typescript`

Generates TS types for your database schema.

`supabase link --project-ref <ref>`

Links your local folder to a remote Supabase project.

`supabase db push`

Pushes local migrations to the remote project.

---

## 🕵️ SQL Editor Scripts (Inspection & Debugging)

Run these in the Supabase Dashboard SQL Editor to inspect the state of your app.

### 1\. Check Current User Context (Who am I?)

    SELECT * FROM public.get_user_session_context();

_Returns: Tenant ID, Role Name, Role Path, and all Permission Slugs._

### 2\. Inspect the Role Hierarchy Tree

    SELECT
        r.name,
        r.path::text as role_path,
        rd.name as definition,
        (SELECT COUNT(*) FROM public.profiles p WHERE p.role_id = r.id) as user_count
    FROM public.roles r
    LEFT JOIN public.role_definitions rd ON r.definition_id = rd.id
    ORDER BY r.path;

### 3\. Check Permission Cache for a Specific User

    SELECT
        p.first_name,
        p.email,
        r.name as role_name,
        p.cached_permissions
    FROM public.profiles p
    JOIN auth.users u ON p.id = u.id
    JOIN public.roles r ON p.role_id = r.id
    WHERE u.email = 'ceo@acme.com'; -- Change email

### 4\. Visualize Deal Access (Who can see what?)

    SELECT
        d.title,
        d.visibility,
        u.email as owner_email,
        d.owner_role_path::text as hierarchy_path
    FROM public.crm_deals d
    LEFT JOIN auth.users u ON d.owner_id = u.id;

### 5\. Audit RLS Policies

    SELECT
        schemaname,
        tablename,
        policyname,
        permissive,
        roles,
        cmd,
        qual
    FROM pg_policies
    WHERE schemaname = 'public';

Here are the remaining optimizations to handle hyper-scale (millions of users/rows):

Asynchronous Cache Propagation (Critical):

The Issue: Your new triggers (propagate_definition_perm_change) run synchronously. If you change a permission for a role with 100,000 assigned users, the database will try to update 100,000 rows in a single transaction, locking the table and potentially timing out.

The Fix: Move this logic to a Job Queue (using pg_net to call an Edge Function or pg_mq). The trigger should just queue a "Refresh Role X" job, and a background worker handles the mass updates in batches.

Table Partitioning:

The Issue: As crm_deals grows to billions of rows, indexes become huge and slow.

The Fix: Implement Native Postgres Partitioning by tenant_id. This physically splits the table so queries for Tenant A never even look at Tenant B's data storage.

Read Replicas:

The Issue: A single primary database handles both Reads and Writes.

The Fix: Configure Supabase to use Read Replicas. Point your frontend's "Read" queries to the replica and keeping RPC "Writes" on the primary.

Audit Logging:

The Issue: You have no record of who changed a deal or permission.

The Fix: Create an immutable audit_logs table and use triggers to record every INSERT/UPDATE/DELETE with the auth.uid(), tenant_id, and old/new values.

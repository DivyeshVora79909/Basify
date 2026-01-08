-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- 2. ENUMS
CREATE TYPE public.visibility_mode AS ENUM ('PRIVATE', 'PUBLIC', 'CONTROLLED');
CREATE TYPE public.invitation_status AS ENUM ('pending', 'accepted', 'expired');
CREATE TYPE public.crm_stage_category AS ENUM ('OPEN', 'WON', 'LOST');

-- 3. INTERNAL SCHEMA (Security through obscurity for helper functions)
CREATE SCHEMA IF NOT EXISTS app_internal;
GRANT USAGE ON SCHEMA app_internal TO authenticated;
GRANT USAGE ON SCHEMA app_internal TO service_role;

-- 4. CRITICAL UTILITY: UUID to LTREE
-- Ltree does not support dashes. This standardizes the conversion.
CREATE OR REPLACE FUNCTION app_internal.uuid_to_ltree(p_id uuid)
RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
    SELECT translate(p_id::text, '-', '_');
$$;
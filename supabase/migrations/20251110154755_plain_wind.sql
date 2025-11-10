/*
  # Database Security Fixes

  This migration addresses multiple security and performance issues:

  ## 1. Missing Indexes on Foreign Keys
  - Add indexes on user_id columns for all tables to improve query performance
  - These indexes will speed up JOIN operations and foreign key constraint checks

  ## 2. RLS Policy Optimization
  - Replace auth.uid() with (select auth.uid()) in all RLS policies
  - This prevents re-evaluation of auth functions for each row, improving performance at scale

  ## 3. Function Security
  - Fix search_path for update_updated_at_column function to prevent security vulnerabilities

  ## 4. Performance Improvements
  - All changes focus on maintaining security while improving query performance
*/

-- Add missing indexes on foreign key columns for better query performance
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON public.user_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON public.chat_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_medical_files_user_id ON public.medical_files(user_id);
CREATE INDEX IF NOT EXISTS idx_health_assessments_user_id ON public.health_assessments(user_id);

-- Drop existing RLS policies that use inefficient auth.uid() calls
DROP POLICY IF EXISTS "Users can read own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can manage own chat sessions" ON public.chat_sessions;
DROP POLICY IF EXISTS "Users can manage own medical files" ON public.medical_files;
DROP POLICY IF EXISTS "Users can manage own health assessments" ON public.health_assessments;

-- Create optimized RLS policies using (select auth.uid()) for better performance
CREATE POLICY "Users can read own profile"
  ON public.user_profiles
  FOR SELECT
  TO authenticated
  USING ((select auth.uid()) = user_id);

CREATE POLICY "Users can insert own profile"
  ON public.user_profiles
  FOR INSERT
  TO authenticated
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can update own profile"
  ON public.user_profiles
  FOR UPDATE
  TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can manage own chat sessions"
  ON public.chat_sessions
  FOR ALL
  TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can manage own medical files"
  ON public.medical_files
  FOR ALL
  TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "Users can manage own health assessments"
  ON public.health_assessments
  FOR ALL
  TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

-- Fix function security by recreating with proper search_path
DROP FUNCTION IF EXISTS public.update_updated_at_column();

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

-- Ensure the function has proper permissions
REVOKE ALL ON FUNCTION public.update_updated_at_column() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.update_updated_at_column() TO authenticated;
GRANT EXECUTE ON FUNCTION public.update_updated_at_column() TO service_role;

-- Add additional performance indexes for commonly queried columns
CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated_at ON public.chat_sessions(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_type ON public.chat_sessions(type);
CREATE INDEX IF NOT EXISTS idx_medical_files_created_at ON public.medical_files(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_medical_files_category ON public.medical_files(category);
CREATE INDEX IF NOT EXISTS idx_health_assessments_created_at ON public.health_assessments(created_at DESC);

-- Add composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_type_updated ON public.chat_sessions(user_id, type, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_medical_files_user_category_created ON public.medical_files(user_id, category, created_at DESC);
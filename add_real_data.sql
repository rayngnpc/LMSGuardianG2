-- ============================================================================
-- LMS Guardian v2 - Add Real Data Script  
-- ACTUAL COURSE DATA FOR PRODUCTION
-- ============================================================================
-- 
-- This contains the real course data for production use
-- Run this AFTER running cleanup_example_data.sql
--
-- ============================================================================

BEGIN;

-- ============================================================================
-- ADD YOUR REAL UNIT COORDINATORS
-- ============================================================================

-- Replace with your actual unit coordinators
INSERT INTO unit_coordinators (full_name, email) VALUES
    ('Peter Col', 'npchau95@gmail.com');

-- ============================================================================
-- ADD YOUR REAL MODULES/COURSES
-- ============================================================================

-- Replace with your actual course modules
-- Format: (uc_id, module_name, teaching_period, semester, module_description, unit_code)
INSERT INTO modules (uc_id, module_name, teaching_period, semester, module_description, unit_code) VALUES
    (1, 'BSC203 Introduction to ICT Research Methods', 'Semester 1', '2025', 'Introduction to research methods and practices in ICT.', 'BSC203'),
    (1, 'ICT280 Information Security Policy and Governance', 'Semester 1', '2025', 'Information security policy development and governance frameworks.', 'ICT280');

-- ============================================================================
-- VERIFICATION
-- ============================================================================

-- Show the new real data
SELECT 'New Unit Coordinators:' as info;
SELECT uc_id, full_name, email FROM unit_coordinators;

SELECT 'New Modules:' as info;
SELECT module_id, uc_id, module_name, unit_code, teaching_period, semester FROM modules;

SELECT 'Database ready with real data!' as status;

COMMIT;

-- ============================================================================
-- CUSTOMIZATION INSTRUCTIONS
-- ============================================================================

-- TO CUSTOMIZE THIS SCRIPT FOR YOUR NEEDS:
--
-- 1. Update Unit Coordinators section:
--    - Replace names and email addresses with real coordinators
--    - Add or remove coordinators as needed
--
-- 2. Update Modules section:
--    - Replace module names with your actual course names
--    - Update unit codes to match your real course codes
--    - Update teaching periods and semesters to current values
--    - Add or remove modules as needed
--    - Make sure uc_id references match the coordinators above
--
-- 3. Save and run:
--    psql -h localhost -U admin -d lmsguardian -f add_real_data.sql

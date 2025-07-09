-- ============================================================================
-- LMS Guardian v2 - Add Real Data Script
-- TEMPLATE FOR YOUR ACTUAL COURSE DATA
-- ============================================================================
-- 
-- Replace the example data below with your real course information
-- Run this AFTER running cleanup_example_data.sql
--
-- ============================================================================

BEGIN;

-- ============================================================================
-- ADD YOUR REAL UNIT COORDINATORS
-- ============================================================================

-- Replace with your actual unit coordinators
INSERT INTO unit_coordinators (full_name, email) VALUES
    ('Dr. Your Real Name', 'your.real.email@university.edu'),
    ('Prof. Another Coordinator', 'another.coordinator@university.edu');

-- ============================================================================
-- ADD YOUR REAL MODULES/COURSES
-- ============================================================================

-- Replace with your actual course modules
-- Format: (uc_id, module_name, teaching_period, semester, module_description, unit_code)
INSERT INTO modules (uc_id, module_name, teaching_period, semester, module_description, unit_code) VALUES
    (1, 'Your Real Course Name 1', 'Current Teaching Period', 'Current Semester', 'Real course description here', 'REAL001'),
    (2, 'Your Real Course Name 2', 'Current Teaching Period', 'Current Semester', 'Another real course description', 'REAL002');

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

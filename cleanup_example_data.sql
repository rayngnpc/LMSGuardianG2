-- ============================================================================
-- LMS Guardian v2 - Database Cleanup Script
-- REMOVE EXAMPLE DATA AND RESET FOR REAL DATA
-- ============================================================================
-- 
-- This script removes all the example/test data and prepares the database
-- for your real course data.
--
-- ⚠️  WARNING: This will delete all existing data!
-- Only run this if you want to start fresh with real data.
--
-- ============================================================================

BEGIN;

-- ============================================================================
-- REMOVE ALL EXISTING DATA
-- ============================================================================

-- Delete in correct order due to foreign key constraints
DELETE FROM scraped_contents;
DELETE FROM modules;
DELETE FROM unit_coordinators;
DELETE FROM scraper_sessions;

-- Reset sequences to start from 1
ALTER SEQUENCE unit_coordinators_uc_id_seq RESTART WITH 1;
ALTER SEQUENCE modules_module_id_seq RESTART WITH 1;
ALTER SEQUENCE scraper_sessions_session_id_seq RESTART WITH 1;
ALTER SEQUENCE scraped_contents_scraped_id_seq RESTART WITH 1;

-- ============================================================================
-- VERIFICATION
-- ============================================================================

-- Show that tables are now empty
SELECT 'unit_coordinators' as table_name, COUNT(*) as row_count FROM unit_coordinators
UNION ALL
SELECT 'modules' as table_name, COUNT(*) as row_count FROM modules
UNION ALL
SELECT 'scraper_sessions' as table_name, COUNT(*) as row_count FROM scraper_sessions
UNION ALL
SELECT 'scraped_contents' as table_name, COUNT(*) as row_count FROM scraped_contents;

SELECT 'Database cleaned successfully - ready for real data' as status;

COMMIT;

-- ============================================================================
-- NEXT STEPS
-- ============================================================================

-- After running this script:
-- 1. Add your real unit coordinators using the API or directly:
--    INSERT INTO unit_coordinators (full_name, email) VALUES ('Real Name', 'real.email@domain.com');
--
-- 2. Add your real modules using the API or directly:
--    INSERT INTO modules (uc_id, module_name, teaching_period, semester, module_description, unit_code)
--    VALUES (1, 'Your Real Course Name', 'Current Period', 'Current Semester', 'Real Description', 'REAL_CODE');
--
-- 3. Run your scraper to populate with real data:
--    python scraper/main.py
--
-- 4. Your application will now work with clean, real data!

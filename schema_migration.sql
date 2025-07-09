-- ============================================================================
-- LMS Guardian v2 Database Migration Script
-- SAFE UPDATE FOR EXISTING DATABASES
-- ============================================================================
-- 
-- This script safely updates an existing database to match the current
-- application models WITHOUT losing existing data.
-- 
-- Use this script when you have existing data that you want to preserve.
-- For fresh installations, use schema.sql instead.
--
-- ============================================================================

-- Begin transaction for atomic operations
BEGIN;

-- ============================================================================
-- BACKUP RECOMMENDATIONS
-- ============================================================================
-- Before running this script, create a backup:
-- pg_dump -U your_username -h localhost -p 5432 your_database > backup_$(date +%Y%m%d_%H%M%S).sql

-- ============================================================================
-- SAFE COLUMN ADDITIONS
-- ============================================================================

-- Function to safely add columns if they don't exist
CREATE OR REPLACE FUNCTION add_column_if_not_exists(table_name_param text, column_name_param text, column_definition text)
RETURNS void AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = table_name_param AND column_name = column_name_param
    ) THEN
        EXECUTE format('ALTER TABLE %I ADD COLUMN %I %s', table_name_param, column_name_param, column_definition);
        RAISE NOTICE 'Added column % to table %', column_name_param, table_name_param;
    ELSE
        RAISE NOTICE 'Column % already exists in table %', column_name_param, table_name_param;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to safely modify column types
CREATE OR REPLACE FUNCTION modify_column_type_if_needed(table_name_param text, column_name_param text, new_type text)
RETURNS void AS $$
DECLARE
    current_type text;
BEGIN
    SELECT data_type INTO current_type
    FROM information_schema.columns 
    WHERE table_name = table_name_param AND column_name = column_name_param;
    
    IF current_type IS NULL THEN
        RAISE NOTICE 'Column % does not exist in table %', column_name_param, table_name_param;
        RETURN;
    END IF;
    
    IF current_type != new_type THEN
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE %s', table_name_param, column_name_param, new_type);
        RAISE NOTICE 'Changed column % in table % from % to %', column_name_param, table_name_param, current_type, new_type;
    ELSE
        RAISE NOTICE 'Column % in table % already has correct type %', column_name_param, table_name_param, new_type;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SCHEMA UPDATES TO MATCH APPLICATION MODELS
-- ============================================================================

-- Update unit_coordinators table
-- Note: Remove created_at/updated_at columns if they exist (not in model)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'unit_coordinators' AND column_name = 'created_at') THEN
        ALTER TABLE unit_coordinators DROP COLUMN created_at;
        RAISE NOTICE 'Removed created_at column from unit_coordinators';
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'unit_coordinators' AND column_name = 'updated_at') THEN
        ALTER TABLE unit_coordinators DROP COLUMN updated_at;
        RAISE NOTICE 'Removed updated_at column from unit_coordinators';
    END IF;
END
$$;

-- Update modules table to match model exactly
SELECT modify_column_type_if_needed('modules', 'teaching_period', 'VARCHAR(255)');
SELECT modify_column_type_if_needed('modules', 'semester', 'VARCHAR(255)');
SELECT modify_column_type_if_needed('modules', 'module_description', 'VARCHAR(255)');
SELECT modify_column_type_if_needed('modules', 'unit_code', 'VARCHAR(255)');

-- Remove extra columns from modules if they exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'created_at') THEN
        ALTER TABLE modules DROP COLUMN created_at;
        RAISE NOTICE 'Removed created_at column from modules';
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'updated_at') THEN
        ALTER TABLE modules DROP COLUMN updated_at;
        RAISE NOTICE 'Removed updated_at column from modules';
    END IF;
END
$$;

-- Update scraper_sessions table
-- Remove created_at if it exists (not in model)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'scraper_sessions' AND column_name = 'created_at') THEN
        ALTER TABLE scraper_sessions DROP COLUMN created_at;
        RAISE NOTICE 'Removed created_at column from scraper_sessions';
    END IF;
END
$$;

-- Update scraped_contents table
-- Remove created_at if it exists (not in model)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'scraped_contents' AND column_name = 'created_at') THEN
        ALTER TABLE scraped_contents DROP COLUMN created_at;
        RAISE NOTICE 'Removed created_at column from scraped_contents';
    END IF;
END
$$;

-- Remove default values that don't exist in models
DO $$
BEGIN
    -- Remove default from scraped_at in scraped_contents
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scraped_contents' 
        AND column_name = 'scraped_at' 
        AND column_default IS NOT NULL
    ) THEN
        ALTER TABLE scraped_contents ALTER COLUMN scraped_at DROP DEFAULT;
        RAISE NOTICE 'Removed default value from scraped_at in scraped_contents';
    END IF;
    
    -- Remove default from url_link in scraped_contents  
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scraped_contents' 
        AND column_name = 'url_link' 
        AND column_default IS NOT NULL
    ) THEN
        ALTER TABLE scraped_contents ALTER COLUMN url_link DROP DEFAULT;
        RAISE NOTICE 'Removed default value from url_link in scraped_contents';
    END IF;
    
    -- Remove default from risk_score in scraped_contents
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scraped_contents' 
        AND column_name = 'risk_score' 
        AND column_default IS NOT NULL
    ) THEN
        ALTER TABLE scraped_contents ALTER COLUMN risk_score DROP DEFAULT;
        RAISE NOTICE 'Removed default value from risk_score in scraped_contents';
    END IF;
    
    -- Remove default from risk_category in scraped_contents
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'scraped_contents' 
        AND column_name = 'risk_category' 
        AND column_default IS NOT NULL
    ) THEN
        ALTER TABLE scraped_contents ALTER COLUMN risk_category DROP DEFAULT;
        RAISE NOTICE 'Removed default value from risk_category in scraped_contents';
    END IF;
END
$$;

-- ============================================================================
-- FOREIGN KEY CONSTRAINT UPDATES
-- ============================================================================

-- Update constraint names to match the new schema
DO $$
BEGIN
    -- Drop old constraint names and recreate with standard names
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'modules' AND constraint_name = 'fk_uc'
    ) THEN
        ALTER TABLE modules DROP CONSTRAINT fk_uc;
        ALTER TABLE modules ADD CONSTRAINT fk_modules_uc_id FOREIGN KEY (uc_id) REFERENCES unit_coordinators (uc_id) ON DELETE CASCADE;
        RAISE NOTICE 'Updated foreign key constraint name in modules table';
    END IF;
    
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'scraped_contents' AND constraint_name = 'fk_module_scraped'
    ) THEN
        ALTER TABLE scraped_contents DROP CONSTRAINT fk_module_scraped;
        ALTER TABLE scraped_contents ADD CONSTRAINT fk_scraped_contents_module_id FOREIGN KEY (module_id) REFERENCES modules (module_id) ON DELETE CASCADE;
        RAISE NOTICE 'Updated module foreign key constraint name in scraped_contents table';
    END IF;
    
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE table_name = 'scraped_contents' AND constraint_name = 'fk_session_scraped'
    ) THEN
        ALTER TABLE scraped_contents DROP CONSTRAINT fk_session_scraped;
        ALTER TABLE scraped_contents ADD CONSTRAINT fk_scraped_contents_session_id FOREIGN KEY (session_id) REFERENCES scraper_sessions (session_id) ON DELETE CASCADE;
        RAISE NOTICE 'Updated session foreign key constraint name in scraped_contents table';
    END IF;
END
$$;

-- ============================================================================
-- INDEX UPDATES
-- ============================================================================

-- Recreate indexes with consistent naming
DROP INDEX IF EXISTS idx_scraped_contents_url_link;
CREATE INDEX IF NOT EXISTS idx_scraped_contents_url_hash ON scraped_contents USING hash(url_link);

-- ============================================================================
-- DATA CLEANUP
-- ============================================================================

-- Clean up any inconsistent data
UPDATE scraped_contents SET risk_score = NULL WHERE risk_score = 0.0;
UPDATE scraped_contents SET risk_category = NULL WHERE risk_category = 'unknown';

-- ============================================================================
-- VERIFICATION
-- ============================================================================

-- Verify the schema matches the models
SELECT 
    'Schema verification' as check_type,
    table_name,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
    AND table_name IN ('unit_coordinators', 'modules', 'scraper_sessions', 'scraped_contents')
ORDER BY table_name, ordinal_position;

-- Verify foreign key constraints
SELECT 
    'Foreign key verification' as check_type,
    tc.constraint_name, 
    tc.table_name, 
    kcu.column_name, 
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name 
FROM information_schema.table_constraints AS tc 
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.table_schema = kcu.table_schema
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
    AND ccu.table_schema = tc.table_schema
WHERE tc.constraint_type = 'FOREIGN KEY' 
    AND tc.table_schema='public'
    AND tc.table_name IN ('modules', 'scraped_contents');

-- Clean up helper functions
DROP FUNCTION IF EXISTS add_column_if_not_exists(text, text, text);
DROP FUNCTION IF EXISTS modify_column_type_if_needed(text, text, text);

-- Show completion status
SELECT 
    'Migration completed successfully' as status,
    NOW() as completed_at;

COMMIT;

-- ============================================================================
-- POST-MIGRATION NOTES
-- ============================================================================

-- After running this migration:
-- 1. Test your application thoroughly
-- 2. Verify all CRUD operations work correctly
-- 3. Check that relationships between tables are functioning
-- 4. Monitor for any foreign key constraint violations
-- 5. Consider running VACUUM ANALYZE on all tables for performance

-- If you encounter any issues:
-- 1. Check the PostgreSQL logs for detailed error messages
-- 2. Verify your application models match the updated schema
-- 3. Ensure all foreign key references are valid
-- 4. Restore from backup if necessary and investigate the issue

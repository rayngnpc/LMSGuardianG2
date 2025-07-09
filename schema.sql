-- ============================================================================
-- LMS Guardian v2 Database Schema
-- PRODUCTION-READY RESET SCRIPT
-- ============================================================================
-- 
-- WARNING: This script will DROP and RECREATE all tables!
-- This is intended for fresh database installations or complete resets.
-- ALL EXISTING DATA WILL BE LOST!
--
-- Use this script when:
-- 1. Setting up a new deployment
-- 2. Needing a complete database reset
-- 3. Development environment resets
--
-- For production database updates/migrations, use migrate_database.sh instead
--
-- ============================================================================

-- Begin transaction for atomic operations
BEGIN;

-- ============================================================================
-- COMPLETE DATABASE RESET - DROP ALL EXISTING TABLES
-- ============================================================================

-- Drop all tables in correct dependency order
DROP TABLE IF EXISTS scraped_contents CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS scraper_sessions CASCADE;
DROP TABLE IF EXISTS modules CASCADE;
DROP TABLE IF EXISTS unit_coordinators CASCADE;

-- Drop any remaining sequences
DROP SEQUENCE IF EXISTS unit_coordinators_uc_id_seq CASCADE;
DROP SEQUENCE IF EXISTS modules_module_id_seq CASCADE;
DROP SEQUENCE IF EXISTS scraper_sessions_session_id_seq CASCADE;
DROP SEQUENCE IF EXISTS scraped_contents_scraped_id_seq CASCADE;
DROP SEQUENCE IF EXISTS reports_report_id_seq CASCADE;

-- ============================================================================
-- CORE TABLES - Exact match to SQLAlchemy models
-- ============================================================================

-- UnitCoordinator Table (matches app/models/unitCoordinator.py)
CREATE TABLE unit_coordinators (
    uc_id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
);

-- Module Table (matches app/models/module.py)
CREATE TABLE modules (
    module_id SERIAL PRIMARY KEY,
    uc_id INTEGER NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    teaching_period VARCHAR(255) NOT NULL,
    semester VARCHAR(255) NOT NULL,
    module_description VARCHAR(255) NOT NULL,
    unit_code VARCHAR(255) NOT NULL,
    CONSTRAINT fk_modules_uc_id FOREIGN KEY (uc_id) REFERENCES unit_coordinators (uc_id) ON DELETE CASCADE
);

-- ScraperSession Table (matches app/models/scrapedSession.py)
CREATE TABLE scraper_sessions (
    session_id SERIAL PRIMARY KEY,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    completion_status VARCHAR(255),
    error_log TEXT
);

-- ScrapedContent Table (matches app/models/scrapedContent.py)
CREATE TABLE scraped_contents (
    scraped_id SERIAL PRIMARY KEY,
    module_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    scraped_at TIMESTAMP,
    url_link TEXT,
    risk_category VARCHAR(255),
    risk_score FLOAT,
    content_location TEXT,
    is_paywall BOOLEAN DEFAULT FALSE,
    apa7 TEXT,
    CONSTRAINT fk_scraped_contents_module_id FOREIGN KEY (module_id) REFERENCES modules (module_id) ON DELETE CASCADE,
    CONSTRAINT fk_scraped_contents_session_id FOREIGN KEY (session_id) REFERENCES scraper_sessions (session_id) ON DELETE CASCADE
);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- UnitCoordinator indexes
CREATE INDEX idx_unit_coordinators_email ON unit_coordinators(email);

-- Module indexes  
CREATE INDEX idx_modules_uc_id ON modules(uc_id);
CREATE INDEX idx_modules_unit_code ON modules(unit_code);

-- ScraperSession indexes
CREATE INDEX idx_scraper_sessions_started_at ON scraper_sessions(started_at);
CREATE INDEX idx_scraper_sessions_status ON scraper_sessions(completion_status);

-- ScrapedContent indexes
CREATE INDEX idx_scraped_contents_module_id ON scraped_contents(module_id);
CREATE INDEX idx_scraped_contents_session_id ON scraped_contents(session_id);
CREATE INDEX idx_scraped_contents_scraped_at ON scraped_contents(scraped_at);
CREATE INDEX idx_scraped_contents_risk_category ON scraped_contents(risk_category);
CREATE INDEX idx_scraped_contents_url_hash ON scraped_contents USING hash(url_link);

-- ============================================================================
-- EXAMPLE DATA (SAFE FOR PRODUCTION)
-- ============================================================================

-- Insert example Unit Coordinators (replace with your actual coordinators)
INSERT INTO unit_coordinators (full_name, email) VALUES
    ('Dr. Jane Smith', 'jane.smith@university.edu.au'),
    ('Prof. John Doe', 'john.doe@university.edu.au'),
    ('Dr. Alice Johnson', 'alice.johnson@university.edu.au')
ON CONFLICT (email) DO NOTHING;

-- Insert example Modules (replace with your actual modules)
INSERT INTO modules (
    uc_id,
    module_name,
    teaching_period,
    semester,
    module_description,
    unit_code
) VALUES
    (1, 'BSC203 Introduction to ICT Research Methods', 'TMA', '2025', 'This unit introduces students to ICT research methods and practices.', 'BSC203'),
    (2, 'ICT280 Information Security Policy and Governance', 'TMA', '2025', 'This unit covers information security policies and governance frameworks.', 'ICT280'),
    (3, 'ICT302 Advanced Database Systems', 'TMA', '2025', 'Advanced concepts in database design and management.', 'ICT302')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- DATABASE VERIFICATION
-- ============================================================================

-- Verify table structure
SELECT 
    'Tables created successfully' as status,
    COUNT(*) as table_count 
FROM information_schema.tables 
WHERE table_schema = 'public' 
    AND table_name IN ('unit_coordinators', 'modules', 'scraper_sessions', 'scraped_contents');

-- Verify foreign key constraints
SELECT 
    'Foreign keys verified' as status,
    COUNT(*) as constraint_count
FROM information_schema.table_constraints 
WHERE table_schema = 'public' 
    AND constraint_type = 'FOREIGN KEY';

-- Verify indexes
SELECT 
    'Indexes created' as status,
    COUNT(*) as index_count
FROM pg_indexes 
WHERE schemaname = 'public';

-- Show sample data
SELECT 'Sample data inserted' as status, COUNT(*) as coordinator_count FROM unit_coordinators;
SELECT 'Sample data inserted' as status, COUNT(*) as module_count FROM modules;

COMMIT;

-- ============================================================================
-- POST-RESET INSTRUCTIONS
-- ============================================================================

-- After running this script successfully:
-- 1. Update the unit_coordinators table with your actual coordinators
-- 2. Update the modules table with your actual course modules  
-- 3. Configure your application's .env file with correct database credentials
-- 4. Start your application and verify connectivity
--
-- Example queries to customize your data:
--
-- -- Replace example coordinators with real ones:
-- DELETE FROM unit_coordinators WHERE email LIKE '%@university.edu.au';
-- INSERT INTO unit_coordinators (full_name, email) VALUES ('Your Real Name', 'your.email@domain.com');
--
-- -- Replace example modules with real ones:
-- DELETE FROM modules WHERE unit_code IN ('BSC203', 'ICT280', 'ICT302');
-- INSERT INTO modules (uc_id, module_name, teaching_period, semester, module_description, unit_code) 
-- VALUES (1, 'Your Real Module', 'Actual Period', 'Real Semester', 'Real Description', 'REAL_CODE');

-- ============================================================================
-- TROUBLESHOOTING
-- ============================================================================

-- If you encounter permission errors:
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_database_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_database_user;

-- If you need to check what went wrong:
-- SELECT * FROM information_schema.tables WHERE table_schema = 'public';
-- SELECT * FROM information_schema.table_constraints WHERE table_schema = 'public';

#!/bin/bash

# ============================================================================
# LMS Guardian Database Diagnosis Script
# ============================================================================
# This script will help you understand the current state of your database
# and what needs to be fixed to match the application requirements.

echo "🔍 LMS Guardian Database Diagnosis"
echo "=================================="
echo

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL environment variable is not set"
    echo "Please set it like this:"
    echo "export DATABASE_URL='postgresql://username:password@host:port/database'"
    echo
    read -p "Enter your database URL: " DATABASE_URL
    export DATABASE_URL
fi

echo "🔗 Using database: $DATABASE_URL"
echo

# Extract connection details from DATABASE_URL
DB_DETAILS=$(python3 -c "
import urllib.parse as up
url = up.urlparse('$DATABASE_URL')
print(f'-h {url.hostname} -p {url.port or 5432} -U {url.username} -d {url.path[1:]}')
")

echo "📊 Checking database structure..."
echo "================================="

# Create a temporary SQL file for diagnosis
cat > /tmp/diagnosis.sql << 'EOF'
-- Check if tables exist
SELECT 'TABLE EXISTENCE CHECK' as check_type;
SELECT 
    table_name,
    CASE WHEN table_name IS NOT NULL THEN '✅ EXISTS' ELSE '❌ MISSING' END as status
FROM information_schema.tables 
WHERE table_schema = 'public' 
    AND table_name IN ('unit_coordinators', 'modules', 'scraper_sessions', 'scraped_contents')
ORDER BY table_name;

-- Check table structures
SELECT '' as separator, 'COLUMN STRUCTURE CHECK' as check_type;
SELECT 
    table_name,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
    AND table_name IN ('unit_coordinators', 'modules', 'scraper_sessions', 'scraped_contents')
ORDER BY table_name, ordinal_position;

-- Check foreign key constraints
SELECT '' as separator, 'FOREIGN KEY CHECK' as check_type;
SELECT 
    tc.table_name,
    tc.constraint_name,
    kcu.column_name,
    ccu.table_name AS foreign_table,
    ccu.column_name AS foreign_column
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu 
    ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage ccu 
    ON tc.constraint_name = ccu.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY' 
    AND tc.table_schema = 'public'
ORDER BY tc.table_name;

-- Check data counts
SELECT '' as separator, 'DATA COUNT CHECK' as check_type;
SELECT 'unit_coordinators' as table_name, COUNT(*) as row_count FROM unit_coordinators
UNION ALL
SELECT 'modules' as table_name, COUNT(*) as row_count FROM modules  
UNION ALL
SELECT 'scraper_sessions' as table_name, COUNT(*) as row_count FROM scraper_sessions
UNION ALL
SELECT 'scraped_contents' as table_name, COUNT(*) as row_count FROM scraped_contents;

-- Check for schema mismatches that commonly cause issues
SELECT '' as separator, 'COMMON ISSUES CHECK' as check_type;

-- Check if unit_coordinators has created_at/updated_at (shouldn't in new schema)
SELECT 
    'unit_coordinators extra columns' as issue,
    string_agg(column_name, ', ') as extra_columns
FROM information_schema.columns 
WHERE table_name = 'unit_coordinators' 
    AND column_name IN ('created_at', 'updated_at')
GROUP BY 1
HAVING COUNT(*) > 0;

-- Check if modules has wrong column types
SELECT 
    'modules column type issues' as issue,
    column_name,
    data_type as current_type,
    'should be VARCHAR(255)' as expected_type
FROM information_schema.columns 
WHERE table_name = 'modules' 
    AND column_name IN ('teaching_period', 'semester', 'module_description', 'unit_code')
    AND data_type NOT LIKE '%character varying%';

-- Check for wrong default values in scraped_contents
SELECT 
    'scraped_contents default value issues' as issue,
    column_name,
    column_default as current_default,
    'should be NULL' as expected_default
FROM information_schema.columns 
WHERE table_name = 'scraped_contents' 
    AND column_name IN ('scraped_at', 'url_link', 'risk_score', 'risk_category')
    AND column_default IS NOT NULL;
EOF

# Run the diagnosis
echo "Running database diagnosis..."
psql $DB_DETAILS -f /tmp/diagnosis.sql

# Clean up
rm -f /tmp/diagnosis.sql

echo
echo "📋 RECOMMENDATIONS:"
echo "==================="
echo
echo "Based on the results above:"
echo
echo "1. If tables are MISSING:"
echo "   → Use: psql $DB_DETAILS -f schema.sql"
echo
echo "2. If tables exist but have wrong structure:"
echo "   → First backup: pg_dump $DB_DETAILS > backup_\$(date +%Y%m%d_%H%M%S).sql"
echo "   → Then migrate: psql $DB_DETAILS -f schema_migration.sql"
echo
echo "3. If you see 'extra columns' or 'type issues':"
echo "   → The migration script will fix these automatically"
echo
echo "4. If you want a fresh start:"
echo "   → Backup data if needed, then run: psql $DB_DETAILS -f schema.sql"
echo
echo "💡 TIP: If you're unsure, always create a backup first!"

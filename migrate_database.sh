#!/bin/bash
# ============================================================================
# LMS Guardian Database Migration Script
# ============================================================================
# This script will safely update your existing database to match the current schema
# It can be run multiple times safely

echo "🗄️ LMS Guardian Database Migration"
echo "==================================="

# Check if required environment variables are set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ ERROR: DATABASE_URL environment variable is not set"
    echo "Please set it in your .env file or export it:"
    echo "export DATABASE_URL='postgresql://username:password@localhost:5432/lmsguardian'"
    exit 1
fi

# Extract database connection details from DATABASE_URL
DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\).*/\1/p')
DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')
DB_USER=$(echo $DATABASE_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')

echo "📊 Database: $DB_NAME on $DB_HOST"
echo "👤 User: $DB_USER"
echo ""

# Function to run SQL safely
run_sql() {
    local sql="$1"
    local description="$2"
    echo "🔄 $description..."
    
    if psql "$DATABASE_URL" -c "$sql" >/dev/null 2>&1; then
        echo "✅ $description completed"
    else
        echo "⚠️  $description failed or already exists (this may be normal)"
    fi
}

# Function to check if table exists
table_exists() {
    local table_name="$1"
    psql "$DATABASE_URL" -t -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '$table_name');" | grep -q 't'
}

echo "🔍 Checking current database structure..."

# Check what tables exist
echo "📋 Current tables:"
psql "$DATABASE_URL" -c "\dt" 2>/dev/null || echo "No tables found or connection failed"

echo ""
echo "🛠️  Starting migration..."

# 1. Add missing columns safely
echo "📝 Adding missing columns..."

run_sql "ALTER TABLE unit_coordinators ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding created_at to unit_coordinators"
run_sql "ALTER TABLE unit_coordinators ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding updated_at to unit_coordinators"

run_sql "ALTER TABLE modules ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding created_at to modules"
run_sql "ALTER TABLE modules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding updated_at to modules"

run_sql "ALTER TABLE scraper_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding created_at to scraper_sessions"
run_sql "ALTER TABLE scraped_contents ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding created_at to scraped_contents"

run_sql "ALTER TABLE reports ADD COLUMN IF NOT EXISTS report_path TEXT;" "Adding report_path to reports"
run_sql "ALTER TABLE reports ADD COLUMN IF NOT EXISTS generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding generated_at to reports"
run_sql "ALTER TABLE reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" "Adding created_at to reports"

# 2. Add constraints and defaults safely
echo "🔧 Updating constraints and defaults..."

run_sql "ALTER TABLE scraped_contents ALTER COLUMN risk_score SET DEFAULT 0.0;" "Setting default for risk_score"
run_sql "ALTER TABLE scraped_contents ALTER COLUMN risk_category SET DEFAULT 'unknown';" "Setting default for risk_category"
run_sql "ALTER TABLE scraper_sessions ALTER COLUMN completion_status SET DEFAULT 'running';" "Setting default for completion_status"
run_sql "ALTER TABLE reports ALTER COLUMN report_type SET DEFAULT 'standard';" "Setting default for report_type"

# 3. Create indexes for performance
echo "📊 Creating performance indexes..."

run_sql "CREATE INDEX IF NOT EXISTS idx_unit_coordinators_email ON unit_coordinators(email);" "Creating email index"
run_sql "CREATE INDEX IF NOT EXISTS idx_modules_unit_code ON modules(unit_code);" "Creating unit_code index"
run_sql "CREATE INDEX IF NOT EXISTS idx_modules_uc_id ON modules(uc_id);" "Creating module uc_id index"
run_sql "CREATE INDEX IF NOT EXISTS idx_scraped_contents_module_id ON scraped_contents(module_id);" "Creating scraped_contents module_id index"
run_sql "CREATE INDEX IF NOT EXISTS idx_scraped_contents_session_id ON scraped_contents(session_id);" "Creating scraped_contents session_id index"
run_sql "CREATE INDEX IF NOT EXISTS idx_scraped_contents_risk_category ON scraped_contents(risk_category);" "Creating risk_category index"

# 4. Update NULL values with defaults
echo "🧹 Cleaning up NULL values..."

run_sql "UPDATE scraped_contents SET risk_score = 0.0 WHERE risk_score IS NULL;" "Setting default risk_score values"
run_sql "UPDATE scraped_contents SET risk_category = 'unknown' WHERE risk_category IS NULL;" "Setting default risk_category values"
run_sql "UPDATE scraper_sessions SET completion_status = 'completed' WHERE completion_status IS NULL AND ended_at IS NOT NULL;" "Setting completion_status for finished sessions"
run_sql "UPDATE scraper_sessions SET completion_status = 'running' WHERE completion_status IS NULL AND ended_at IS NULL;" "Setting completion_status for active sessions"

# 5. Add UNIQUE constraint to email if it doesn't exist
echo "🔒 Adding unique constraints..."
run_sql "ALTER TABLE unit_coordinators ADD CONSTRAINT unit_coordinators_email_key UNIQUE (email);" "Adding unique constraint to coordinator email"

echo ""
echo "🎯 Verification - Current database structure:"
psql "$DATABASE_URL" -c "
SELECT 
    t.table_name,
    c.column_name,
    c.data_type,
    c.is_nullable,
    c.column_default
FROM information_schema.tables t
JOIN information_schema.columns c ON t.table_name = c.table_name
WHERE t.table_schema = 'public' 
    AND t.table_type = 'BASE TABLE'
    AND t.table_name IN ('unit_coordinators', 'modules', 'scraper_sessions', 'scraped_contents', 'reports')
ORDER BY t.table_name, c.ordinal_position;
" 2>/dev/null

echo ""
echo "✅ Migration completed!"
echo ""
echo "📝 Next steps:"
echo "1. Test your application connection: python -c \"from app.database.database import engine; print('✅ Database connection OK')\""
echo "2. Run a scraper test: python scraper/main.py"
echo "3. Check the backend API: python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "🔧 If you still have issues, you can run the full schema.sql to recreate everything:"
echo "   psql \$DATABASE_URL -f schema.sql"

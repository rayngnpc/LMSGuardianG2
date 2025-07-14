#!/bin/bash

# Quick database data check script
echo "🔍 Checking current database contents..."
echo "======================================"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "Please set DATABASE_URL first:"
    echo "export DATABASE_URL='postgresql://admin:your_password@localhost:5432/lmsguardian'"
    exit 1
fi

# Extract connection details
DB_DETAILS=$(python3 -c "
import urllib.parse as up
url = up.urlparse('$DATABASE_URL')
print(f'-h {url.hostname} -p {url.port or 5432} -U {url.username} -d {url.path[1:]}')
")

echo "📊 Current Unit Coordinators:"
psql $DB_DETAILS -c "SELECT uc_id, full_name, email FROM unit_coordinators ORDER BY uc_id;"

echo ""
echo "📚 Current Modules:"
psql $DB_DETAILS -c "SELECT module_id, uc_id, module_name, unit_code, teaching_period, semester FROM modules ORDER BY module_id;"

echo ""
echo "🕷️ Scraper Sessions:"
psql $DB_DETAILS -c "SELECT session_id, started_at, ended_at, completion_status FROM scraper_sessions ORDER BY session_id DESC LIMIT 5;"

echo ""
echo "📄 Scraped Contents (sample):"
psql $DB_DETAILS -c "SELECT scraped_id, module_id, session_id, url_link, risk_category FROM scraped_contents ORDER BY scraped_id DESC LIMIT 5;"

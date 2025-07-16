#!/bin/bash
# Repository cleanup script
# This script removes test files and keeps only core project files

echo "🧹 Cleaning up repository for GitHub upload..."
echo "Removing test files and temporary files..."

# Remove test files
rm -f test_*.py
rm -f analyze_*.py
rm -f check_*.py
rm -f create_*.py
rm -f demonstrate_*.py
rm -f enhanced_*.py
rm -f final_*.py
rm -f monitor_*.py
rm -f patch_*.py
rm -f production_*.py
rm -f professional_*.py
rm -f quota_*.py
rm -f updated_*.py
rm -f paywall_*.py
rm -f api_*.py
rm -f apa_citation_checker*.py
rm -f cleanup_*.py
rm -f integrated_*.py
rm -f emergency_*.py

# Remove markdown documentation files (keep only essential ones)
rm -f API_FIXES_SUMMARY.md
rm -f API_FIX_SUMMARY.md
rm -f ENHANCED_PORNOGRAPHY_DETECTION.md
rm -f FINAL_ENHANCEMENTS_SUMMARY.md
rm -f IMPROVEMENTS_SUMMARY.md
rm -f PAYWALL_ANALYSIS.md
rm -f PAYWALL_DETECTION_SUMMARY.md
rm -f REPORT_ENHANCEMENTS.md

# Remove config and status files
rm -f api_quota_config.json
rm -f api_status_report_*.json
rm -f emergency_fallback_config.json
rm -f updated_citations.txt

# Remove database files (keep schema)
rm -f database.db

# Remove screenshots
rm -f step*.png

# Remove Python cache
rm -rf __pycache__/
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -type f -delete 2>/dev/null || true

# Remove virtual environment
rm -rf venv/

echo "✅ Repository cleaned up successfully!"
echo "📁 Core project files preserved:"
echo "   - Main application (app/)"
echo "   - Scraper modules (scraper/)"
echo "   - Database schemas (*.sql)"
echo "   - Configuration files"
echo "   - Requirements and documentation"

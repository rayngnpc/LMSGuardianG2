#!/bin/bash
# Server Deployment Guide for LMS Guardian

echo "🚀 LMS Guardian Server Deployment Guide"
echo "========================================"

echo "📋 STEP 1: Install Dependencies on Server"
echo "  sudo apt update && sudo apt upgrade -y"
echo "  sudo apt install python3 python3-pip postgresql postgresql-contrib nodejs npm -y"
echo "  pip3 install -r requirements.txt"

echo ""
echo "🗄️ STEP 2: Setup PostgreSQL Database"
echo "  sudo -u postgres psql"
echo "  CREATE DATABASE lmsguardian;"
echo "  CREATE USER admin WITH PASSWORD '123';"
echo "  GRANT ALL PRIVILEGES ON DATABASE lmsguardian TO admin;"
echo "  \\q"

echo ""
echo "📁 STEP 3: Initialize Database Schema"
echo "  psql -h localhost -U admin -d lmsguardian -f schema.sql"

echo ""
echo "🔧 STEP 4: Update .env for Server Environment"
echo "  Update DATABASE_URL to match your server PostgreSQL settings"
echo "  Update LMS URLs to match your server's Moodle instance"
echo "  Update email credentials for production"

echo ""
echo "🕷️ STEP 5: Test the System"
echo "  # Start the backend API"
echo "  cd /path/to/LMSGuardianv2"
echo "  python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "  # In another terminal, run the scraper"
echo "  python scraper/main.py"

echo ""
echo "🔄 STEP 6: Setup Automated Scheduling (Optional)"
echo "  # Add to crontab for daily scraping at 2 AM"
echo "  0 2 * * * cd /path/to/LMSGuardianv2 && python scraper/main.py"

echo ""
echo "✅ DEPLOYMENT CHECKLIST:"
echo "  □ PostgreSQL installed and configured"
echo "  □ Database created using schema.sql"
echo "  □ Dependencies installed from requirements.txt"
echo "  □ .env file updated for server environment"
echo "  □ Backend API tested (http://server:8000/docs)"
echo "  □ Scraper tested with AUTO_DISCOVER_COURSES=true"
echo "  □ Email reports tested"
echo "  □ Firewall configured (ports 8000, 5432)"

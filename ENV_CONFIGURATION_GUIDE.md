# LMS Guardian Environment Configuration Guide

## Overview

The LMS Guardian system is fully configurable through the `.env` file. You can easily change behavior without modifying any code by simply editing the environment variables.

## 🔒 Security First

**Important**: Always copy `.env.example` to `.env` and update with your actual credentials:

```bash
cp .env.example .env
nano .env  # Edit with your real credentials
```

**Never commit real credentials to version control!**

## Configuration Options

### 🔐 Authentication Settings
```env
MOODLE_USERNAME=your_moodle_username
MOODLE_PASSWORD=your_moodle_password
```

### 📧 Email Configuration
```env
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_app_password
```

### 🗃️ Database Configuration
```env
DATABASE_URL=postgresql://username:password@localhost:5432/lmsguardian
```

### 🔑 API Keys
```env
GOOGLE_SAFE_KEY=your_google_safe_browsing_api_key
```

### 📊 Scraping Configuration
```env
# Scrape all courses or just a single course
SCRAPE_ALL_COURSES=true              # true = all courses, false = single course
SINGLE_COURSE_MODULE_ID=2            # Which course to scrape when SCRAPE_ALL_COURSES=false
```

### 🌐 Browser Configuration
```env
# Browser behavior settings
HEADLESS_BROWSER=true                # true = invisible browser, false = visible browser
BROWSER_TIMEOUT=60000                # Browser timeout in milliseconds
```

### 🕷️ Crawler Configuration
```env
# Crawler behavior settings
CRAWLER_DELAY_SECONDS=0.5            # Delay between page crawls (seconds)
MAX_PAGES_PER_SESSION=100            # Maximum pages to crawl per session
```

### 📋 Report Configuration
```env
# Report generation settings
GENERATE_REPORTS=true                # true = generate PDF reports, false = skip reports
SEND_EMAIL_REPORTS=true              # true = email reports to coordinators, false = save only
```

### 🐛 Debug Configuration
```env
# Debug and development settings
DEBUG_MODE=false                     # true = verbose logging, false = minimal output
SAVE_SCREENSHOTS=true                # true = save login screenshots, false = no screenshots
```

### 📧 Email Configuration
```env
EMAIL_USER=noreplytestict302@gmail.com
EMAIL_PASS= >Password<
```

### 🔗 API Configuration
```env
DATABASE_URL=postgresql://your_db_user:your_db_password@localhost:5432/your_db
GOOGLE_SAFE_KEY=<Your API Key>
```

## Common Configuration Scenarios

### 🖥️ Development Mode (See browser in action)
```env
HEADLESS_BROWSER=false
DEBUG_MODE=true
SAVE_SCREENSHOTS=true
CRAWLER_DELAY_SECONDS=2.0
```

### 🚀 Production Mode (Fast, efficient)
```env
HEADLESS_BROWSER=true
DEBUG_MODE=false
SAVE_SCREENSHOTS=false
CRAWLER_DELAY_SECONDS=0.5
```

### 🎯 Single Course Testing
```env
SCRAPE_ALL_COURSES=false
SINGLE_COURSE_MODULE_ID=3
GENERATE_REPORTS=false
DEBUG_MODE=true
```

### 📊 Report Generation Only (No crawling)
```env
SCRAPE_ALL_COURSES=false
GENERATE_REPORTS=true
SEND_EMAIL_REPORTS=true
```

### 🔧 Development Testing
```env
HEADLESS_BROWSER=false
DEBUG_MODE=true
SCRAPE_ALL_COURSES=false
SINGLE_COURSE_MODULE_ID=2
GENERATE_REPORTS=false
SEND_EMAIL_REPORTS=false
```

## How Configuration Works

1. **Environment Variables**: All settings are read from the `.env` file using the `python-dotenv` library
2. **Type Conversion**: Boolean values are automatically converted from strings ('true'/'false') to Python booleans
3. **Default Values**: If a setting is missing from `.env`, sensible defaults are used
4. **Override Protection**: Settings are loaded with `override=True` to ensure `.env` values take precedence

## Code Implementation

The configuration is implemented in multiple files:

### Main Configuration Loading
```python
from dotenv import load_dotenv
import os

load_dotenv(override=True)

def str_to_bool(value: str) -> bool:
    """Convert string to boolean"""
    return value.lower() in ('true', '1', 'yes', 'on')

# Load all configuration
HEADLESS_BROWSER = str_to_bool(os.getenv("HEADLESS_BROWSER", "true"))
DEBUG_MODE = str_to_bool(os.getenv("DEBUG_MODE", "false"))
# ... etc
```

### Browser Configuration
```python
# In run_crawler function
browser = await playwright.chromium.launch(headless=HEADLESS_BROWSER)
context.set_default_timeout(BROWSER_TIMEOUT)
```

### Crawler Behavior
```python
# Delay between page visits
await asyncio.sleep(CRAWLER_DELAY_SECONDS)

# Debug output
if DEBUG_MODE:
    print(f"[FOUND] Cleaned link: {clean_link}")
```

## How to Change Settings

1. **Edit the `.env` file** in the project root directory
2. **Change the values** you want to modify
3. **Run the scraper** - it will automatically use the new settings
4. **No code changes needed** - all configuration is environment-driven

## Example Usage

```bash
# Edit the .env file
nano .env

# Change HEADLESS_BROWSER from true to false to see the browser
# Change DEBUG_MODE from false to true for verbose output

# Run the scraper with new settings
cd scraper
python main.py
```

The system will automatically read the new configuration and behave accordingly!

## Benefits of Environment Configuration

- ✅ **No Code Changes**: Modify behavior without touching source code
- ✅ **Easy Testing**: Quickly switch between development and production modes
- ✅ **Secure**: Sensitive credentials kept in environment files
- ✅ **Flexible**: Different team members can use different settings
- ✅ **Version Control Safe**: `.env` files can be excluded from git
- ✅ **Environment Specific**: Different settings for dev/staging/production

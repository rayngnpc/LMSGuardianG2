import asyncio
import sys
import os

# Add the current directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from scraper.crawler import run_crawler
from reputation.checker import analyze_links
from reportgenerator.report import generatePDF, send_email_with_report
import requests
from datetime import datetime, UTC
from collections import defaultdict
import pytz
import os
from dotenv import load_dotenv
import re

# Load environment variables
load_dotenv(override=True)

# Configuration from Environment Variables
def str_to_bool(value: str) -> bool:
    """Convert string to boolean"""
    return value.lower() in ('true', '1', 'yes', 'on')

SCRAPE_ALL_COURSES = str_to_bool(os.getenv("SCRAPE_ALL_COURSES", "true"))
SINGLE_COURSE_MODULE_ID = int(os.getenv("SINGLE_COURSE_MODULE_ID", "2"))
GENERATE_REPORTS = str_to_bool(os.getenv("GENERATE_REPORTS", "true"))
SEND_EMAIL_REPORTS = str_to_bool(os.getenv("SEND_EMAIL_REPORTS", "true"))
DEBUG_MODE = str_to_bool(os.getenv("DEBUG_MODE", "false"))
AUTO_DISCOVER_COURSES = str_to_bool(os.getenv("AUTO_DISCOVER_COURSES", "false"))

def print_config():
    """Print current configuration from .env"""
    print("=== LMS Guardian Configuration (.env) ===")
    print(f"🎯 Scrape All Courses: {SCRAPE_ALL_COURSES}")
    if not SCRAPE_ALL_COURSES:
        print(f"   Single Course Module ID: {SINGLE_COURSE_MODULE_ID}")
    print(f"📊 Generate Reports: {GENERATE_REPORTS}")
    print(f"📧 Send Email Reports: {SEND_EMAIL_REPORTS}")
    print(f"🔍 Auto Discover Courses: {AUTO_DISCOVER_COURSES}")
    print(f"🐛 Debug Mode: {DEBUG_MODE}")
    
    # Show browser settings
    headless = str_to_bool(os.getenv("HEADLESS_BROWSER", "true"))
    browser_timeout = int(os.getenv("BROWSER_TIMEOUT", "60000"))
    crawler_delay = float(os.getenv("CRAWLER_DELAY_SECONDS", "0.5"))
    
    print(f"🌐 Browser Headless: {headless}")
    print(f"⏱️  Browser Timeout: {browser_timeout}ms")
    print(f"⏳ Crawler Delay: {crawler_delay}s")
    print("=" * 45)

def create_module_for_course(course_id, title):
    """Create a new module for a discovered course"""
    unit_code = extract_unit_code_from_title(title)
    if not unit_code:
        unit_code = f"COURSE_{course_id}"
    
    module_data = {
        'uc_id': 1,  # Default coordinator
        'unit_code': unit_code,
        'module_name': title,
        'teaching_period': 'TMA',
        'semester': '2025',
        'module_description': f'Auto-discovered course from LMS (Course ID: {course_id})'
    }
    
    try:
        res = requests.post('http://127.0.0.1:8000/modules/', json=module_data)
        if res.status_code == 200:
            created = res.json()
            print(f"✅ Auto-created Module {created['module_id']}: {created['unit_code']} for Course {course_id}")
            return created['module_id']
        else:
            print(f"❌ Failed to create module for Course {course_id}: {res.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error creating module for Course {course_id}: {e}")
        return None

def extract_unit_code_from_title(title):
    """Extract unit code from course title (e.g., 'BSC203' from 'BSC203 Title')"""
    if not title:
        return None
    
    # Look for common unit code patterns
    patterns = [
        r'^([A-Z]{2,4}\d{3})',  # BSC203, ICT280, etc.
        r'([A-Z]{2,4}\d{3})',   # BSC203 anywhere in title
        r'^([A-Z]+\d+)',        # Any letters followed by numbers at start
    ]
    
    for pattern in patterns:
        match = re.search(pattern, title.upper().strip())
        if match:
            return match.group(1)
    
    return None

def getAllCourseId():
    try:
        res = requests.get("http://127.0.0.1:8000/modules")
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"Failed to get module IDs: {e}")
        return []


def getRecentSessionScan():
    try:
        res = requests.get("http://127.0.0.1:8000/scrapedcontents/risks")
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"Failed to get module IDs: {e}")
        return []


def getAllExternalLinks():
    """Get all external links from the latest session, removing duplicates"""
    try:
        res = requests.get("http://127.0.0.1:8000/scrapedcontents/")
        res.raise_for_status()
        all_links = res.json()
        
        # Filter for external links (non-internal domain)
        external_links = []
        seen_urls = set()  # Track URLs we've already seen
        
        for link in all_links:
            url = link.get("url_link", "")
            if url and "10.51.33.25" not in url:  # External if not internal domain
                # Only add if we haven't seen this URL before
                if url not in seen_urls:
                    external_links.append(link)
                    seen_urls.add(url)
                    
        if DEBUG_MODE:
            print(f"Deduplicated: {len(external_links)} unique external links from {len([l for l in all_links if l.get('url_link', '') and '10.51.33.25' not in l.get('url_link', '')])} total external entries")
        return external_links
    except Exception as e:
        print(f"Failed to get external links: {e}")
        return []


def getAllHighRisks():
    try:
        res = requests.get("http://127.0.0.1:8000/scrapedcontents/highrisks")
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"Failed to get module IDs: {e}")
        return []


def startsession():
    payload = {
        "started_at": datetime.now(UTC).isoformat(),
        "completion_status": "running",
        "error_log": None,
    }
    try:
        res = requests.post(
            "http://127.0.0.1:8000/scrapersession/newsession", json=payload
        )
        res.raise_for_status()
        session_data = res.json()
        return session_data["session_id"]
    except Exception as e:
        print(f"Failed to create scraper session: {e}")
        return None


async def batchScrape():
    """Scrape courses based on .env configuration"""
    print_config()
    
    # Auto-discover new courses if enabled
    if AUTO_DISCOVER_COURSES:
        print("🔍 Auto-discovering new courses...")
        from scripts.discover_courses import discover_courses, create_module, get_existing_modules, extract_unit_code
        
        try:
            discovered = await discover_courses()
            if discovered:
                existing_modules = get_existing_modules()
                existing_course_ids = {m['module_id'] + 1 for m in existing_modules}
                
                for course in discovered:
                    course_id = course['course_id']
                    if course_id not in existing_course_ids:
                        unit_code = extract_unit_code(course['title'])
                        if unit_code:
                            module_id = create_module(unit_code, course['title'], course_id)
                            if module_id:
                                print(f"✅ Auto-created Module {module_id} for Course {course_id}: {unit_code}")
        except Exception as e:
            print(f"⚠️ Auto-discovery failed: {e}")
            print("Continuing with existing modules...")
    
    sessionId = startsession()
    if not sessionId:
        print("❌ Failed to start session")
        return
    
    if SCRAPE_ALL_COURSES:
        # Get all courses from database
        moduleIdList = getAllCourseId()
        if not moduleIdList:
            print("⚠️ No modules found in database")
            return
        
        print(f"🎯 Found {len(moduleIdList)} courses to scrape")
        
        for module in moduleIdList:
            module_id = module["module_id"]
            course_id = module_id + 1  # Moodle course ID is module_id + 1
            unit_code = module.get("unit_code", f"Module_{module_id}")
            
            print(f"\n🕷️ Scraping {unit_code} (Module ID: {module_id}, Course ID: {course_id})")
            
            base_url = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"
            print(f"📍 URL: {base_url}")
            
            try:
                await run_crawler(base_url, sessionId, module_id)
                print(f"✅ Completed scraping {unit_code}")
            except Exception as e:
                print(f"❌ Failed to scrape {unit_code}: {e}")
        
        print(f"\n🎉 Batch scraping completed for {len(moduleIdList)} courses")
    
    else:
        # Single course scraping
        module_id = SINGLE_COURSE_MODULE_ID
        course_id = module_id + 1
        
        print(f"🕷️ Scraping single course (Module ID: {module_id}, Course ID: {course_id})")
        
        base_url = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"
        print(f"📍 URL: {base_url}")
        
        try:
            await run_crawler(base_url, sessionId, module_id)
            print(f"✅ Completed scraping Module {module_id}")
        except Exception as e:
            print(f"❌ Failed to scrape Module {module_id}: {e}")
    
    print("📊 Report generation will be handled separately by batchReport()")


async def batchAnalyse():
    scans = getRecentSessionScan()
    if DEBUG_MODE:
        print(f"🧪 Analyzing {len(scans)} links")
    
    for scan in scans:
        if DEBUG_MODE:
            print(scan)
        scrapeId = scan["scrapeID"]
        url = scan["url"]
        analyze_links(scrapeId, url)
    
    if DEBUG_MODE:
        print("🧪 Analysis complete:", getRecentSessionScan())


async def batchReport():
    if not GENERATE_REPORTS:
        print("📊 Report generation disabled in .env")
        return
        
    # Use the same logic as the standalone report generator
    from reportgenerator.report import fetch_all_links_by_module
    
    print("🚀 Starting module-specific report generation...")
    links_by_module = fetch_all_links_by_module()
    
    if not links_by_module:
        print("❌ No external links found for report generation")
        return

    # Generate reports for each module
    for module_id, links in links_by_module.items():
        print(f"\n📋 Module ID: {module_id} ({len(links)} external links)")
        
        try:
            moduleInfo = requests.get(f"http://127.0.0.1:8000/modules/{module_id}").json()
            uc_id = moduleInfo["uc_id"]
            unitCoordinatorInfo = requests.get(
                f"http://127.0.0.1:8000/unitCoordinator/{uc_id}"
            ).json()
            unitCode = moduleInfo["unit_code"]
            unitCoordinatorName = unitCoordinatorInfo["full_name"]
            # Calculate course_id from module_id (course_id = module_id + 1)
            course_id = module_id + 1
            baseUrl = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"
            
            # Generate report
            report_path = generatePDF(unitCoordinatorName, unitCode, links, baseUrl)
            print(f"📊 Generated report: {report_path}")

            # Send email if enabled
            if SEND_EMAIL_REPORTS:
                unitCoordinatorEmail = unitCoordinatorInfo["email"]
                send_email_with_report(
                    unitCoordinatorEmail, report_path, unitCode, unitCoordinatorName
                )
                print(f"📧 Email sent to: {unitCoordinatorEmail}")
            else:
                print("📧 Email sending disabled in .env")
                
        except Exception as e:
            print(f"❌ Failed to generate report for Module {module_id}: {e}")


async def main():
    print("🚀 Starting LMS Guardian")
    
    await batchScrape()
    await batchAnalyse()
    await batchReport()
    
    print("✅ LMS Guardian completed!")


if __name__ == "__main__":
    asyncio.run(main())

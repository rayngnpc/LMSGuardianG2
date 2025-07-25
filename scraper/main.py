import asyncio
import sys
import os
from scraper import savelocal
import concurrent.futures
import threading

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
    return value.lower() in ("true", "1", "yes", "on")


SCRAPE_ALL_COURSES = str_to_bool(os.getenv("SCRAPE_ALL_COURSES", "true"))
SINGLE_COURSE_MODULE_ID = int(os.getenv("SINGLE_COURSE_MODULE_ID", "2"))
GENERATE_REPORTS = str_to_bool(os.getenv("GENERATE_REPORTS", "true"))
SEND_EMAIL_REPORTS = str_to_bool(os.getenv("SEND_EMAIL_REPORTS", "true"))
DEBUG_MODE = str_to_bool(os.getenv("DEBUG_MODE", "false"))
AUTO_DISCOVER_COURSES = str_to_bool(os.getenv("AUTO_DISCOVER_COURSES", "false"))


# Performance Configuration
PARALLEL_ANALYSIS_LIMIT = int(
    os.getenv("PARALLEL_ANALYSIS_LIMIT", "3")
)  # Reduce from 5 to 3
ANALYSIS_TIMEOUT = int(os.getenv("ANALYSIS_TIMEOUT", "30"))  # 30 second timeout per URL
SKIP_SLOW_ANALYSIS = str_to_bool(
    os.getenv("SKIP_SLOW_ANALYSIS", "false")
)  # Skip slow URLs after timeout


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
        "uc_id": 1,  # Default coordinator
        "unit_code": unit_code,
        "module_name": title,
        "teaching_period": "TMA",
        "semester": "2025",
        "module_description": f"Auto-discovered course from LMS (Course ID: {course_id})",
    }

    try:
        res = requests.post("http://127.0.0.1:8000/modules/", json=module_data)
        if res.status_code == 200:
            created = res.json()
            print(
                f"✅ Auto-created Module {created['module_id']}: {created['unit_code']} for Course {course_id}"
            )
            return created["module_id"]
        else:
            print(
                f"❌ Failed to create module for Course {course_id}: {res.status_code}"
            )
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
        r"^([A-Z]{2,4}\d{3})",  # BSC203, ICT280, etc.
        r"([A-Z]{2,4}\d{3})",  # BSC203 anywhere in title
        r"^([A-Z]+\d+)",  # Any letters followed by numbers at start
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
        res = requests.get("http://127.0.0.1:8000/scrapedcontents/scan")
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"Failed to get module IDs: {e}")
        return []


def getAllExternalLinks():
    """Get all external links from the latest session, removing duplicates and trusted domains"""
    try:
        res = requests.get("http://127.0.0.1:8000/scrapedcontents/")
        res.raise_for_status()
        all_links = res.json()

        # Filter for external links (non-internal domain and non-Murdoch)
        external_links = []
        seen_urls = set()  # Track URLs we've already seen

        # Trusted domains that should be excluded from external analysis
        trusted_domains = [
            "10.51.33.25",  # Internal Moodle
            "murdoch.edu.au",
            "moodleprod.murdoch.edu.au",
            "goto.murdoch.edu.au",
            "libguides.murdoch.edu.au",
            "library.murdoch.edu.au",
            "our.murdoch.edu.au",
            "online.murdoch.edu.au",
            "murdochuniversity.sharepoint.com",
        ]

        for link in all_links:
            url = link.get("url_link", "")
            if url:
                # Check if URL contains any trusted domain
                is_trusted = any(domain in url for domain in trusted_domains)

                if not is_trusted:
                    # Only add if we haven't seen this URL before
                    if url not in seen_urls:
                        external_links.append(link)
                        seen_urls.add(url)

        if DEBUG_MODE:
            original_external_count = len(
                [
                    l
                    for l in all_links
                    if l.get("url_link", "")
                    and not any(
                        domain in l.get("url_link", "") for domain in trusted_domains
                    )
                ]
            )
            print(
                f"Deduplicated: {len(external_links)} unique external links from {original_external_count} total external entries"
            )
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


# def should_skip_module_scraping(module_id, minutes_threshold=15):
#     """Check if ICT280 specifically should be skipped to prevent duplicates. Other modules always scrape."""

#     # Only apply duplicate prevention to ICT280 (Module ID: 2)
#     if module_id != 2:
#         return False  # Always scrape other modules

#     try:
#         from datetime import datetime, timedelta, timezone

#         # Get recent sessions
#         response = requests.get("http://127.0.0.1:8000/scrapersession/")
#         if response.status_code != 200:
#             return False

#         sessions = response.json()

#         # Use UTC time for consistency
#         utc_now = datetime.now(timezone.utc)
#         cutoff_time = utc_now - timedelta(minutes=minutes_threshold)

#         recent_sessions = []
#         for session in sessions:
#             try:
#                 session_time_str = session["started_at"]

#                 # Parse session time (assume UTC if no timezone info)
#                 if session_time_str.endswith("Z"):
#                     session_time = datetime.fromisoformat(
#                         session_time_str[:-1]
#                     ).replace(tzinfo=timezone.utc)
#                 elif "+" in session_time_str or session_time_str.count(":") > 2:
#                     session_time = datetime.fromisoformat(session_time_str)
#                 else:
#                     session_time = datetime.fromisoformat(session_time_str).replace(
#                         tzinfo=timezone.utc
#                     )

#                 # Ensure timezone aware comparison
#                 if session_time.tzinfo is None:
#                     session_time = session_time.replace(tzinfo=timezone.utc)

#                 # Only consider sessions that started within the threshold
#                 if session_time > cutoff_time:
#                     recent_sessions.append(session)

#             except Exception as e:
#                 print(f"Error parsing session time: {e}")
#                 continue

#         if not recent_sessions:
#             return False  # No recent sessions, safe to scrape

#         # Check if any recent session contains ICT280 content
#         response = requests.get("http://127.0.0.1:8000/scrapedcontents/")
#         if response.status_code == 200:
#             scraped_content = response.json()

#             # Count ICT280 items in recent sessions
#             ict280_items_count = 0
#             recent_session_ids = {s["session_id"] for s in recent_sessions}

#             for item in scraped_content:
#                 if (
#                     item.get("module_id") == 2
#                     and item.get("session_id") in recent_session_ids
#                 ):
#                     ict280_items_count += 1

#             # If ICT280 has more than 5 items in recent sessions, skip it
#             if ict280_items_count > 5:
#                 print(
#                     f"⚠️ ICT280 has {ict280_items_count} items in recent sessions - skipping to prevent duplicates"
#                 )
#                 return True

#             # Also check if ICT280 was scraped very recently (last 5 minutes)
#             #very_recent_cutoff = utc_now - timedelta(minutes=5)
#             #for session in sessions:
#             #    try:
#                     session_time_str = session["started_at"]

#                     # Parse session time
#                     if session_time_str.endswith("Z"):
#                         session_time = datetime.fromisoformat(
#                             session_time_str[:-1]
#                         ).replace(tzinfo=timezone.utc)
#                     elif "+" in session_time_str or session_time_str.count(":") > 2:
#                         session_time = datetime.fromisoformat(session_time_str)
#                     else:
#                         session_time = datetime.fromisoformat(session_time_str).replace(
#                             tzinfo=timezone.utc
#                         )

#                     # Ensure timezone aware comparison
#                     if session_time.tzinfo is None:
#                         session_time = session_time.replace(tzinfo=timezone.utc)

#                     if session_time > very_recent_cutoff:
#                         for item in scraped_content:
#                             if (
#                                 item.get("session_id") == session["session_id"]
#                                 and item.get("module_id") == 2
#                             ):
#                                 print(
#                                     f"⚠️ ICT280 was scraped very recently in session {session['session_id']} at {session_time}"
#                                 )
#                                 return True
#                 except Exception as e:
#                     continue

#         return False

#     except Exception as e:
#         print(f"⚠️ Error checking recent ICT280 scrapes: {e}")
#         return False


# def is_module_already_scraped_in_session(module_id, session_id):
#     """Check if ICT280 specifically has already been scraped in the current session. Other modules always scrape."""

#     # Only apply session-level duplicate prevention to ICT280 (Module ID: 2)
#     if module_id != 2:
#         return False  # Always scrape other modules

#     try:
#         response = requests.get("http://127.0.0.1:8000/scrapedcontents/")
#         if response.status_code == 200:
#             scraped_content = response.json()

#             # Check if ICT280 already has content in this session
#             for item in scraped_content:
#                 if item.get("module_id") == 2 and item.get("session_id") == session_id:
#                     return True

#         return False

#     except Exception as e:
#         print(
#             f"⚠️ Error checking if ICT280 already scraped in session {session_id}: {e}"
#         )
#         return False


async def batchScrape():
    """Scrape courses based on .env configuration"""
    print_config()

    # Auto-discover new courses if enabled
    if AUTO_DISCOVER_COURSES:
        print("🔍 Auto-discovering new courses...")
        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from scripts.discover_courses import (
            discover_courses,
            create_module,
            get_existing_modules,
            extract_unit_code,
        )

        try:
            discovered = await discover_courses()
            if discovered:
                existing_modules = get_existing_modules()
                existing_course_ids = {m["module_id"] + 1 for m in existing_modules}

                for course in discovered:
                    course_id = course["course_id"]
                    if course_id not in existing_course_ids:
                        unit_code = extract_unit_code(course["title"])
                        if unit_code:
                            module_id = create_module(
                                unit_code, course["title"], course_id
                            )
                            if module_id:
                                print(
                                    f"✅ Auto-created Module {module_id} for Course {course_id}: {unit_code}"
                                )
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

        # # Track which modules have been processed in this batch (ICT280 only)
        # processed_ict280 = False

        for module in moduleIdList:
            module_id = module["module_id"]
            course_id = module_id + 1  # Moodle course ID is module_id + 1
            unit_code = module.get("unit_code", f"Module_{module_id}")

            # # Check if ICT280 was already processed in this batch
            # if module_id == 2 and processed_ict280:
            #     print(
            #         f"⏭️ Skipping {unit_code} (Module ID: {module_id}, Course ID: {course_id}) - already processed in this batch"
            #     )
            #     continue

            # # Check if this module was scraped recently (ICT280 only)
            # if should_skip_module_scraping(module_id):
            #     print(
            #         f"⏭️ Skipping {unit_code} (Module ID: {module_id}, Course ID: {course_id}) - scraped recently"
            #     )
            #     continue

            # # Check if this module is already scraped in the current session (ICT280 only)
            # if is_module_already_scraped_in_session(module_id, sessionId):
            #     print(
            #         f"⏭️ Skipping {unit_code} (Module ID: {module_id}, Course ID: {course_id}) - already scraped in this session"
            #     )
            #     continue

            # # Mark ICT280 as being processed
            # if module_id == 2:
            #     processed_ict280 = True

            print(
                f"\n🕷️ Scraping {unit_code} (Module ID: {module_id}, Course ID: {course_id})"
            )

            base_url = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"
            print(f"📍 URL: {base_url}")

            try:
                print(f"📝 Starting scrape for {unit_code} at {datetime.now()}")
                await run_crawler(base_url, sessionId, module_id)
                print(f"✅ Completed scraping {unit_code} at {datetime.now()}")
            except Exception as e:
                print(f"❌ Failed to scrape {unit_code}: {e}")
                # # Reset ICT280 flag if it failed, so it can be retried later
                # if module_id == 2:
                #     processed_ict280 = False

        print(f"\n🎉 Batch scraping completed for {len(moduleIdList)} courses")

    else:
        # Single course scraping
        module_id = SINGLE_COURSE_MODULE_ID
        course_id = module_id + 1

        print(
            f"🕷️ Scraping single course (Module ID: {module_id}, Course ID: {course_id})"
        )

        base_url = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"
        print(f"📍 URL: {base_url}")

        try:
            await run_crawler(base_url, sessionId, module_id)
            print(f"✅ Completed scraping Module {module_id}")
        except Exception as e:
            print(f"❌ Failed to scrape Module {module_id}: {e}")


async def batchScrapeModules1and2():
    """Scrape both module_id = 1 (BSC203) and module_id = 2 (ICT280)"""
    print_config()

    sessionId = startsession()
    if not sessionId:
        print("❌ Failed to start session")
        return

    modules = [
        {"module_id": 1, "unit_code": "ICT280"},
    ]

    for mod in modules:
        module_id = mod["module_id"]
        unit_code = mod["unit_code"]
        course_id = module_id + 1
        base_url = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"

        print(
            f"\n🕷️ Scraping {unit_code} (Module ID: {module_id}, Course ID: {course_id})"
        )
        print(f"📍 URL: {base_url}")

        try:
            await run_crawler(base_url, sessionId, module_id)
            print(f"✅ Completed scraping {unit_code}")
        except Exception as e:
            print(f"❌ Failed to scrape {unit_code}: {e}")


async def batchAnalyse():
    scans = getRecentSessionScan()
    if DEBUG_MODE:
        print(f"🧪 Analyzing {len(scans)} links")

    # Deduplicate based on url_link (keep first occurrence only)
    seen = set()
    unique_scans = []
    for scan in scans:
        url = scan["url_link"]
        if url not in seen:
            seen.add(url)
            unique_scans.append(scan)

    # Count total + duplicates
    total_count = len(scans)
    unique_url_count = len(unique_scans)
    duplicate_count = total_count - unique_url_count

    print(
        f"🎯 Processing {total_count} total scans "
        f"({unique_url_count} unique URLs, {duplicate_count} duplicates ignored)"
    )

    # Sequentially analyze each unique URL
    # Sequentially analyze each unique URL
    for scan in unique_scans:
        is_paywall = scan["is_paywall"]
        url = scan["url_link"]

        print("=" * 50)
        print(f"URL: {url}")

        if is_paywall:
            print(
                "Link is paywall content. There is no need to send to reputation checker."
            )

            continue
        scrapeId = scan["scraped_id"]
        url = scan["url_link"]
        from urllib.parse import urlparse, urlunparse

        def normalize_url(url):
            parsed = urlparse(url)
            if not parsed.path or parsed.path.endswith("/"):
                return urlunparse(parsed._replace(path=parsed.path or "/"))
            elif "." not in parsed.path.split("/")[-1]:
                # if last segment has no dot (not a file), add slash
                return urlunparse(parsed._replace(path=parsed.path + "/"))
            return url  # already ends with a file extension

        normalizedurl = normalize_url(url)
        print(normalizedurl)

        print(f"🔍 Analyzing URL: {url}")

        try:
            analyze_links(scrapeId, normalizedurl)  # Direct call to sync function
        except Exception as e:
            print(f"❌ Error analyzing {url}: {e}")
            try:
                requests.put(
                    f"http://127.0.0.1:8000/scrapedcontents/updaterisk/{scrapeId}",
                    params={"score": 0, "category": "ANALYSIS_ERROR"},
                )
            except:
                pass

    # if DEBUG_MODE:
    #     print("🧪 Analysis complete:", getRecentSessionScan())


from reportgenerator.report import (
    generate_and_send_module_reports,
    generate_and_send_module_reports_to_security_officer,
)


async def batchReport():
    print("\n" + "=" * 60)
    print("🚀 Starting Module-Specific Report Generation")
    print("=" * 60 + "\n")

    # 📬 Unit Coordinators Report Generation
    print("Step 1: Generating and emailing reports to Unit Coordinators")
    print(" Only applicable for modules with flagged or unsafe links...\n")
    generate_and_send_module_reports()

    # 🔐 Security Officer Report Generation
    print("Step 2: Generating and emailing consolidated report to the Security Officer")
    print(" Includes all scanned modules and link classifications...\n")
    generate_and_send_module_reports_to_security_officer()

    print("✅ Report generation process completed.\n")


# async def batchReport():
#     if not GENERATE_REPORTS:
#         print("📊 Report generation disabled in .env")
#         return

#     # Use the same logic as the standalone report generator
#     from reportgenerator.report import fetch_all_links_by_module

#     print("🚀 Starting module-specific report generation...")
#     links_by_module = fetch_all_links_by_module()

#     if not links_by_module:
#         print("❌ No external links found for report generation")
#         return

#     # Generate reports for each module
#     for module_id, links in links_by_module.items():
#         print(f"\n📋 Module ID: {module_id} ({len(links)} external links)")

#         try:
#             moduleInfo = requests.get(
#                 f"http://127.0.0.1:8000/modules/{module_id}"
#             ).json()
#             uc_id = moduleInfo["uc_id"]
#             unitCoordinatorInfo = requests.get(
#                 f"http://127.0.0.1:8000/unitcoordinator/{uc_id}"
#             ).json()
#             unitCode = moduleInfo["unit_code"]
#             unitCoordinatorName = unitCoordinatorInfo["full_name"]
#             # Calculate course_id from module_id (course_id = module_id + 1)
#             course_id = module_id + 1
#             baseUrl = f"http://10.51.33.25/moodle/course/view.php?id={course_id}"

#             # Generate report
#             report_path = generatePDF(unitCoordinatorName, unitCode, links, baseUrl)
#             print(f"📊 Generated report: {report_path}")

#             # Send email if enabled
#             if SEND_EMAIL_REPORTS:
#                 unitCoordinatorEmail = unitCoordinatorInfo["email"]
#                 send_email_with_report(
#                     unitCoordinatorEmail, report_path, unitCode, unitCoordinatorName
#                 )
#                 print(f"📧 Email sent to: {unitCoordinatorEmail}")
#             else:
#                 print("📧 Email sending disabled in .env")

#         except Exception as e:
#             print(f"❌ Failed to generate report for Module {module_id}: {e}")


from reportgenerator.report import generate_apa7_citation


async def batchSaveToLocal():
    print("Running local page downloader...")
    savelocal.process_and_download_unique_safe_links()
    moduleIdList = getAllCourseId()
    if not moduleIdList:
        print("No modules found in database")
        return

    # print(f"[SAVE LOCAL] Found {len(moduleIdList)} courses to scrape")

    for module in moduleIdList:
        module_id = module["module_id"]
        allLocalAvailable = requests.get(
            f"http://127.0.0.1:8000/scrapedcontents/localcopyavailable/{module_id}"
        ).json()
        for link in allLocalAvailable:
            actualurl = link.get("url_link")
            scrapeid = link.get("scraped_id")
            citation = generate_apa7_citation(actualurl)
            updatecitationapi = f"http://127.0.0.1:8000/scrapedcontents/updatecitation/{scrapeid}?citation={citation}"

            response = requests.put(updatecitationapi)

            if response.status_code == 200:
                print("[CITATION] Citation updated successfully:", response.json())
            else:
                print("[CITATION FAILED] Failed to update:", response.text)


async def finalize_all_duplicate_updates():
    scans = getRecentSessionScan()
    url_to_scans = {}

    # Step 1: Group scans by URL
    for scan in scans:
        url = scan["url_link"]
        url_to_scans.setdefault(url, []).append(scan)

    # Step 2: Process each group
    for url, scan_group in url_to_scans.items():
        if len(scan_group) <= 1:
            continue  # No duplicates, skip

        base_scan = None
        score = None
        category = None

        # Step 3: Find the first scan WITH risk_score and risk_category
        for scan in scan_group:
            try:
                response = requests.get(
                    f"http://127.0.0.1:8000/scrapedcontents/get/{scan['scraped_id']}"
                )
                if response.status_code == 200:
                    data = response.json()
                    s = data.get("risk_score")
                    c = data.get("risk_category")
                    if s is not None and c is not None:
                        base_scan = scan
                        score = s
                        category = c
                        break  # ✅ Found usable base
            except Exception as e:
                print(f"❌ Error checking risk info for {scan['scraped_id']}: {e}")

        if base_scan is None:
            print(f"⚠️ No valid risk info found in duplicates for {url}")
            continue  # nothing to sync

        # Step 4: Update all other scans in the group to match the base
        for scan in scan_group:
            if scan["scraped_id"] == base_scan["scraped_id"]:
                continue  # skip base itself

            try:
                requests.put(
                    f"http://127.0.0.1:8000/scrapedcontents/updaterisk/{scan['scraped_id']}",
                    params={"score": score, "category": category},
                )
                print(f"✅ Synced risk info to {scan['scraped_id']} for {url}")
            except Exception as e:
                print(f"❌ Failed to update {scan['scraped_id']} for {url}: {e}")


import requests


def update_latest_session_status(status: str, error_log: str = None):
    try:
        # Step 1: Get latest session via API
        res = requests.get("http://10.51.33.25:8000/scrapersession/latest")
        res.raise_for_status()
        session = res.json()

        if not session:
            print("⚠️ No latest running session found.")
            return

        session_id = session["session_id"]

        # Step 2: Update the session status
        params = {"status": status}
        if error_log:
            params["error_log"] = error_log

        update_url = f"http://127.0.0.1:8000/scrapersession/update/{session_id}"
        update_res = requests.put(update_url, params=params)
        update_res.raise_for_status()

        print(f"✅ Session {session_id} updated to status '{status}'")

    except Exception as e:
        print(f"❌ Failed to update session status: {e}")


async def main():
    try:
        # await batchScrapeModules1and2()
        await batchScrape()
        await batchAnalyse()
        await finalize_all_duplicate_updates()
        await batchSaveToLocal()
        await batchReport()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received — exiting gracefully.")
        update_latest_session_status(
            "failed", "Scraper terminated due to keyboard interrupt input"
        )
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        update_latest_session_status("failed", str(e))
    else:
        update_latest_session_status("completed")
    finally:
        print("✅ LMS Guardian completed!")


if __name__ == "__main__":
    asyncio.run(main())

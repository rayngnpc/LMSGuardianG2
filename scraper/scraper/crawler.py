import os
import re
import asyncio
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse, unquote
from dotenv import load_dotenv
from playwright.async_api import async_playwright, Page
from .utils import *
import hashlib
import pytz
from .downloadfiles import *

# Import paywall detection
try:
    from ..paywall.main import detect_paywall_from_html
    PAYWALL_DETECTION_AVAILABLE = True
except ImportError:
    print("⚠️ Paywall detection not available - continuing without it")
    PAYWALL_DETECTION_AVAILABLE = False

load_dotenv(override=True)
USERNAME = os.getenv("MOODLE_USERNAME")
PASSWORD = os.getenv("MOODLE_PASSWORD")


# Configuration from Environment Variables
def str_to_bool(value: str) -> bool:
    """Convert string to boolean"""
    return value.lower() in ("true", "1", "yes", "on")


HEADLESS_BROWSER = str_to_bool(os.getenv("HEADLESS_BROWSER", "false"))
BROWSER_TIMEOUT = int(os.getenv("BROWSER_TIMEOUT", "60000"))
CRAWLER_DELAY_SECONDS = float(os.getenv("CRAWLER_DELAY_SECONDS", "0.5"))
SAVE_SCREENSHOTS = str_to_bool(os.getenv("SAVE_SCREENSHOTS", "true"))
DEBUG_MODE = str_to_bool(os.getenv("DEBUG_MODE", "false"))

# FOR LOCAL
# BASE_URL = "http://3.107.195.248/moodle/course/view.php?id="
# MOODLE_DOMAIN = "3.107.195.248"

# FOR PRODUCTION ENVIORNMENT
BASE_URL = "http://10.51.33.25/moodle/course/view.php?id="
MOODLE_DOMAIN = "10.51.33.25"

EXCLUDED_PATH_PREFIXES = [
    "/moodle/user/",
    "/moodle/message/",
    "/moodle/notes/",
    "/moodle/blog/",
    "/moodle/iplookup/",
    "/moodle/tag/",
    "/moodle/calendar/",
    "/moodle/report/usersessions/",
    "/moodle/admin/",
    "/moodle/enrol/",
    "/moodle/grade/report/overview/",
    "/moodle/competency/",
    "/moodle/user",
]

import requests


def is_publicly_accessible(url: str) -> tuple[bool, bool]:
    """
    Returns (is_reachable, is_login_required)
    """
    try:
        response = requests.get(url, allow_redirects=False, timeout=5)
        status = response.status_code
        location = response.headers.get("location", "").lower()

        # Common login indicators in redirect URL
        login_keywords = ["login", "signin", "auth", "session", "noauth", "login.aspx"]

        if status in (301, 302) and any(k in location for k in login_keywords):
            return (True, True)  # Reachable, but leads to login

        return (True, False)  # Reachable and no obvious login

    except requests.exceptions.RequestException:
        return (False, False)  # Not reachable at all


from urllib.parse import urlparse


def is_external_link(url: str) -> bool:
    """
    Returns True if the URL is considered external (i.e., not our local Moodle or trusted Murdoch domains).
    Treats local Moodle IP and all murdoch.edu.au domains as internal/trusted.
    """
    if not url or url.strip() == "" or url.startswith("mailto:"):
        return False  # Not a scrapable or external link

    # Internal/trusted domains (won't be scanned for security threats)
    internal_domains = [
        "10.51.33.25",  # local Moodle IP
    ]
    
    # All Murdoch domains are considered trusted (internal)
    trusted_murdoch_domains = [
        "murdoch.edu.au",
        "moodleprod.murdoch.edu.au", 
        "murdochuniversity.sharepoint.com",
        "goto.murdoch.edu.au",
        "libguides.murdoch.edu.au",
        "library.murdoch.edu.au",
        "our.murdoch.edu.au",
        "online.murdoch.edu.au",
        "myanswers.custhelp.com",  # Murdoch support system
    ]

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        
        # Check if it's our local internal domain
        if any(domain == d or domain.endswith(f".{d}") for d in internal_domains):
            return False  # Internal
            
        # Check if it's a trusted Murdoch domain
        if any(domain == d or domain.endswith(f".{d}") for d in trusted_murdoch_domains):
            return False  # Trusted, treat as internal
            
        # Check for any murdoch.edu.au subdomains
        if domain.endswith(".murdoch.edu.au") or domain == "murdoch.edu.au":
            return False  # All Murdoch domains are trusted
            
        # Everything else is external
        return True
        
    except Exception as e:
        print(f"[WARNING] Failed to parse URL: {url} - {e}")
        return True  # Treat unknowns as external for safety


def detect_paywall_for_url(url: str, html_content: str = None) -> bool:
    """
    Enhanced paywall detection with expanded domain coverage and improved patterns
    """
    
    # First try domain-based detection (fast and reliable)
    try:
        from urllib.parse import urlparse
        
        # Enhanced paywall domains - significantly expanded for better coverage
        PAYWALL_DOMAINS = {
            # Original major sites
            'wsj.com', 'ft.com', 'nytimes.com', 'bloomberg.com', 'economist.com',
            'washingtonpost.com', 'newyorker.com', 'theatlantic.com', 'jstor.org',
            'nature.com', 'science.org', 'springer.com', 'wiley.com', 'elsevier.com',
            
            # Additional news and magazine sites
            'spectator.co.uk', 'foreignaffairs.com', 'harpers.org', 'newstatesman.com',
            'thetimes.co.uk', 'telegraph.co.uk', 'vanityfair.com', 'wired.com',
            'medium.com', 'substack.com', 'politico.com', 'axios.com', 'forbes.com',
            'businessinsider.com', 'fortune.com', 'scientificamerican.com',
            'nationalgeographic.com', 'slate.com', 'salon.com', 'vox.com',
            
            # Academic and professional sites
            'ieee.org', 'acm.org', 'cambridge.org', 'oxford.org', 'tandfonline.com',
            'sagepub.com', 'jama.jamanetwork.com', 'nejm.org', 'bmj.com',
            'thelancet.com', 'cell.com', 'sciencedirect.com',
            
            # Trade and tech publications
            'techcrunch.com', 'venturebeat.com', 'recode.net', 'theverge.com',
            'arstechnica.com', 'engadget.com', 'gizmodo.com', 'mashable.com',
            'readwrite.com', 'gigaom.com', 'allthingsd.com', 'pandodaily.com',
            
            # Financial publications
            'marketwatch.com', 'investopedia.com', 'morningstar.com',
            'fool.com', 'seekingalpha.com', 'zacks.com', 'thestreet.com',
            'reuters.com', 'cnbc.com', 'barrons.com',
            
            # International publications
            'guardian.co.uk', 'independent.co.uk', 'dailymail.co.uk',
            'mirror.co.uk', 'express.co.uk', 'thesun.co.uk', 'standard.co.uk',
            'eveningstandard.co.uk', 'metro.co.uk', 'cityam.com',
            
            # Lifestyle and entertainment
            'gq.com', 'vogue.com', 'elle.com', 'marieclaire.com',
            'cosmopolitan.com', 'harpersbazaar.com', 'esquire.com',
            'rollingstone.com', 'people.com', 'time.com', 'newsweek.com',
            'usnews.com', 'usatoday.com', 'latimes.com', 'chicagotribune.com',
            
            # Sports and entertainment
            'espn.com', 'si.com', 'bleacherreport.com', 'nfl.com',
            'nba.com', 'mlb.com', 'nhl.com', 'variety.com',
            'hollywoodreporter.com', 'deadline.com', 'entertainment.com',
            
            # Subscription platforms
            'patreon.com', 'memberful.com', 'gumroad.com',
            'teachable.com', 'thinkific.com', 'kajabi.com', 'podia.com',
            
            # Learning platforms
            'coursera.org', 'udemy.com', 'skillshare.com', 'masterclass.com',
            'pluralsight.com', 'lynda.com', 'codecademy.com', 'treehouse.com',
            'edx.org', 'brilliant.org', 'datacamp.com'
        }
        
        # Enhanced URL patterns that indicate paywall/subscription content
        PAYWALL_PATTERNS = [
            '/subscribe', '/subscription', '/premium', '/member', '/membership',
            '/paywall', '/paid', '/pro', '/plus', '/upgrade', '/billing',
            '/checkout', '/payment', '/purchase', '/buy', '/pricing',
            '/plans', '/tiers', '/unlock', '/access', '/exclusive',
            '/vip', '/elite', '/gold', '/platinum', '/diamond',
            '/signin', '/login', '/register', '/signup', '/join',
            '/trial', '/demo', '/preview', '/teaser', '/excerpt'
        ]
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Primary method: Check for exact domain match
        if domain in PAYWALL_DOMAINS:
            print(f"🔒 Paywall detected for {url}: Known paywall domain ({domain})")
            return True
        
        # Check for subdomain matches
        for paywall_domain in PAYWALL_DOMAINS:
            if domain.endswith(paywall_domain):
                print(f"🔒 Paywall detected for {url}: Subdomain of paywall domain ({paywall_domain})")
                return True
        
        # Secondary method: URL pattern detection
        url_lower = url.lower()
        for pattern in PAYWALL_PATTERNS:
            if pattern in url_lower:
                print(f"🔒 Paywall detected for {url}: URL pattern ({pattern})")
                return True
        
        # If domain-based detection didn't find paywall, it's likely clean
        print(f"✅ No paywall detected for {url} (enhanced check)")
        return False
        
    except Exception as e:
        print(f"⚠️ Enhanced paywall detection failed for {url}: {e}")
    
    # Fallback to original detection method if available and domain check failed
    if not PAYWALL_DETECTION_AVAILABLE:
        return False
    
    try:
        if html_content:
            # Use HTML content if available
            result = detect_paywall_from_html(html_content)
        else:
            # Import and use the full detection method
            from ..paywall.main import classify_page_access
            result = classify_page_access(url)
        
        # Check if the result indicates paywall or controlled access
        status = result.get('status', '').lower()
        if status in ['paywalled', 'controlled_access']:
            print(f"🔒 Paywall detected for {url}: {result.get('reason', 'Unknown')}")
            return True
        elif status == 'unavailable':
            print(f"⚠️ Could not check paywall for {url}: {result.get('reason', 'Unknown')}")
            return False
        else:
            print(f"✅ No paywall detected for {url}")
            return False
            
    except Exception as e:
        print(f"❌ Error detecting paywall for {url}: {e}")
        return False


def post_scraped_link(
    session_id: int,
    module_id: int,
    url_link: str,
    risk_category: str = "unknown",
    is_paywall: bool = False,
    content_location: str = None,
    apa7: str = None,
    localurl: str = None,
):
    sg = pytz.timezone("Asia/Singapore")
    formattedSGtime = datetime.now(sg)
    print(formattedSGtime)
    payload = {
        "module_id": module_id,
        "session_id": session_id,
        "url_link": url_link,
        "scraped_at": formattedSGtime.isoformat(),
        "risk_category": risk_category,
        "is_paywall": is_paywall,
        "content_location": content_location,
        "apa7": apa7,
        "localurl": localurl,
    }
    try:
        response = requests.post("http://127.0.0.1:8000/scrapedcontents/", json=payload)
        response.raise_for_status()
        print(f"✅ Link stored: {url_link}")
    except Exception as e:
        print(f"❌ Failed to store link: {url_link} — {e}")


async def handle_login_flow(page: Page):
    print("Starting login flow...")
    if DEBUG_MODE:
        print("USERNAME:", USERNAME)
        print("PASSWORD:", PASSWORD)

    if "login" in page.url:
        print("Login page detected.")

        # Ensure full page load before interacting
        await page.wait_for_load_state("networkidle")
        await page.wait_for_selector('input[name="username"]')
        await page.wait_for_selector('input[name="password"]')

        # Screenshot before filling (if enabled)
        if SAVE_SCREENSHOTS:
            await page.screenshot(path="step1_login_page.png")

        # Fill credentials
        await page.fill('input[name="username"]', USERNAME or "")
        await page.fill('input[name="password"]', PASSWORD or "")

        # Screenshot after filling credentials (if enabled)
        if SAVE_SCREENSHOTS:
            await page.screenshot(path="step2_filled_credentials.png")

        # Try clicking the login button (supports both button types)
        try:
            await page.click('button[type="submit"]')
        except Exception:
            try:
                await page.click("input#loginbtn")
            except Exception as e:
                print(f"⚠️ Could not click login button: {e}")
                if SAVE_SCREENSHOTS:
                    await page.screenshot(path="step2b_click_error.png")
                return

        # Wait for next page to load
        await page.wait_for_load_state("networkidle")
        if SAVE_SCREENSHOTS:
            await page.screenshot(path="step3_after_submit.png")

        # Check if login was successful
        if "login" in page.url:
            print("❌ Login failed. Still on login page.")
            if DEBUG_MODE:
                html = await page.content()
                with open("login_failed_dump.html", "w", encoding="utf-8") as f:
                    f.write(html)
        else:
            print(f"✅ Login successful. URL: {page.url}")
            if SAVE_SCREENSHOTS:
                await page.screenshot(path="step4_login_success.png")
    else:
        print("✅ Already logged in or no login required.")


async def expand_internal_toggles(page: Page):
    toggles = await page.query_selector_all(
        '#page-content a[data-for="sectiontoggler"]'
    )

    if not toggles:
        print("No section toggles found.")
        return

    for toggle in toggles:
        try:
            is_expanded = await toggle.get_attribute("aria-expanded")
            if is_expanded == "false":
                await toggle.click()
                print("✅ Toggle clicked to expand section.")
            else:
                print("⏭️ Section already expanded. Skipping.")
        except Exception as e:
            print(f"⚠️ Failed to handle toggle: {e}")


async def get_content_type_with_playwright(context, url: str) -> str:
    content_type_result = "unknown"
    page = await context.new_page()

    def handle_response(response):
        nonlocal content_type_result
        if response.url == url:
            headers = response.headers
            content_type_result = headers.get("content-type", "unknown")

    page.on("response", handle_response)

    try:
        await page.goto(url, wait_until="load", timeout=60000)
    except Exception as e:
        if "net::ERR_ABORTED" not in str(e) and "pluginfile.php" not in url:
            print(f"⚠️ Failed to load {url} — {e}")
    finally:
        await page.close()

    return content_type_result


import os
import hashlib
from urllib.parse import urlparse, unquote
from playwright.async_api import Page


async def storeTempRepoWithPlaywright(page: Page, url: str, ftype: str, downloaded_files: set) -> str | None:
    if is_possibly_malicious(url, ftype):
        print(f"⚠️ Skipped potentially dangerous file: {url} ({ftype})")
        return None

    if not ftype.startswith("text/html"):
        try:
            # --- Extract filename from URL ---
            parsed_url = urlparse(url)
            raw_name = os.path.basename(parsed_url.path)
            raw_name = unquote(raw_name)  # Decode URL-encoded characters

            # Fallback if filename is empty or doesn't have an extension
            if not raw_name or "." not in raw_name:
                extension = getFileExtension(ftype)
                raw_name = f"downloaded_file{extension}"

            # Remove any potential directory traversal characters
            filename = os.path.basename(raw_name)
            
            # Check if this file has already been downloaded
            file_key = f"{filename}_{ftype}"
            if file_key in downloaded_files:
                print(f"⏭️ SKIP: {filename} already downloaded")
                return None
            
            # Add to downloaded files set
            downloaded_files.add(file_key)

            response = await page.request.get(url)
            if response.status != 200:
                print(f"❌ Response error: {response.status} for {url}")
                return None

            target_dir = os.path.join("scraper", "scraper", "toProcessFurther")
            os.makedirs(target_dir, exist_ok=True)
            save_path = os.path.join(target_dir, filename)

            # Save the file content
            content = await response.body()
            with open(save_path, "wb") as f:
                f.write(content)

            print(f"📥 SAVED: {url} → {save_path}")
            return save_path

        except Exception as e:
            print(f"❌ Failed to download via Playwright: {url} — {e}")
            return None


async def resolve_final_resource_url(page: Page, url: str) -> str | None:
    """
    Resolves the actual file or external content URL behind a Moodle mod/resource link.
    Handles direct pluginfile URLs, downloads, iframe previews, and HTML-based redirects.
    """

    file_extensions = [
        ".pdf",
        ".docx",
        ".pptx",
        ".zip",
        ".doc",
        ".ppt",
        ".xls",
        ".xlsx",
    ]

    def looks_like_file_url(u: str) -> bool:
        last_segment = re.split(r"[/?&]", u.split("/")[-1])[-1].lower()
        return any(last_segment.endswith(ext) for ext in file_extensions)

    # 🥇 0. Direct file URL (Method 2 first)
    if looks_like_file_url(url):
        print("METHOD 2 (FAST) \n")
        print(f"📄 URL already looks like a file: {url}")
        return url

    # 🧼 1. Sanity check for typical Moodle mod/resource links
    if not re.search(r"/mod/resource/view\.php\?id=\d+", url):
        print(f"⚠️ Malformed or suspicious resource URL skipped: {url}")
        return None

    # 🥈 2. Try to detect file request for known extensions
    try:
        async with page.expect_request(
            lambda r: any(ext in r.url.lower() for ext in file_extensions),
            timeout=8000,
        ) as req_info:
            try:
                await page.goto(url, wait_until="commit")
            except Exception as e:
                print(f"⚠️ Navigation error (request-level): {e}")
        request = await req_info.value
        print("METHOD 2 \n")
        print(f"🔗 File request captured: {request.url}")
        return request.url
    except Exception as e:
        print(f"🕵️ No direct file request captured: {e}")

    # 🥉 3. Fallback: Try to capture a file download (Method 1)
    try:
        async with page.expect_download(timeout=10000) as download_info:
            try:
                await page.goto(url, wait_until="commit")
            except Exception as e:
                print(f"⚠️ Navigation interrupted (likely due to download): {e}")
        download = await download_info.value
        print("METHOD 1 \n")
        print(f"📥 Detected file download: {download.url}")
        return download.url
    except Exception as e:
        print(f"🕵️ No file download captured: {e}")

    # 🏁 4. Fallback: Check for iframe or redirect-based HTML structures
    try:
        await page.goto(url, wait_until="domcontentloaded")

        for frame in page.frames:
            if frame.url != page.url:
                print("METHOD 3 \n")
                print(f"🖼️ Iframe found: {frame.url}")
                return frame.url

        html = await page.content()

        match_meta = re.search(
            r'<meta http-equiv=["\']refresh["\'] content=["\']\d+;url=([^"\']+)',
            html,
            re.IGNORECASE,
        )
        if match_meta:
            redirect_url = match_meta.group(1)
            print("METHOD 3 \n")
            print(f"🔁 Meta refresh detected: {redirect_url}")
            return redirect_url

        match_js = re.search(r'window\.location\s*=\s*["\']([^"\']+)', html)
        if match_js:
            redirect_url = match_js.group(1)
            print("METHOD 3 \n")
            print(f"🔁 JS redirect detected: {redirect_url}")
            return redirect_url

    except Exception as e:
        print(f"❌ Fallback parsing failed: {e}")

    print("🚫 No file, iframe, or redirect target found.")
    return None


EXCLUDED_FULL_URL_KEYWORDS = [
    "login",  # generic
    "signin",  # often used in Google/Outlook
    "auth",  # e.g., /auth/session
    "microsoftonline",  # specific
    "accounts.google.com",
    "teams.microsoft.com/light-meetings",
    "teams.microsoft.com/meeting",
]


from urllib.parse import unquote


def is_blocked_url(url: str) -> bool:
    decoded_url = unquote(url.lower())
    if "teams.microsoft.com" in decoded_url:
        print(f"[BLOCKED LINKS] Skipped teams link: {url}")
        return True
    return any(keyword in decoded_url for keyword in EXCLUDED_FULL_URL_KEYWORDS)


async def extract_links(page: Page, base_url: str, session_id: int, module_id: int, downloaded_files: set):
    await page.wait_for_selector("#page-content")
    anchors = await page.query_selector_all("#page-content a")

    links_to_crawl_further = []
    external_links = []
    collected_links = []

    for anchor in anchors:
        try:
            if await anchor.get_attribute("data-region") == "post-action":
                continue
            href = await anchor.get_attribute("href")
            original_url = await anchor.get_attribute("data-original-url")

            if not href or href.startswith("#"):
                continue

            # Ignore local mirrors completely
            if href.startswith("/localrepo/"):
                continue

            # Use original URL if available, else fall back to href
            scan_url = urljoin(base_url, original_url if original_url else href)

            class_attr = await anchor.get_attribute("class") or ""
            if "btn" in class_attr:
                continue  # Skip navigation buttons

            collected_links.append(scan_url)

        except:
            continue

    for full_url in collected_links:
        # Check if it's an external link first (this applies to all link types)
        # check if initial url already has login in its name
        if is_blocked_url(full_url):
            print(f"[BLOCKED LINKS] Blocked due to pattern match: {full_url}")
            continue
        if is_external_link(full_url):
            print("EXTERNAL URL DETECTED")

            # Detect paywall for external links
            is_paywall = detect_paywall_for_url(full_url)
            
            external_links.append(full_url)
            post_scraped_link(session_id, module_id, full_url, is_paywall=is_paywall)
            continue

        if "mod/resource/view.php" in full_url:
            try:
                resolved_url = await resolve_final_resource_url(page, full_url)
                if is_blocked_url(resolved_url):
                    print(f"🚫 Skipping resolved blocked URL: {resolved_url}")
                    continue

                print(f"📎 Found file: {resolved_url} — from {full_url}")
                if not resolved_url:
                    continue

                # Check if resolved URL is external
                if is_external_link(resolved_url):
                    print(
                        "EXTERNAL FILE URL DETECTED AFTER RESOLVING INTERNAL MIDDLEWARE"
                    )
                    
                    # Detect paywall for external resolved URLs
                    is_paywall = detect_paywall_for_url(resolved_url)
                    
                    external_links.append(resolved_url)
                    post_scraped_link(session_id, module_id, resolved_url, is_paywall=is_paywall)
                    continue

                # Apply exclusion rules only to internal URLs
                if should_exclude_url(resolved_url):
                    print(f"🚫 Skipping excluded internal URL: {resolved_url}")
                    continue

                mime_type = await get_content_type_with_playwright(
                    page.context, resolved_url
                )
                print(f"📎 File Type: {mime_type}")

                if mime_type.startswith("text/html"):
                    links_to_crawl_further.append(resolved_url)
                else:
                    if not is_possibly_malicious(resolved_url, mime_type):
                        await storeTempRepoWithPlaywright(page, resolved_url, mime_type, downloaded_files)
                        print("📥 Internal file saved for processing")

                continue
            except Exception as e:
                print(f"❌ Failed to resolve file: {e}")
                continue

        # For non-resource internal URLs, apply exclusion rules
        if should_exclude_url(full_url):
            print(f"🚫 Skipping excluded internal URL: {full_url}")
            continue

        mime_type = await get_content_type_with_playwright(page.context, full_url)

        if not is_possibly_malicious(full_url, mime_type):
            await storeTempRepoWithPlaywright(page, full_url, mime_type, downloaded_files)

        print(f"INTERNAL URL: {mime_type} — {full_url}")

        if mime_type.startswith("text/html"):
            # Skip problematic external Murdoch domains that we can't access
            if "moodleprod.murdoch.edu.au" in full_url and "10.51.33.25" not in full_url:
                print(f"🚫 Skipping external Murdoch domain (access issues): {full_url}")
            else:
                links_to_crawl_further.append(full_url)
        else:
            print("📥 Internal file saved for processing")

    print(f"[INTERNAL LINKS] Found {len(links_to_crawl_further)} at: {base_url}")
    print(f"[EXTERNAL LINKS] Found {len(external_links)} at: {base_url}")
    return links_to_crawl_further


async def crawl_page(page: Page, url: str, session_id: int, module_id: int, downloaded_files: set):
    print(f"🌐 Visiting: {url}")
    try:
        await page.goto(url, wait_until="load")
    except:
        print(f"⚠️ Failed to load: {url}")
        return []

    if "login" in page.url or "Continue" in await page.content():
        await handle_login_flow(page)
        await page.goto(url, wait_until="load")  # reload after login

    meta_tags = await page.query_selector_all("meta[content]")
    for tag in meta_tags:
        content_val = await tag.get_attribute("content")
        print(f"✅ Meta content value: {content_val}")

    title = await page.title()
    print(f"📄 Page title: {title}")

    # ⛏ Try to extract Moodle's internal course ID
    course_id = await page.evaluate(
        """() => {
            if (window.M && M.cfg && M.cfg.courseId) {
                return M.cfg.courseId;
            }
            return null;
        }"""
    )

    if course_id is None or course_id != module_id + 1:
        print(f"🚫 No M.cfg.courseId found — treating as external link.")
        return []

    print(f"🎯 Course ID (from M.cfg): {course_id}")

    await expand_internal_toggles(page)
    return await extract_links(page, url, session_id, module_id, downloaded_files)


async def run_crawler(starting_page: str, session_id: int, module_id: int):
    if DEBUG_MODE:
        print(
            f"🔧 Browser Config: Headless={HEADLESS_BROWSER}, Timeout={BROWSER_TIMEOUT}ms, Delay={CRAWLER_DELAY_SECONDS}s"
        )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=HEADLESS_BROWSER)
        context = await browser.new_context()
        context.set_default_timeout(BROWSER_TIMEOUT)
        page = await context.new_page()

        pages_to_check = [starting_page]
        pages_already_seen = set()
        pages_visited = []
        # Add file deduplication tracking
        downloaded_files = set()

        while pages_to_check:
            current_page = pages_to_check.pop(0)
            clean_page_url = normalize_url(current_page)

            if clean_page_url in pages_already_seen:
                continue

            pages_already_seen.add(clean_page_url)
            print(f"[CHECK] {current_page}")

            found_links = await crawl_page(page, current_page, session_id, module_id, downloaded_files)
            pages_visited.append(current_page)

            for link in found_links:
                clean_link = normalize_url(link)
                if DEBUG_MODE:
                    print(f"[FOUND] Cleaned link: {clean_link}")

                if clean_link not in pages_already_seen:
                    pages_to_check.append(clean_link)

            await asyncio.sleep(CRAWLER_DELAY_SECONDS)

        # Second loop for scanned file links
        downloaded_links = downloadFilesAndCheck()
        unique_links = list(set(downloaded_links))

        # Post only valid, external links after crawling them
        for link in unique_links:
            if is_external_link(link):
                print(f"[FROM DOCUMENT] External link detected → posting: {link}")
                post_scraped_link(session_id, module_id, link)
            else:
                print(f"[SKIP] Internal or Murdoch-owned link → ignored: {link}")

        await browser.close()

        print("\n✅ Crawling complete.")
        print(f"📦 Summary for module_id: {module_id}\n")

        # Print visited internal links
        print("🔗 Internal links that were expanded:")
        if pages_visited:
            for url in pages_visited:
                print(f"   - {url}")
        else:
            print("   (none)")

        # Fetch and print external links
        try:
            response = requests.get("http://127.0.0.1:8000/scrapedcontents/scan")
            response.raise_for_status()
            data = response.json()

            external_links = [
                item.get("url_link")
                for item in data
                if item.get("module_id") == module_id
            ]

            print("\n🌐 External links that were found:")
            if external_links:
                for url in external_links:
                    print(f"   - {url}")
            else:
                print("   (none)")

        except requests.exceptions.RequestException as e:
            print(f"\n❌ Failed to fetch external link data: {e}")

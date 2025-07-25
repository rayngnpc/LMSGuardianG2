import json
import requests
import urllib.parse
import os
import time
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup
from dotenv import load_dotenv


VT_API_KEY = (
    # os.getenv("VT_API_KEY")
    # or
    "f2ac01e460409228a6376e95732096b7e76f8c33df0f864b2be1f16325cbb1e9"
)
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_KEY")

VT_URL_REPORT = "https://www.virustotal.com/vtapi/v2/url/report"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/"


# --------------------------------
# 🎯 Smart Domain Filtering
# --------------------------------
TRUSTED_DOMAINS = {
    # Educational institutions - Australia
    "edu.au",
    "murdoch.edu.au",
    "moodleprod.murdoch.edu.au",
    "goto.murdoch.edu.au",
    "libguides.murdoch.edu.au",
    "library.murdoch.edu.au",
    "our.murdoch.edu.au",
    "online.murdoch.edu.au",
    "murdochuniversity.sharepoint.com",
    "rmit.edu.au",
    "emedia.rmit.edu.au",
    "dlsweb.rmit.edu.au",
    "unsw.edu.au",
    "student.unsw.edu.au",
    "usyd.edu.au",
    "uq.edu.au",
    "monash.edu",
    "anu.edu.au",
    "griffith.edu.au",
    "qut.edu.au",
    "curtin.edu.au",
    "deakin.edu.au",
    "swinburne.edu.au",
    "uts.edu.au",
    # Educational institutions - International
    "wikipedia.org",
    "wikimedia.org",
    "en.wikipedia.org",
    "ac.uk",
    "cam.ac.uk",
    "ox.ac.uk",
    "imperial.ac.uk",
    "ucl.ac.uk",
    "kcl.ac.uk",
    "manchester.ac.uk",
    "ed.ac.uk",
    "warwick.ac.uk",
    "edu",
    "harvard.edu",
    "mit.edu",
    "stanford.edu",
    "berkeley.edu",
    "caltech.edu",
    "princeton.edu",
    "yale.edu",
    "columbia.edu",
    "ac.nz",
    "edu.sg",
    "edu.ca",
    "uni.de",
    "ac.jp",
    "edu.cn",
    "khanacademy.org",
    "coursera.org",
    "edx.org",
    "udacity.com",
    "codecademy.com",
    "duolingo.com",
    # Government domains
    "gov.au",
    "gov.uk",
    "gov.sg",
    "gov",
    "government",
    "gov.ca",
    "gov.nz",
    "gov.de",
    "gov.fr",
    "gov.in",
    "gov.jp",
    "gov.cn",
    "europa.eu",
    "nea.gov.sg",
    "ato.gov.au",
    "aihw.gov.au",
    "abs.gov.au",
    "rba.gov.au",
    "treasury.gov.au",
    "health.gov.au",
    "education.gov.au",
    "nih.gov",
    "nasa.gov",
    "cdc.gov",
    "fda.gov",
    "sec.gov",
    "who.int",
    "un.org",
    # Technology & Documentation
    "docs.python.org",
    "python.org",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "stackexchange.com",
    "developer.mozilla.org",
    "w3.org",
    "docs.oracle.com",
    "docs.microsoft.com",
    "developer.apple.com",
    "developer.android.com",
    "nodejs.org",
    "java.com",
    "oracle.com",
    "php.net",
    "ruby-lang.org",
    "golang.org",
    "rust-lang.org",
    "scala-lang.org",
    "kotlinlang.org",
    "apache.org",
    "gnu.org",
    "opensource.org",
    "linux.org",
    "mozilla.org",
    "eclipse.org",
    "kernel.org",
    # Major Technology Companies
    "microsoft.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "office.com",
    "sharepoint.com",
    "onedrive.com",
    "xbox.com",
    "msn.com",
    "bing.com",
    "skype.com",
    "linkedin.com",
    "google.com",
    "gmail.com",
    "youtube.com",
    "android.com",
    "chrome.com",
    "chromium.org",
    "googleadservices.com",
    "googlesource.com",
    "googleusercontent.com",
    "apple.com",
    "icloud.com",
    "itunes.com",
    "appstore.com",
    "mac.com",
    "me.com",
    "amazon.com",
    "amazonaws.com",
    "aws.amazon.com",
    "adobe.com",
    "salesforce.com",
    "sap.com",
    "vmware.com",
    "cisco.com",
    "intel.com",
    "nvidia.com",
    "ibm.com",
    "redhat.com",
    "canonical.com",
    # News & Media (Reputable)
    "ft.com",
    "wsj.com",
    "reuters.com",
    "bloomberg.com",
    "economist.com",
    "marketwatch.com",
    "cnbc.com",
    "bbc.com",
    "cnn.com",
    "theguardian.com",
    "nytimes.com",
    "washingtonpost.com",
    "npr.org",
    "pbs.org",
    "abc.net.au",
    "sbs.com.au",
    "news.com.au",
    "smh.com.au",
    "theage.com.au",
    "theaustralian.com.au",
    # Academic Publishers & Research
    "springer.com",
    "elsevier.com",
    "wiley.com",
    "nature.com",
    "sciencedirect.com",
    "tandfonline.com",
    "sagepub.com",
    "ieee.org",
    "acm.org",
    "aaas.org",
    "aps.org",
    "rsc.org",
    "researchgate.net",
    "academia.edu",
    "scholar.google.com",
    "pubmed.ncbi.nlm.nih.gov",
    "arxiv.org",
    "ssrn.com",
    # Cloud & Infrastructure
    "amazonaws.com",
    "azure.com",
    "googlecloud.com",
    "digitalocean.com",
    "linode.com",
    "vultr.com",
    "cloudflare.com",
    "cloudfront.net",
    "fastly.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.com",
    # Financial Services (Established)
    "jpmorgan.com",
    "goldmansachs.com",
    "morganstanley.com",
    "citigroup.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "commbank.com.au",
    "anz.com",
    "nab.com.au",
    "westpac.com.au",
    "paypal.com",
    "stripe.com",
    "square.com",
    "visa.com",
    "mastercard.com",
    "amex.com",
}

# Enhanced pattern matching for educational and government domains
TRUSTED_PATTERNS = {
    "EDUCATIONAL": [
        ".edu",
        ".ac.uk",
        ".edu.au",
        ".ac.nz",
        ".edu.sg",
        ".edu.ca",
        ".uni.de",
    ],
    "GOVERNMENT": [".gov", ".gov.au", ".gov.uk", ".gov.sg", ".gov.ca", ".gov.nz"],
    "RESEARCH": [".int"],  # For international research organizations
}

SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".pw",
    ".top",
    ".click",
    ".download",
    ".stream",
    ".science",
    ".racing",
    ".win",
}


def is_trusted_domain(url: str) -> bool:
    """Enhanced trusted domain detection with better URL handling"""
    try:
        # Handle URLs without protocol
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url.lower())
        domain = parsed.netloc.lower()

        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]

        # 1. Check exact match in trusted domains
        if domain in TRUSTED_DOMAINS:
            return True

        # 2. Check pattern matching for educational and government TLDs
        for category, patterns in TRUSTED_PATTERNS.items():
            for pattern in patterns:
                if domain.endswith(pattern):
                    return True

        # 3. Check if domain is a subdomain of any trusted domain
        for trusted in TRUSTED_DOMAINS:
            if domain.endswith("." + trusted) or domain == trusted:
                return True

        return False
    except:
        return False


def needs_full_scan(url: str) -> bool:
    """Determine if URL needs full multi-API scanning"""
    try:
        parsed = urlparse(url.lower())
        domain = parsed.netloc.lower()

        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True

        # Check for suspicious patterns
        suspicious_patterns = [
            "bit.ly",
            "tinyurl",
            "shortened",
            "redirect",
            "download",
            "crack",
            "hack",
            "free",
            "porn",
            "xxx",
            "adult",
            "sex",
            "casino",
            "pharma",
        ]

        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                return True

        return False
    except:
        return True  # Default to full scan if parsing fails


# --------------------------------
# 🔎 Utilities
# --------------------------------
def extract_domain_from_url(url: str) -> str:
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain[4:] if domain.startswith("www.") else domain
    except Exception as e:
        print(f"❌ Error parsing URL: {e}")
        return ""


def clean_and_validate_url(url: str) -> str:
    """Clean and validate URLs before processing"""
    if not url or not url.strip():
        return None

    # Remove extra characters and fix common issues
    url = url.strip()
    url = url.strip("()")  # Remove parentheses
    url = url.rstrip(".")  # Remove trailing periods

    # Skip URLs that are clearly text fragments, not actual URLs
    if any(
        keyword in url.lower()
        for keyword in [
            "ontario, canada:",
            "university of waterloo",
            "available from",
            "provides links to",
            "many organizations",
            "information systems audit",
            "hosts seminars",
            "source for recommended",
        ]
    ):
        return None

    # Extract actual URL from text if it contains URL patterns
    import re

    url_pattern = r"https?://[^\s\)]+|www\.[^\s\)]+\.[a-zA-Z]{2,}"
    url_match = re.search(url_pattern, url)
    if url_match:
        url = url_match.group()

    # Fix common URL issues
    if url.startswith("www.") and not url.startswith("http"):
        url = "https://" + url

    # Skip obviously malformed URLs or text fragments
    if not url.startswith(("http://", "https://")):
        return None

    # Skip URLs that are clearly not actual websites
    if any(
        invalid in url.lower()
        for invalid in [
            "ontario,",
            "canada:",
            "university of",
            "available from",
            "provides links",
            "many organizations",
            "information systems",
        ]
    ):
        return None

    # Final validation
    try:
        parsed = urlparse(url)
        if not parsed.netloc or not parsed.scheme:
            return None

        # Check if domain looks valid
        if "." not in parsed.netloc:
            return None

        return url
    except Exception:
        return None


# --------------------------------
# 🧪 VirusTotal Domain Scan (v3)
# --------------------------------
def get_report_given_domain(domain):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_DOMAIN_REPORT}/{domain}", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Domain report failed with status code {response.status_code}")
        return None


def getscanresults(url):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_URL_SCAN}/{url=}", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Domain report failed with status code {response.status_code}")
        return None


def getAnalysisOfExternalLinks(domain: str):
    reports_file = "scraper/reputation/output/reports.json"
    # report = get_report_given_domain(domain)
    report = getscanresults(domain)

    if not report:
        return None

    os.makedirs(os.path.dirname(reports_file), exist_ok=True)
    with open(reports_file, "w") as f:
        json.dump(report, f, indent=2)

    try:
        attributes = report["data"]["attributes"]
        domain = report["data"]["id"]
        reputation = attributes.get("reputation", "")
        categories = attributes.get("categories", {})
        category_values = ", ".join(categories.values())

        print("\nVirusTotal Analysis")
        print(f"Domain: {domain}")
        print(f"Reputation: {reputation}")
        print(f"Categories: {category_values}\n")

        return domain, reputation, category_values
    except Exception as e:
        print(f"❌ Error processing domain report: {e}")
        return None


# --------------------------------
# 🧪 VirusTotal URL Scan (v2)
# --------------------------------
def get_url_report(target_url):
    params = {"apikey": VT_API_KEY, "resource": target_url}
    try:
        return requests.get(VT_URL_REPORT, params=params).json()
    except Exception as e:
        return {"error": str(e)}


def submit_url_for_scan(target_url):
    data = {"apikey": VT_API_KEY, "url": target_url}
    try:
        return requests.post(VT_URL_SCAN, data=data).json()
    except Exception as e:
        return {"error": str(e)}


def get_or_scan_url(target_url, wait_for_fresh=False):
    print(f"🔍 Checking VirusTotal for: {target_url}")
    report = get_url_report(target_url)

    if report.get("response_code") == 1:
        print(f"✅ Cached: {report['positives']}/{report['total']} detections")
        return report

    print("❌ No cached report. Submitting for scan...")
    scan_response = submit_url_for_scan(target_url)

    if not wait_for_fresh:
        print("📤 Submitted. Results will be ready soon.")
        return scan_response

    print("⏳ Waiting for fresh scan...")
    for _ in range(10):
        time.sleep(3)  # Reduced from 10 to 3 seconds
        report = get_url_report(target_url)
        if report.get("response_code") == 1:
            print(f"✅ Scan complete: {report['positives']}/{report['total']}")
            return report

    return {"error": "Timeout waiting for scan"}

    # --------------------------------
    # 🔐 Google Safe Browsing
    # --------------------------------


def check_safe_browsing(url):
    """Check URL against Google Safe Browsing API"""
    if not SAFE_BROWSING_API_KEY:
        print("❌ Google Safe Browsing API key not found")
        return None

    payload = {
        "client": {"clientId": "lms-guardian", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5,
        )
        response.raise_for_status()
        result = response.json()

        if result.get("matches"):
            threat_type = result["matches"][0].get("threatType", "MALICIOUS")
            print(f"🚨 Google Safe Browsing detected threat: {threat_type}")

            # Map threat types to scores
            threat_scores = {
                "MALWARE": 95,
                "SOCIAL_ENGINEERING": 90,
                "UNWANTED_SOFTWARE": 80,
                "POTENTIALLY_HARMFUL_APPLICATION": 70,
                "THREAT_TYPE_UNSPECIFIED": 60,
            }

            score = threat_scores.get(threat_type, 85)
            category = f"GOOGLE_SAFE_BROWSING_{threat_type}"

            return (score, category)
        else:
            print("✅ Google Safe Browsing: URL is clean")
            return (0, "GOOGLE_SAFE_BROWSING_CLEAN")

    except Exception as e:
        print(f"❌ Safe Browsing error: {e}")
        return None


def vt_v3_get_url_info(url, save_dir="vt_reports"):
    """
    Get URL information from VirusTotal v3 API and save the response to a JSON file.
    Returns: (reputation, categories) tuple on success, None on failure
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(endpoint, headers=headers, timeout=8)

        if response.status_code == 200:
            data = response.json()

            # Save JSON response to file
            os.makedirs(save_dir, exist_ok=True)
            safe_filename = url.replace("://", "_").replace("/", "_")
            with open(f"{save_dir}/{safe_filename}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            stats = data["data"]["attributes"].get("categories", {})
            # this category is not used by VirusTotal usually unless its overwhelmingly reported
            # reputation = data["data"]["attributes"].get("reputation", 0)
            reputation = data["data"]["attributes"]["last_analysis_stats"].get(
                "malicious", 0
            )
            reputation = -reputation

            category_values = list(stats.values())
            categories = (
                ", ".join(category_values) if category_values else "UNCATEGORIZED"
            )

            print("\nVirusTotal URL Report")
            print(f"URL: {url}")
            print(f"Reputation Score: {reputation}")
            print(f"Categories: {categories}")

            return reputation, categories

        elif response.status_code in [404, 403, 429]:
            print(f"\nVirusTotal Error {response.status_code} for {url}")
            print(f"Response: {response.text}")
            return None

        else:
            print(f"\nUnexpected VirusTotal API Error for {url}")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"\nVirusTotal request failed for {url}: {e}")
        return None


import requests


import requests
from urllib.parse import urlparse


def is_publicly_accessible(url: str) -> tuple[bool, bool]:
    """
    Returns (is_reachable, is_login_required)
    - is_reachable: True if the URL responded with a valid status
    - is_login_required: True if URL or any redirect appears to lead to a login page
    """
    login_keywords = ["login", "signin", "auth", "session", "noauth", "login.aspx"]

    try:
        # Follow redirects to get the final landing page
        response = requests.get(url, allow_redirects=True, timeout=5)
        final_url = response.url.lower()
        status = response.status_code

        # Check if final URL or redirect location contains login keywords
        if any(k in final_url for k in login_keywords):
            return (True, True)

        # If 200 OK and no login-related patterns, assume it's public
        if status == 200:
            return (True, False)

        # Redirects without login hint (optional)
        if status in (301, 302):
            location = response.headers.get("location", "").lower()
            if any(k in location for k in login_keywords):
                return (True, True)
            return (True, False)

        # Other unexpected status codes
        return (False, False)

    except requests.exceptions.SSLError as e:
        print(f"🔒 SSL Error for {url}: {e}")
        try:
            # Try without SSL verification for problematic certificates
            response = requests.get(url, allow_redirects=True, timeout=5, verify=False)
            print(f"⚠️ SSL verification bypassed for {url}")
            return (True, False)
        except requests.exceptions.RequestException:
            return (False, False)

    except requests.exceptions.Timeout as e:
        print(f"⏰ Timeout accessing {url}: {e}")
        return (False, False)

    except requests.exceptions.ConnectionError as e:
        print(f"🔌 Connection error for {url}: {e}")
        return (False, False)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Connection failed for {url}: {e}")
        return (False, False)


# --------------------------------
# 🧠 Main Risk Analysis
# --------------------------------
import time
import requests


def should_skip_url_scanning(url: str) -> bool:
    """
    Check if URL should be skipped from security scanning
    """
    # Skip all Murdoch University domains (trusted institution)
    murdoch_domains = [
        "murdoch.edu.au",
        "moodleprod.murdoch.edu.au",
        "goto.murdoch.edu.au",
        "libguides.murdoch.edu.au",
        "library.murdoch.edu.au",
        "our.murdoch.edu.au",
        "online.murdoch.edu.au",
        "murdochuniversity.sharepoint.com",
    ]

    url_lower = url.lower()
    for domain in murdoch_domains:
        if domain in url_lower:
            print(f"🏫 Skipping trusted Murdoch domain: {url}")
            return True

    # Skip obvious login URLs
    login_patterns = [
        "/login",
        "/signin",
        "/auth",
        "/sso",
        "/oauth",
        "login.php",
        "signin.php",
        "auth.php",
        "accounts.google.com",
        "login.microsoft.com",
        "auth.microsoft.com",
        "login.live.com",
    ]

    if any(pattern in url_lower for pattern in login_patterns):
        print(f"🔐 Skipping login URL: {url}")
        return True

    # Skip localhost and internal IPs
    internal_patterns = [
        "localhost",
        "127.0.0.1",
        "10.51.33.25",
        "192.168.",
        "10.",
        "172.16.",
        "172.31.",
    ]

    if any(pattern in url_lower for pattern in internal_patterns):
        print(f"🏠 Skipping internal URL: {url}")
        return True

    # Skip clearly broken URLs
    if url.startswith("javascript:") or url.startswith("mailto:"):
        print(f"🚫 Skipping non-HTTP URL: {url}")
        return True

    # Skip URLs with obvious tracking parameters that might be private
    if "?token=" in url or "&token=" in url or "session=" in url:
        print(f"🔒 Skipping URL with session token: {url}")
        return True

    return False


def ipqualityscore_fallback(url: str):
    """
    Fallback to IPQualityScore when VirusTotal fails
    Returns: (reputation, category) tuple on success, None on failure
    """
    try:
        print("🔄 Switching to IPQualityScore API...")

        API_KEY = os.getenv(
            "IPQUALITYSCORE_API_KEY", "IYd59ukXZEz4gt6tr4wPApSUkxUa074n"
        )

        # Clean URL for IPQualityScore
        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        # URL encode the URL for the API request
        encoded_url = urllib.parse.quote_plus(clean_url)

        # Make request to IPQualityScore
        endpoint = (
            f"https://www.ipqualityscore.com/api/json/url/{API_KEY}/{encoded_url}"
        )
        response = requests.get(endpoint, timeout=8)

        if response.status_code == 200:
            result = response.json()
            print("✅ IPQualityScore scan successful.")

            if result.get("success"):
                risk_score = result.get("risk_score", 0)

                # Map risk score to category
                if risk_score >= 85:
                    category = "HIGH_RISK"
                elif risk_score >= 50:
                    category = "MEDIUM_RISK"
                elif risk_score >= 25:
                    category = "LOW_RISK"
                else:
                    category = "CLEAN"

                # Add additional context
                if result.get("malware"):
                    category += "_MALWARE"
                if result.get("phishing"):
                    category += "_PHISHING"
                if result.get("suspicious"):
                    category += "_SUSPICIOUS"

                print(
                    f"🎯 IPQualityScore Result: Risk Score: {risk_score}, Category: {category}"
                )
                return (risk_score, category)
            else:
                error_msg = result.get("message", "Unknown error")
                print(f"❌ IPQualityScore scan failed: {error_msg}")
                if "quota" in error_msg.lower() or "exceeded" in error_msg.lower():
                    print("⚠️ IPQualityScore daily quota exceeded")
                return None  # Return None instead of calling MetaDefender
        elif response.status_code == 429:
            print(f"❌ IPQualityScore API error: {response.status_code}")
            print("⚠️ IPQualityScore API quota exceeded")
            return None  # Return None instead of calling MetaDefender
        else:
            print(f"❌ IPQualityScore API error: {response.status_code}")
            return None  # Return None instead of calling MetaDefender

    except Exception as e:
        print(f"❌ IPQualityScore fallback error: {e}")
        return None  # Return None instead of calling MetaDefender


def metadefender_fallback(url: str):
    """
    Final fallback to MetaDefender when both VirusTotal and IPQualityScore fail
    Uses hash lookup method for URL analysis
    """
    try:
        print("🔄 Switching to MetaDefender API...")

        API_KEY = os.getenv("METADEFENDER_API_KEY")
        if not API_KEY:
            print("❌ MetaDefender API key not found in environment")
            return (-1, "API_KEY_MISSING")

        # Clean URL for MetaDefender
        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        headers = {"apikey": API_KEY}

        # Create SHA256 hash of the URL for lookup
        import hashlib

        url_hash = hashlib.sha256(clean_url.encode()).hexdigest()
        print(f"🔍 Looking up URL hash: {url_hash}")

        # Look up existing scan results via hash
        hash_endpoint = f"https://api.metadefender.com/v4/hash/{url_hash}"
        response = requests.get(hash_endpoint, headers=headers, timeout=8)

        if response.status_code == 200:
            data = response.json()

            # Check if scan results exist
            if "scan_results" in data:
                scan_results = data["scan_results"]

                # Get scan details
                if "scan_details" in scan_results:
                    scan_details = scan_results["scan_details"]

                    # Count threats
                    total_engines = len(scan_details)
                    threats_found = 0

                    for engine_name, engine_result in scan_details.items():
                        if engine_result.get("threat_found"):
                            threats_found += 1

                    # Calculate risk score
                    if total_engines > 0:
                        risk_percentage = (threats_found / total_engines) * 100

                        # Determine category
                        if risk_percentage >= 50:
                            category = (
                                f"HIGH_RISK_MALWARE_{threats_found}_{total_engines}"
                            )
                        elif risk_percentage >= 25:
                            category = (
                                f"MEDIUM_RISK_MALWARE_{threats_found}_{total_engines}"
                            )
                        elif risk_percentage >= 10:
                            category = (
                                f"LOW_RISK_MALWARE_{threats_found}_{total_engines}"
                            )
                        else:
                            category = "CLEAN_VERIFIED"

                        print(
                            f"✅ MetaDefender scan complete: {threats_found}/{total_engines} engines detected threats"
                        )
                        print(
                            f"📊 Risk Score: {risk_percentage:.1f}%, Category: {category}"
                        )

                        return (risk_percentage, category)
                    else:
                        return (-1, "NO_ENGINES_AVAILABLE")
                else:
                    return (-1, "NO_SCAN_DETAILS")
            else:
                return (-1, "NO_SCAN_RESULTS")

        elif response.status_code == 404:
            # URL not found in database - this is normal for new URLs
            # Return -1 to indicate "unknown" rather than 0 (which implies safe)
            print(f"ℹ️ URL not found in MetaDefender database (may be new/clean)")
            return (-1, "URL_NOT_IN_DATABASE")

        else:
            print(f"❌ MetaDefender API error: {response.status_code}")
            if response.status_code == 429:
                print("⚠️ MetaDefender API quota exceeded")
                return (-1, "QUOTA_EXCEEDED")
            return (-1, f"API_ERROR_{response.status_code}")

    except Exception as e:
        print(f"❌ MetaDefender fallback error: {e}")
        return (-1, "FALLBACK_ERROR")


# --------------------------------
# 🧼 Content Filtering via DNS
# --------------------------------
# def contentFiltering(url):
#     resolver = dns.resolver.Resolver()
#     resolver.nameservers = ["1.1.1.3"]  # Cloudflare Family DNS
#     try:
#         resolver.resolve(url, "A")
#         return True
#     except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
#         return False


# --------------------------------
# 🧪 Test Section
# --------------------------------


# def save_report_to_file(report, filename="output/url_scan_report.json"):
#     os.makedirs(os.path.dirname(filename), exist_ok=True)
#     with open(filename, "w") as f:
#         json.dump(report, f, indent=2)
#     print(f"✅ Saved scan report to {filename}")


# if __name__ == "__main__":
# # Example usage
# url_to_scan = "https://www.example.com"  # Replace with your target URL
# result = scan_url_v3(url_to_scan)
# if result:
#     save_report_to_file(result)
# test_url = "https://www.xvideos.com/tags/xxxvideo"
# analyze_links(184, test_url)

# Other utilities:
# print(contentFiltering("www.xvideos.com"))
# print(check_safe_browsing("https://example.com"))
# print(get_or_scan_url("https://malicious.example", wait_for_fresh=True))


class IPQS:
    def __init__(self, api_key: str):
        self.key = api_key

    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        encoded_url = urllib.parse.quote_plus(url)
        api_url = (
            f"https://www.ipqualityscore.com/api/json/url/{self.key}/{encoded_url}"
        )
        response = requests.get(api_url, params=vars)
        print(f"\n?? Requesting scan at IPQualityScore API for: {url}")
        print("?? Raw response:\n", response.text)
        return response.json()


def is_valid_api_result(result) -> bool:
    """Check if API result is valid and usable"""
    if not result or not isinstance(result, tuple) or len(result) != 2:
        return False

    score, category = result
    return (
        isinstance(score, (int, float))
        and isinstance(category, str)
        and category.strip() != ""
    )


from urllib.parse import urlparse
import requests
from requests.exceptions import SSLError, ConnectionError, Timeout
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def preprocess_input(url, scrapeID, safe_update_risk, timeout=5):
    result = {
        "url": url,
        "domain": "",
        "is_edu_au": False,
        "is_accessible": False,
        "should_scan": False,
        "http_status": None,
        "notes": "",
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        result["domain"] = domain

        if domain.endswith(".edu.au"):
            result["is_edu_au"] = True
            result["notes"] = "EDUCATION DOMAIN"
            safe_update_risk(scrapeID, -1, "EDUCATION DOMAIN", url, "System")
            return result

        # Try HEAD request — ignore SSL errors
        try:
            response = requests.head(
                url, allow_redirects=True, timeout=timeout, verify=False
            )
            if response.status_code == 405:
                response = requests.get(url, stream=True, timeout=timeout, verify=False)

            result["http_status"] = response.status_code
            result["is_accessible"] = response.status_code in [200, 301, 302]

        except SSLError:
            # SSL error, but still treat as accessible (if response is returned)
            result["http_status"] = "SSL_IGNORED"
            result["is_accessible"] = True
            result["notes"] = "SSL ERROR IGNORED"

        # Final scan decision
        if result["is_accessible"]:
            result["should_scan"] = True
        else:
            safe_update_risk(scrapeID, -1, "SITE UNREACHABLE", url, "System")

    except (ConnectionError, Timeout) as e:
        result["http_status"] = "CONNECTION_FAILED"
        result["notes"] = f"Site not reachable: {str(e)}"
        safe_update_risk(scrapeID, -1, "SITE UNREACHABLE", url, "System")

    return result


def analyze_links(scrapeID: int, url: str):
    def safe_update_risk(scrape_id, score, category, analyzed_url, engine):
        try:
            category = category[:300]
            update_url = f"http://127.0.0.1:8000/scrapedcontents/updaterisk/{scrape_id}"
            response = requests.put(
                update_url, params={"score": score, "category": category}
            )

            if response.status_code == 200:
                print(
                    f"[{engine}] ✅ UPDATE SUCCESS | ID={scrape_id} | SCORE={score} | CATEGORY={category} | URL={analyzed_url}"
                )
                print(f"🟢 Response: {response.json()}")
            else:
                print(
                    f"[{engine}] ❌ UPDATE FAILED | ID={scrape_id} | status={response.status_code} | URL={analyzed_url}"
                )
                print(f"🔴 Response: {response.text}")
        except Exception as e:
            print(f"[{engine}] 🚨 ERROR during update for ID={scrape_id}: {e}")

    def check_nsfw_content(url_to_check: str) -> tuple:
        try:
            from content_filter import ContentFilter

            filter_obj = ContentFilter()
            is_nsfw, reason = filter_obj.is_pornography_url(url_to_check)
            confidence = 85 if is_nsfw else 0
            return is_nsfw, f"NSFW_{reason}" if is_nsfw else "SAFE", confidence
        except Exception:
            return False, "NSFW_CHECK_UNAVAILABLE", 0

    cleaned_url = clean_and_validate_url(url)
    if not cleaned_url:
        safe_update_risk(scrapeID, -1, "INVALID_URL", url, "System")
        return
    # TO STOP EDUCAITONAL DOMAINS AND SITE UNREACHABLE
    result = preprocess_input(url, scrapeID, safe_update_risk)

    if not result["should_scan"]:
        # Already handled by safe_update_risk inside preprocess_input
        return  # ⛔ Do NOT continue to scanning APIs

    is_nsfw, nsfw_reason, nsfw_score = check_nsfw_content(cleaned_url)
    if is_nsfw:
        inversescore = -(nsfw_score)
        safe_update_risk(
            scrapeID, inversescore, nsfw_reason, cleaned_url, "JigsawStack"
        )
        return

    if should_skip_url_scanning(cleaned_url):
        safe_update_risk(scrapeID, 0, "SKIPPED_URL", cleaned_url, "Filter")
        return

    apis_in_order = [
        ("VirusTotal", vt_v3_get_url_info),
        ("IPQualityScore", ipqualityscore_fallback),
        # ("MetaDefender", metadefender_fallback),
        # ("Google Safe Browsing", check_safe_browsing),
    ]

    for engine, func in apis_in_order:
        try:
            result = func(cleaned_url)
            if is_valid_api_result(result):
                score, category = result
                safe_update_risk(scrapeID, score, category, cleaned_url, engine)
                return
        except Exception as e:
            print(f"[{engine}] ERROR during scan: {e}")

    safe_update_risk(
        scrapeID, -1, "UNKNOWN_ALL_APIS_FAILED", cleaned_url, "AllEnginesFailed"
    )


def main():
    print("🧪 Starting manual test of analyze_links()")

    # Example test cases: (scrapeID, url)
    test_cases = [
        (5174, "https://coinlab.biz/"),
        (5244, "https://www.coinlab.biz"),
    ]

    for scrape_id, test_url in test_cases:
        print("\n" + "=" * 40)
        print(f"🔗 Test URL: {test_url}")
        analyze_links(scrape_id, test_url)
        print("=" * 40)


if __name__ == "__main__":
    main()

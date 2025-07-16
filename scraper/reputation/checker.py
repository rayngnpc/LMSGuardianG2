import json
import requests
import urllib.parse
import os
import time
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import base64

# --------------------------------
# 🔐 API Keys & Config
# --------------------------------
load_dotenv(override=True)
VT_API_KEY = (
    os.getenv("VT_API_KEY")
    or "0321311ce4e6139cf90dd29e3265b4299d6d0379d8178b3baeb90bcf49133f00"
)
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_KEY")

VT_URL_REPORT = "https://www.virustotal.com/vtapi/v2/url/report"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/"


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
    
    # Remove extra characters
    url = url.strip()
    url = url.strip('()')  # Remove parentheses
    url = url.rstrip('.')  # Remove trailing periods
    
    # Fix common issues
    if url.startswith('www.') and not url.startswith('http'):
        url = 'https://' + url
    
    # Skip obviously malformed URLs
    if not url.startswith(('http://', 'https://')):
        return None
        
    return url

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
    # def check_safe_browsing(url):
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
        )
        response.raise_for_status()
        result = response.json()

        if result.get("matches"):
            return result["matches"][0].get("threatType", "malicious").lower()
        return "clean"
    except Exception as e:
        print(f"❌ Safe Browsing error: {e}")
        return "error"


VT_API_KEY = "0321311ce4e6139cf90dd29e3265b4299d6d0379d8178b3baeb90bcf49133f00"


def vt_v3_get_url_info(url):
    """
    Get URL information from VirusTotal v3 API
    Returns: (reputation, categories) tuple on success, None on failure
    """
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(endpoint, headers=headers, timeout=8)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"].get("categories", {})
            reputation = data["data"]["attributes"].get("reputation", 0)

            category_values = list(stats.values())
            categories = ", ".join(category_values) if category_values else "UNCATEGORIZED"

            print("\nVirusTotal URL Report")
            print(f"URL: {url}")
            print(f"Reputation Score: {reputation}")
            print(f"Categories: {categories}")

            return reputation, categories

        elif response.status_code == 404:
            print(f"\nVirusTotal 404: URL not found in cache - {url}")
            return "NOT_FOUND"  # Special indicator for 404
        
        elif response.status_code == 403:
            print(f"\nVirusTotal 403: Access denied - {url}")
            return "ACCESS_DENIED"  # Special indicator for 403
        
        else:
            print(f"\nVirusTotal API Error for {url}")
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
        'murdoch.edu.au', 'moodleprod.murdoch.edu.au', 'goto.murdoch.edu.au',
        'libguides.murdoch.edu.au', 'library.murdoch.edu.au', 'our.murdoch.edu.au',
        'online.murdoch.edu.au', 'murdochuniversity.sharepoint.com'
    ]
    
    url_lower = url.lower()
    for domain in murdoch_domains:
        if domain in url_lower:
            print(f"🏫 Skipping trusted Murdoch domain: {url}")
            return True
    
    # Skip obvious login URLs
    login_patterns = [
        '/login', '/signin', '/auth', '/sso', '/oauth',
        'login.php', 'signin.php', 'auth.php',
        'accounts.google.com', 'login.microsoft.com',
        'auth.microsoft.com', 'login.live.com'
    ]
    
    if any(pattern in url_lower for pattern in login_patterns):
        print(f"🔐 Skipping login URL: {url}")
        return True
    
    # Skip localhost and internal IPs
    internal_patterns = [
        'localhost', '127.0.0.1', '10.51.33.25',
        '192.168.', '10.', '172.16.', '172.31.'
    ]
    
    if any(pattern in url_lower for pattern in internal_patterns):
        print(f"🏠 Skipping internal URL: {url}")
        return True
        
    # Skip clearly broken URLs
    if url.startswith('javascript:') or url.startswith('mailto:'):
        print(f"🚫 Skipping non-HTTP URL: {url}")
        return True
        
    # Skip URLs with obvious tracking parameters that might be private
    if '?token=' in url or '&token=' in url or 'session=' in url:
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
        
        API_KEY = os.getenv("IPQUALITYSCORE_API_KEY", "IYd59ukXZEz4gt6tr4wPApSUkxUa074n")
        
        # Clean URL for IPQualityScore
        clean_url = url.strip()
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = 'https://' + clean_url
        
        # URL encode the URL for the API request
        encoded_url = urllib.parse.quote_plus(clean_url)
        
        # Make request to IPQualityScore
        endpoint = f"https://www.ipqualityscore.com/api/json/url/{API_KEY}/{encoded_url}"
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
                
                print(f"🎯 IPQualityScore Result: Risk Score: {risk_score}, Category: {category}")
                return (risk_score, category)
            else:
                print(f"❌ IPQualityScore scan failed: {result.get('message', 'Unknown error')}")
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
            return (0, "API_KEY_MISSING")
        
        # Clean URL for MetaDefender
        clean_url = url.strip()
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = 'https://' + clean_url
        
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
            if 'scan_results' in data:
                scan_results = data['scan_results']
                
                # Get scan details
                if 'scan_details' in scan_results:
                    scan_details = scan_results['scan_details']
                    
                    # Count threats
                    total_engines = len(scan_details)
                    threats_found = 0
                    
                    for engine_name, engine_result in scan_details.items():
                        if engine_result.get('threat_found'):
                            threats_found += 1
                    
                    # Calculate risk score
                    if total_engines > 0:
                        risk_percentage = (threats_found / total_engines) * 100
                        
                        # Determine category
                        if risk_percentage >= 50:
                            category = f"HIGH_RISK_MALWARE_{threats_found}_{total_engines}"
                        elif risk_percentage >= 25:
                            category = f"MEDIUM_RISK_MALWARE_{threats_found}_{total_engines}"
                        elif risk_percentage >= 10:
                            category = f"LOW_RISK_MALWARE_{threats_found}_{total_engines}"
                        else:
                            category = "CLEAN_VERIFIED"
                        
                        print(f"✅ MetaDefender scan complete: {threats_found}/{total_engines} engines detected threats")
                        print(f"📊 Risk Score: {risk_percentage:.1f}%, Category: {category}")
                        
                        return (risk_percentage, category)
                    else:
                        return (0, "NO_ENGINES_AVAILABLE")
                else:
                    return (0, "NO_SCAN_DETAILS")
            else:
                return (0, "NO_SCAN_RESULTS")
        
        elif response.status_code == 404:
            # URL not found in database - this is normal for new URLs
            print(f"ℹ️ URL not found in MetaDefender database (may be new/clean)")
            return (0, "URL_NOT_IN_DATABASE")
        
        else:
            print(f"❌ MetaDefender API error: {response.status_code}")
            return (0, f"API_ERROR_{response.status_code}")
            
    except Exception as e:
        print(f"❌ MetaDefender fallback error: {e}")
        return (0, "FALLBACK_ERROR")


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


def is_valid_api_result(result):
    """
    Check if an API result is valid and usable
    Returns True if result is a valid tuple with non-None values
    """
    return (result is not None and 
            isinstance(result, tuple) and 
            len(result) == 2 and 
            result[0] is not None and 
            result[1] is not None)


def analyze_links(scrapeID: int, url: str):
    """
    Analyze a single URL for security risks using VirusTotal and IPQualityScore
    """
    # Define the safe update function first
    def safe_update_risk(scrape_id: int, score: float, category: str, url_arg: str = ""):
        try:
            category = category[:300] if len(category) > 300 else category
            update_url = f"http://127.0.0.1:8000/scrapedcontents/updaterisk/{scrape_id}"
            response = requests.put(update_url, params={"score": score, "category": category})
            response.raise_for_status()
            print(f"✅ Updated {url_arg} with score {score} and category {category}")
            return True
        except Exception as e:
            print(f"❌ Error updating risk for {url_arg}: {e}")
            return False
    
    # Clean and validate URL first
    cleaned_url = clean_and_validate_url(url)
    if not cleaned_url:
        print(f"❌ Invalid URL format: {url}")
        safe_update_risk(scrapeID, 0, "INVALID_URL", url)
        return
    
    # Use cleaned URL for processing
    print(f"\n🔍 Analyzing URL: {cleaned_url}")
    if cleaned_url != url:
        print(f"🔧 Cleaned from: {url}")
    
    # Check if this is a Murdoch URL that should be trusted
    murdoch_domains = [
        'murdoch.edu.au', 'moodleprod.murdoch.edu.au', 'goto.murdoch.edu.au',
        'libguides.murdoch.edu.au', 'library.murdoch.edu.au', 'our.murdoch.edu.au',
        'online.murdoch.edu.au', 'murdochuniversity.sharepoint.com'
    ]
    
    url_lower = cleaned_url.lower()
    if any(domain in url_lower for domain in murdoch_domains):
        print(f"🏫 Murdoch domain detected - marking as trusted: {cleaned_url}")
        safe_update_risk(scrapeID, 0, "TRUSTED_MURDOCH_DOMAIN", cleaned_url)
        return
    
    # Skip URLs that shouldn't be scanned
    if should_skip_url_scanning(cleaned_url):
        safe_update_risk(scrapeID, 0, "SKIPPED_URL", cleaned_url)
        return

    # Skip connectivity check - let security APIs handle unreachable URLs
    # This allows cached results and reputation analysis even for down sites

    try:
        # Step 1: Try VirusTotal first
        print("🦠 Checking VirusTotal...")
        vt_result = vt_v3_get_url_info(cleaned_url)
        
        # Check if VirusTotal succeeded
        if is_valid_api_result(vt_result):
            reputation, category = vt_result
            print(f"✅ VirusTotal successful - Score: {reputation}, Category: {category}")
            safe_update_risk(scrapeID, reputation, category, cleaned_url)
            return
        
        # Step 2: VirusTotal failed, try IPQualityScore
        print("❌ VirusTotal failed or returned invalid result, trying IPQualityScore...")
        ipqs_result = ipqualityscore_fallback(cleaned_url)
        
        if is_valid_api_result(ipqs_result):
            reputation, category = ipqs_result
            print(f"✅ IPQualityScore successful - Score: {reputation}, Category: {category}")
            safe_update_risk(scrapeID, reputation, category, cleaned_url)
            return
        
        # Step 3: IPQualityScore failed, try MetaDefender as final fallback
        print("❌ IPQualityScore failed or returned invalid result, trying MetaDefender...")
        md_result = metadefender_fallback(cleaned_url)
        
        if is_valid_api_result(md_result):
            reputation, category = md_result
            print(f"✅ MetaDefender successful - Score: {reputation}, Category: {category}")
            safe_update_risk(scrapeID, reputation, category, cleaned_url)
            return
        
        # Step 4: All APIs failed
        print("❌ All security APIs failed or returned invalid results")
        safe_update_risk(scrapeID, 0, "ALL_APIS_FAILED", cleaned_url)

    except Exception as e:
        print(f"❌ Critical error analyzing {cleaned_url}: {e}")
        safe_update_risk(scrapeID, 0, "CRITICAL_ERROR", cleaned_url)

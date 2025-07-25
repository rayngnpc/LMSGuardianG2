import subprocess
import os
import platform
import requests
from urllib.parse import urlparse, quote
from datetime import datetime
import json
import re


SINGLEFILE_PATH = "/usr/bin/single-file"
BASE_FOLDER = "/var/www/html/localrepo"


os.makedirs(BASE_FOLDER, exist_ok=True)
API_BASE = "http://127.0.0.1:8000"

# # Global cache for module information
# _MODULE_CACHE = {}


# def get_cached_module_info(module_id):
#     """Get module information from cache or API"""
#     if module_id in _MODULE_CACHE:
#         return _MODULE_CACHE[module_id]

#     try:
#         module_response = requests.get(f"{API_BASE}/modules/{module_id}", timeout=3)
#         if module_response.status_code == 200:
#             module_data = module_response.json()
#             module_info = {
#                 "module_name": module_data.get("unit_code", f"MODULE_{module_id}"),
#                 "unit_code": module_data.get("unit_code", f"MODULE_{module_id}"),
#                 "module_full_name": module_data.get(
#                     "module_full_name", f"Module {module_id}"
#                 ),
#                 "module_id": module_id,
#             }
#             _MODULE_CACHE[module_id] = module_info
#             return module_info
#         else:
#             print(
#                 f"⚠️ Module API failed for module_id {module_id}: {module_response.status_code}"
#             )
#     except Exception as e:
#         print(f"⚠️ Error fetching module {module_id}: {e}")

#     # Fallback
#     fallback_info = {
#         "module_name": f"MODULE_{module_id}",
#         "unit_code": f"MODULE_{module_id}",
#         "module_full_name": f"Module {module_id}",
#         "module_id": module_id,
#     }
#     _MODULE_CACHE[module_id] = fallback_info
#     return fallback_info


def get_chrome_path():
    return (
        "/usr/bin/google-chrome"
        if platform.system() != "Windows"
        else r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    )


def sanitize_filename(s):
    """Clean filename for filesystem safety"""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


# def create_organized_folder_structure(scraped_id, url, module_info=None):
#     """
#     Create organized folder structure:
#     localrepo/scan-YYYY-MM-DD-HH-MM/MODULE_NAME/content_type/scraped_id/
#     """
#     current_time = datetime.now()
#     date_folder = current_time.strftime("scan-%Y-%m-%d-%H-%M")

#     # Try to get module information from API if not provided
#     if not module_info:
#         try:
#             # First try to get specific scraped content by ID
#             response = requests.get(f"{API_BASE}/scrapedcontents/{scraped_id}")
#             if response.status_code == 200:
#                 scraped_data = response.json()
#                 module_id = scraped_data.get("module_id")

#                 if module_id:
#                     # Now get the module details using module_id
#                     module_info = get_cached_module_info(module_id)
#                     module_name = module_info["module_name"]
#                     module_full_name = module_info["module_full_name"]
#                     print(f"✅ Found module {module_name} for scraped_id {scraped_id}")
#                 else:
#                     print(f"⚠️ No module_id found for scraped_id {scraped_id}")
#                     module_name = "UNKNOWN_MODULE"
#                     module_full_name = "Unknown Module"

#                 module_info = {
#                     "module_name": module_name,
#                     "unit_code": module_name,  # Add unit_code for compatibility
#                     "module_full_name": module_full_name,
#                     "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                     "source_url": url,
#                     "title": "Content from LMS",
#                     "scraped_date": current_time.isoformat(),
#                     "module_id": module_id,
#                 }
#             else:
#                 print(
#                     f"⚠️ Could not find scraped content for {scraped_id}: {response.status_code}"
#                 )
#                 # Fallback: try to find it in all scraped content
#                 response = requests.get(f"{API_BASE}/scrapedcontents/")
#                 if response.status_code == 200:
#                     all_scraped_data = response.json()

#                     # Find our specific scraped content
#                     scraped_data = None
#                     for item in all_scraped_data:
#                         if item.get("scraped_id") == scraped_id:
#                             scraped_data = item
#                             break

#                     if scraped_data:
#                         module_id = scraped_data.get("module_id")

#                         if module_id:
#                             # Now get the module details using module_id
#                             module_info = get_cached_module_info(module_id)
#                             module_name = module_info["module_name"]
#                             module_full_name = module_info["module_full_name"]
#                             print(
#                                 f"✅ Found module {module_name} for scraped_id {scraped_id} (fallback)"
#                             )
#                         else:
#                             module_name = "UNKNOWN_MODULE"
#                             module_full_name = "Unknown Module"

#                         module_info = {
#                             "module_name": module_name,
#                             "unit_code": module_name,  # Add unit_code for compatibility
#                             "module_full_name": module_full_name,
#                             "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                             "source_url": url,
#                             "title": "Content from LMS",
#                             "scraped_date": current_time.isoformat(),
#                             "module_id": module_id,
#                         }
#                     else:
#                         print(
#                             f"⚠️ Could not find scraped content for {scraped_id} in all records"
#                         )
#                         module_info = {
#                             "module_name": "UNKNOWN_MODULE",
#                             "unit_code": "UNKNOWN_MODULE",  # Add unit_code for compatibility
#                             "module_full_name": "Unknown Module",
#                             "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                             "source_url": url,
#                             "title": "Untitled",
#                             "scraped_date": current_time.isoformat(),
#                             "module_id": None,
#                         }
#                 else:
#                     print(
#                         f"⚠️ Could not fetch scraped content list: {response.status_code}"
#                     )
#                     module_info = {
#                         "module_name": "UNKNOWN_MODULE",
#                         "unit_code": "UNKNOWN_MODULE",  # Add unit_code for compatibility
#                         "module_full_name": "Unknown Module",
#                         "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                         "source_url": url,
#                         "title": "Untitled",
#                         "scraped_date": current_time.isoformat(),
#                         "module_id": None,
#                     }
#         except Exception as e:
#             print(f"⚠️ Could not fetch module info for {scraped_id}: {e}")
#             module_info = {
#                 "module_name": "UNKNOWN_MODULE",
#                 "unit_code": "UNKNOWN_MODULE",  # Add unit_code for compatibility
#                 "module_full_name": "Unknown Module",
#                 "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                 "source_url": url,
#                 "title": "Untitled",
#                 "scraped_date": current_time.isoformat(),
#                 "module_id": None,
#             }

#     # Create folder structure
#     module_name = sanitize_filename(module_info["module_name"])
#     content_type = module_info["content_type"]

#     folder_path = os.path.join(
#         BASE_FOLDER, date_folder, module_name, content_type, str(scraped_id)
#     )

#     os.makedirs(folder_path, exist_ok=True)

#     # Create metadata file
#     metadata_path = os.path.join(folder_path, "metadata.json")
#     with open(metadata_path, "w", encoding="utf-8") as f:
#         json.dump(module_info, f, indent=2, ensure_ascii=False)

#     # Create a README file with information
#     readme_path = os.path.join(folder_path, "README.md")
#     with open(readme_path, "w", encoding="utf-8") as f:
#         f.write(f"# Scraped Content Information\n\n")
#         f.write(f"**Scraped ID:** {scraped_id}\n")
#         f.write(
#             f"**Module:** {module_info.get('module_full_name', module_info.get('unit_code', 'Unknown'))}\n"
#         )
#         f.write(f"**Unit Code:** {module_info.get('unit_code', 'Unknown')}\n")
#         f.write(f"**Content Type:** {content_type}\n")
#         f.write(f"**Source URL:** {url}\n")
#         f.write(f"**Title:** {module_info.get('title', 'Unknown')}\n")
#         f.write(f"**Scraped Date:** {module_info.get('scraped_date', 'Unknown')}\n")
#         f.write(f"**Domain:** {urlparse(url).netloc}\n\n")
#         f.write("## Files in this directory:\n")
#         f.write("- `metadata.json` - Complete metadata in JSON format\n")
#         if content_type == "pdf":
#             f.write("- `document.pdf` - Downloaded PDF file\n")
#         else:
#             f.write("- `index.html` - Complete webpage snapshot\n")
#         f.write("- `README.md` - This information file\n")

#     return folder_path, date_folder


def save_pdf_file(url, scraped_id, module_info):

    module_id = module_info.get("module_id", "UNKNOWN")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    # Create subpath ONLY under /var/www/html/localrepo
    relative_path = f"module_{module_id}/{timestamp}/{scraped_id}"
    base_path = os.path.join(BASE_FOLDER, relative_path)  # Absolute path
    os.makedirs(base_path, exist_ok=True)

    filename = os.path.join(base_path, "document.pdf")
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, stream=True, timeout=10, headers=headers)
        response.raise_for_status()

        with open(filename, "wb") as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)

        print(f"📄 PDF saved at: {filename}")
        return f"localrepo/{relative_path}"  # Correct relative URL for rewriting
    except Exception as e:
        print(f"❌ PDF download failed: {e}")
        return None


def save_page_with_singlefile(url, scraped_id, module_info):
    import subprocess
    import os
    from datetime import datetime

    module_id = module_info.get("module_id", "UNKNOWN")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")

    # Store under /var/www/html/localrepo/...
    relative_path = f"module_{module_id}/{timestamp}/{scraped_id}"
    base_path = os.path.join(BASE_FOLDER, relative_path)
    os.makedirs(base_path, exist_ok=True)

    output_path = os.path.join(base_path, "index.html")
    chrome_path = get_chrome_path()

    command = [
        SINGLEFILE_PATH,
        url,
        output_path,
        "--browser-executable-path",
        chrome_path,
        "--max-resource-size-enabled",
        "--max-resource-size",
        "10",
    ]

    try:
        subprocess.run(command, check=True, timeout=30)
        print(f"🌐 HTML saved at: {output_path}")
        return f"localrepo/{relative_path}"  # Relative to /var/www/html
    except Exception as e:
        print(f"❌ HTML save failed: {e}")
        return None


def download_all_safe_links():
    safe_links = getAllSafeLinks()
    if not safe_links:
        print("ℹ️ No safe links found.")
        return

    from collections import defaultdict

    # Group links by module_id
    grouped = defaultdict(list)
    for link in safe_links:
        module_id = link.get("module_id", "UNKNOWN")
        grouped[module_id].append(link)

    # Print links per module
    for module_id, links in grouped.items():
        try:
            response = requests.get(f"{API_BASE}/modules/{module_id}", timeout=5)
            if response.status_code == 200:
                module_data = response.json()
                unit_code = module_data.get("unit_code", f"MODULE_{module_id}")
                module_full_name = module_data.get(
                    "module_full_name", f"Module {module_id}"
                )
            else:
                unit_code = f"MODULE_{module_id}"
                module_full_name = (
                    f"Module {module_id} (API ERROR {response.status_code})"
                )
        except Exception as e:
            unit_code = f"MODULE_{module_id}"
            module_full_name = f"Module {module_id} (API ERROR: {e})"

        print(f"\n📚 {unit_code} - {module_full_name}")
        print(f"Safe links: {len(links)}")
        for i, link in enumerate(links, 1):
            print(f"  {i}. {link.get('url_link')}")

    print(f"\n✅ Printed {len(safe_links)} safe links across {len(grouped)} modules.")


# def create_scan_summary(date_folder):
#     """Create a summary of the scan session"""
#     scan_folder = os.path.join(BASE_FOLDER, date_folder)
#     summary_path = os.path.join(scan_folder, "SCAN_SUMMARY.md")

#     if not os.path.exists(scan_folder):
#         return

#     # Count files and modules
#     modules = {}
#     total_files = 0

#     for root, dirs, files in os.walk(scan_folder):
#         for file in files:
#             if file in ["index.html", "document.pdf"]:
#                 total_files += 1
#                 # Extract module name from path
#                 path_parts = root.split(os.sep)
#                 if len(path_parts) >= 3:
#                     module_name = path_parts[-3]  # Module name is 3 levels up
#                     content_type = path_parts[-2]  # Content type is 2 levels up

#                     if module_name not in modules:
#                         modules[module_name] = {"html": 0, "pdf": 0}
#                     modules[module_name][content_type] += 1

#     # Write summary
#     with open(summary_path, "w", encoding="utf-8") as f:
#         f.write(f"# Scan Summary - {date_folder}\n\n")
#         f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
#         f.write(f"**Total Files:** {total_files}\n")
#         f.write(f"**Modules Scanned:** {len(modules)}\n\n")

#         f.write("## Files by Module:\n\n")
#         for module, counts in sorted(modules.items()):
#             f.write(f"### {module}\n")
#             f.write(f"- HTML pages: {counts['html']}\n")
#             f.write(f"- PDF documents: {counts['pdf']}\n")
#             f.write(f"- Total: {counts['html'] + counts['pdf']}\n\n")

#         f.write("## Directory Structure:\n")
#         f.write("```\n")
#         f.write(f"{date_folder}/\n")
#         for module in sorted(modules.keys()):
#             f.write(f"├── {module}/\n")
#             f.write(f"│   ├── html/\n")
#             f.write(f"│   │   └── [scraped_id]/\n")
#             f.write(f"│   │       ├── index.html\n")
#             f.write(f"│   │       ├── metadata.json\n")
#             f.write(f"│   │       └── README.md\n")
#             f.write(f"│   └── pdf/\n")
#             f.write(f"│       └── [scraped_id]/\n")
#             f.write(f"│           ├── document.pdf\n")
#             f.write(f"│           ├── metadata.json\n")
#             f.write(f"│           └── README.md\n")
#         f.write("```\n")

#     print(f"📊 Scan summary created at: {summary_path}")


def getAllSafeLinks(include_paywalled=False, min_score=0):
    try:
        response = requests.get(f"{API_BASE}/scrapedcontents/scan")
        response.raise_for_status()
        all_links = response.json()

        safe_links = []
        skipped_low_score = 0
        skipped_paywall = 0

        for link in all_links:
            score = link.get("risk_score", -1)
            paywalled = link.get("is_paywall", False)

            if score < min_score:
                skipped_low_score += 1
                continue

            if paywalled and not include_paywalled:
                skipped_paywall += 1
                continue

            safe_links.append(link)

        print(f"✅ Found {len(safe_links)} safe links out of {len(all_links)} total")
        print(
            f"⛔ Skipped {skipped_low_score} (score too low), {skipped_paywall} (paywalled)"
        )
        return safe_links

    except Exception as e:
        print(f"❌ Failed to fetch safe links: {e}")
        return []


# enhanced download all safe links, older version was doing too much unnecasarily
def download_all_safe_links():
    safe_links = getAllSafeLinks()
    print(safe_links)


# def download_all_safe_links():
#     safe_links = getAllSafeLinks()

#     if not safe_links:
#         print("ℹ️ No safe links found to download")
#         return

#     print(f"🔄 Processing {len(safe_links)} safe links...")

#     # Track scan session
#     current_time = datetime.now()
#     date_folder = current_time.strftime("scan-%Y-%m-%d-%H-%M")
#     processed_count = 0

#     # Use ThreadPoolExecutor for concurrent processing
#     from concurrent.futures import ThreadPoolExecutor, as_completed

#     def process_link(link):
#         """Process a single link with improved error handling"""
#         try:
#             status = link.get("risk_category")
#             if status == "UNAVAILABLE" or status == "LOGIN":
#                 return None

#             scraped_id = link.get("scraped_id") or link.get("scrapeID")
#             raw_url = link.get("url_link") or link.get("url")

#             if not scraped_id:
#                 print("⏭️ Skipping link without scraped_id:", link)
#                 return None

#             # Clean and validate URL
#             url = clean_and_validate_url(raw_url)
#             if not url:
#                 print(f"⏭️ Skipping invalid URL for scraped_id={scraped_id}: {raw_url}")
#                 return None

#             print(f"🔄 Processing scraped_id={scraped_id}: {url}")

#             # Get cached module info or use default
#             cached_module = get_cached_module_info(scraped_id)
#             if cached_module:
#                 module_name = cached_module.get("unit_code", "UNKNOWN_MODULE")
#             else:
#                 module_name = link.get("module_name", "UNKNOWN_MODULE")

#             # Prepare module info
#             module_info = {
#                 "module_name": module_name,
#                 "content_type": "pdf" if ".pdf" in url.lower() else "html",
#                 "source_url": url,
#                 "title": link.get("title", "Untitled"),
#                 "scraped_date": current_time.isoformat(),
#                 "scraped_id": scraped_id,
#                 "risk_category": status,
#             }

#             # Add additional module info if available
#             if cached_module:
#                 module_info.update(
#                     {
#                         "unit_code": cached_module.get("unit_code", "Unknown"),
#                         "module_full_name": cached_module.get(
#                             "module_full_name", "Unknown"
#                         ),
#                         "module_id": cached_module.get("module_id", scraped_id),
#                     }
#                 )

#             # Save based on content type
#             if ".pdf" in url.lower():
#                 local_path = save_pdf_file(url, scraped_id, module_info)
#             else:
#                 local_path = save_page_with_singlefile(url, scraped_id, module_info)

#             if not local_path:
#                 print(f"⚠️ Could not save for scraped_id={scraped_id}")
#                 return None

#             # Update database with new path
#             try:
#                 encoded_path = quote(local_path, safe="")
#                 update_url = f"{API_BASE}/scrapedcontents/localurl/{scraped_id}?localurl={encoded_path}"
#                 update_res = requests.put(update_url, timeout=5)
#                 update_res.raise_for_status()
#                 print(f"✅ Updated scraped_id={scraped_id} with {local_path}")
#                 return scraped_id
#             except Exception as e:
#                 print(
#                     f"❌ Failed to update backend for scraped_id={scraped_id}: {str(e)[:100]}..."
#                 )
#                 return None

#         except KeyboardInterrupt:
#             print(f"\n⏹️ Processing interrupted for scraped_id={scraped_id}")
#             return None
#         except Exception as e:
#             print(f"❌ Error processing scraped_id={scraped_id}: {str(e)[:100]}...")
#             return None

#     # Process links concurrently with limited workers
#     max_workers = 4  # Limit concurrent downloads
#     failed_links = []

#     with ThreadPoolExecutor(max_workers=max_workers) as executor:
#         # Submit all tasks
#         future_to_link = {
#             executor.submit(process_link, link): link for link in safe_links
#         }

#         # Process completed tasks with progress tracking
#         total_links = len(safe_links)
#         for i, future in enumerate(as_completed(future_to_link), 1):
#             link = future_to_link[future]
#             try:
#                 result = future.result()
#                 if result is not None:
#                     processed_count += 1
#                 else:
#                     failed_links.append(link)
#             except Exception as e:
#                 print(
#                     f"❌ Future exception for {link.get('scraped_id', 'unknown')}: {str(e)[:100]}..."
#                 )
#                 failed_links.append(link)

#             # Show progress every 10 files or at the end
#             if i % 10 == 0 or i == total_links:
#                 print(
#                     f"📈 Progress: {i}/{total_links} files processed ({processed_count} successful, {len(failed_links)} failed)"
#                 )

#     # Report failed links
#     if failed_links:
#         print(f"\n⚠️ {len(failed_links)} links failed to process:")
#         for link in failed_links[:10]:  # Show first 10 failed links
#             scraped_id = link.get("scraped_id", "unknown")
#             url = link.get("url_link", "unknown")
#             print(f"  - scraped_id={scraped_id}: {url[:80]}...")
#         if len(failed_links) > 10:
#             print(f"  ... and {len(failed_links) - 10} more")

#     # Create scan summary
#     create_scan_summary(date_folder)

#     print(f"\n🎉 Scan complete! Processed {processed_count} files.")
#     print(f"📁 Files saved in: {os.path.join(BASE_FOLDER, date_folder)}")
#     print(
#         f"📊 Success rate: {processed_count}/{len(safe_links)} ({processed_count/len(safe_links)*100:.1f}%)"
#     )
#     print(f"⚠️ Failed: {len(failed_links)} links")

#     return {
#         "processed": processed_count,
#         "failed": len(failed_links),
#         "total": len(safe_links),
#         "success_rate": processed_count / len(safe_links) * 100 if safe_links else 0,
#     }


def clean_and_validate_url(url):
    """Clean and validate URL before processing"""
    if not url or not isinstance(url, str):
        return None

    # Remove extra parentheses and trailing dots
    url = re.sub(r"^\(+|\)+$|^\s+|\s+$", "", url)
    url = re.sub(r"[.)]+$", "", url)

    # Skip complex text that contains URLs but isn't a URL itself
    if any(
        word in url.lower()
        for word in ["available from", "ontario, canada", "university of"]
    ):
        return None

    # Skip obviously invalid URLs
    if url in ["https://", "http://", "", "www.", "."]:
        return None

    # Add protocol if missing
    if url.startswith("www."):
        url = "https://" + url
    elif not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Basic URL validation - must have domain with at least one dot
    if not re.match(r"^https?://[^/]+\.[^/]+", url):
        return None

    return url


from collections import defaultdict
from urllib.parse import quote
from datetime import datetime
import requests


API_BASE = "http://127.0.0.1:8000"


def process_and_download_unique_safe_links():
    try:
        safe_links = getAllSafeLinks()  # 👈 now uses centralized filtering with logging
    except Exception as e:
        print(f"❌ Failed to fetch safe links: {e}")
        return

    if not safe_links:
        print("ℹ️ No safe links to process.")
        return

    grouped = defaultdict(list)
    for link in safe_links:
        module_id = link.get("module_id", "UNKNOWN")
        grouped[module_id].append(link)

    summary = []

    for module_id, links in grouped.items():
        print(f"\n📦 MODULE {module_id} — {len(links)} links")

        seen = {}
        for link in links:
            url = link.get("url_link")
            scraped_id = link.get("scraped_id")
            title = link.get("title", "Untitled")
            if not url or not scraped_id:
                continue
            if url not in seen:
                seen[url] = {"primary": scraped_id, "title": title, "duplicates": []}
            else:
                seen[url]["duplicates"].append(scraped_id)

        for url, info in seen.items():
            primary_id = info["primary"]
            duplicates = info["duplicates"]
            title = info["title"]

            print(f"\n🔽 Downloading scraped_id={primary_id}: {url}")

            # Build module info for metadata
            module_info = {
                "module_name": f"MODULE_{module_id}",
                "unit_code": f"MODULE_{module_id}",
                "module_full_name": f"Module {module_id}",
                "module_id": module_id,
                "content_type": "pdf" if ".pdf" in url.lower() else "html",
                "source_url": url,
                "title": title,
                "scraped_date": datetime.now().isoformat(),
            }

            # Call appropriate download method
            try:
                if ".pdf" in url.lower():
                    localurl = save_pdf_file(url, primary_id, module_info)
                else:
                    localurl = save_page_with_singlefile(url, primary_id, module_info)

                if not localurl:
                    print(f"❌ Download failed for scraped_id={primary_id}")
                    continue
            except Exception as e:
                print(f"❌ Error downloading scraped_id={primary_id}: {e}")
                continue

            print(f"  ✅ Saved at: {localurl}")

            # Update primary record
            try:
                encoded = quote(localurl, safe="")
                update_url = f"{API_BASE}/scrapedcontents/localurl/{primary_id}?localurl={encoded}"
                r = requests.put(update_url)
                r.raise_for_status()
                print(f"  ✅ Updated DB for primary {primary_id}")
            except Exception as e:
                print(f"❌ Failed to update DB for primary {primary_id}: {e}")
                continue

            # Update duplicates
            for dup_id in duplicates:
                try:
                    update_url = f"{API_BASE}/scrapedcontents/localurl/{dup_id}?localurl={encoded}"
                    r = requests.put(update_url)
                    r.raise_for_status()
                    print(f"  ↪️  Synced duplicate {dup_id}")
                except Exception as e:
                    print(f"❌ Failed to update duplicate {dup_id}: {e}")

            summary.append(
                {
                    "module_id": module_id,
                    "url": url,
                    "primary_id": primary_id,
                    "duplicates": duplicates,
                    "localurl": localurl,
                }
            )

    # Print summary
    print("\n📊 SUMMARY:")
    for entry in summary:
        print(
            f"- Module {entry['module_id']} | Primary: {entry['primary_id']} | Duplicates: {len(entry['duplicates'])}"
        )
        print(f"  → URL: {entry['url']}")
        print(f"  → LocalURL: {entry['localurl']}")


if __name__ == "__main__":
    process_and_download_unique_safe_links()

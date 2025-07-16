import subprocess
import os
import platform
import requests
from urllib.parse import urlparse, quote
from datetime import datetime
import json
import re

SINGLEFILE_PATH = "/usr/bin/single-file"
# Use /tmp for server compatibility or create user-accessible folder
if os.path.exists("/var/www") and os.access("/var/www", os.W_OK):
    BASE_FOLDER = "/var/www/localrepo"
else:
    BASE_FOLDER = os.path.join(os.path.expanduser("~"), "localrepo")

os.makedirs(BASE_FOLDER, exist_ok=True)
API_BASE = "http://127.0.0.1:8000"

# Global cache for module information
_MODULE_CACHE = {}


def get_cached_module_info(module_id):
    """Get module information from cache or API"""
    if module_id in _MODULE_CACHE:
        return _MODULE_CACHE[module_id]
    
    try:
        module_response = requests.get(f"{API_BASE}/modules/{module_id}", timeout=3)
        if module_response.status_code == 200:
            module_data = module_response.json()
            module_info = {
                'module_name': module_data.get('unit_code', f'MODULE_{module_id}'),
                'unit_code': module_data.get('unit_code', f'MODULE_{module_id}'),
                'module_full_name': module_data.get('module_full_name', f'Module {module_id}'),
                'module_id': module_id
            }
            _MODULE_CACHE[module_id] = module_info
            return module_info
        else:
            print(f"⚠️ Module API failed for module_id {module_id}: {module_response.status_code}")
    except Exception as e:
        print(f"⚠️ Error fetching module {module_id}: {e}")
    
    # Fallback
    fallback_info = {
        'module_name': f'MODULE_{module_id}',
        'unit_code': f'MODULE_{module_id}',
        'module_full_name': f'Module {module_id}',
        'module_id': module_id
    }
    _MODULE_CACHE[module_id] = fallback_info
    return fallback_info


def get_chrome_path():
    return (
        "/usr/bin/google-chrome"
        if platform.system() != "Windows"
        else r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    )


def sanitize_filename(s):
    """Clean filename for filesystem safety"""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def create_organized_folder_structure(scraped_id, url, module_info=None):
    """
    Create organized folder structure:
    localrepo/scan-YYYY-MM-DD-HH-MM/MODULE_NAME/content_type/scraped_id/
    """
    current_time = datetime.now()
    date_folder = current_time.strftime("scan-%Y-%m-%d-%H-%M")
    
    # Try to get module information from API if not provided
    if not module_info:
        try:
            # First try to get specific scraped content by ID
            response = requests.get(f"{API_BASE}/scrapedcontents/{scraped_id}")
            if response.status_code == 200:
                scraped_data = response.json()
                module_id = scraped_data.get('module_id')
                
                if module_id:
                    # Now get the module details using module_id
                    module_info = get_cached_module_info(module_id)
                    module_name = module_info['module_name']
                    module_full_name = module_info['module_full_name']
                    print(f"✅ Found module {module_name} for scraped_id {scraped_id}")
                else:
                    print(f"⚠️ No module_id found for scraped_id {scraped_id}")
                    module_name = 'UNKNOWN_MODULE'
                    module_full_name = 'Unknown Module'
                
                module_info = {
                    'module_name': module_name,
                    'unit_code': module_name,  # Add unit_code for compatibility
                    'module_full_name': module_full_name,
                    'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                    'source_url': url,
                    'title': 'Content from LMS',
                    'scraped_date': current_time.isoformat(),
                    'module_id': module_id
                }
            else:
                print(f"⚠️ Could not find scraped content for {scraped_id}: {response.status_code}")
                # Fallback: try to find it in all scraped content
                response = requests.get(f"{API_BASE}/scrapedcontents/")
                if response.status_code == 200:
                    all_scraped_data = response.json()
                    
                    # Find our specific scraped content
                    scraped_data = None
                    for item in all_scraped_data:
                        if item.get('scraped_id') == scraped_id:
                            scraped_data = item
                            break
                    
                    if scraped_data:
                        module_id = scraped_data.get('module_id')
                        
                        if module_id:
                            # Now get the module details using module_id
                            module_info = get_cached_module_info(module_id)
                            module_name = module_info['module_name']
                            module_full_name = module_info['module_full_name']
                            print(f"✅ Found module {module_name} for scraped_id {scraped_id} (fallback)")
                        else:
                            module_name = 'UNKNOWN_MODULE'
                            module_full_name = 'Unknown Module'
                        
                        module_info = {
                            'module_name': module_name,
                            'unit_code': module_name,  # Add unit_code for compatibility
                            'module_full_name': module_full_name,
                            'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                            'source_url': url,
                            'title': 'Content from LMS',
                            'scraped_date': current_time.isoformat(),
                            'module_id': module_id
                        }
                    else:
                        print(f"⚠️ Could not find scraped content for {scraped_id} in all records")
                        module_info = {
                            'module_name': 'UNKNOWN_MODULE',
                            'unit_code': 'UNKNOWN_MODULE',  # Add unit_code for compatibility
                            'module_full_name': 'Unknown Module',
                            'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                            'source_url': url,
                            'title': 'Untitled',
                            'scraped_date': current_time.isoformat(),
                            'module_id': None
                        }
                else:
                    print(f"⚠️ Could not fetch scraped content list: {response.status_code}")
                    module_info = {
                        'module_name': 'UNKNOWN_MODULE',
                        'unit_code': 'UNKNOWN_MODULE',  # Add unit_code for compatibility
                        'module_full_name': 'Unknown Module',
                        'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                        'source_url': url,
                        'title': 'Untitled',
                        'scraped_date': current_time.isoformat(),
                        'module_id': None
                    }
        except Exception as e:
            print(f"⚠️ Could not fetch module info for {scraped_id}: {e}")
            module_info = {
                'module_name': 'UNKNOWN_MODULE',
                'unit_code': 'UNKNOWN_MODULE',  # Add unit_code for compatibility
                'module_full_name': 'Unknown Module',
                'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                'source_url': url,
                'title': 'Untitled',
                'scraped_date': current_time.isoformat(),
                'module_id': None
            }
    
    # Create folder structure
    module_name = sanitize_filename(module_info['module_name'])
    content_type = module_info['content_type']
    
    folder_path = os.path.join(
        BASE_FOLDER,
        date_folder,
        module_name,
        content_type,
        str(scraped_id)
    )
    
    os.makedirs(folder_path, exist_ok=True)
    
    # Create metadata file
    metadata_path = os.path.join(folder_path, "metadata.json")
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(module_info, f, indent=2, ensure_ascii=False)
    
    # Create a README file with information
    readme_path = os.path.join(folder_path, "README.md")
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(f"# Scraped Content Information\n\n")
        f.write(f"**Scraped ID:** {scraped_id}\n")
        f.write(f"**Module:** {module_info.get('module_full_name', module_info.get('unit_code', 'Unknown'))}\n")
        f.write(f"**Unit Code:** {module_info.get('unit_code', 'Unknown')}\n")
        f.write(f"**Content Type:** {content_type}\n")
        f.write(f"**Source URL:** {url}\n")
        f.write(f"**Title:** {module_info.get('title', 'Unknown')}\n")
        f.write(f"**Scraped Date:** {module_info.get('scraped_date', 'Unknown')}\n")
        f.write(f"**Domain:** {urlparse(url).netloc}\n\n")
        f.write("## Files in this directory:\n")
        f.write("- `metadata.json` - Complete metadata in JSON format\n")
        if content_type == 'pdf':
            f.write("- `document.pdf` - Downloaded PDF file\n")
        else:
            f.write("- `index.html` - Complete webpage snapshot\n")
        f.write("- `README.md` - This information file\n")
    
    return folder_path, date_folder


def save_pdf_file(url, scraped_id, module_info=None):
    """Save PDF file with organized structure and improved error handling"""
    folder_path, date_folder = create_organized_folder_structure(scraped_id, url, module_info)
    full_path = os.path.join(folder_path, "document.pdf")

    try:
        # Add headers to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, stream=True, timeout=12, headers=headers)
        
        # Check if response is actually a PDF
        content_type = response.headers.get('content-type', '').lower()
        if 'pdf' not in content_type and response.status_code == 200:
            # Try to detect PDF by content
            first_chunk = response.iter_content(chunk_size=1024).__next__()
            if not first_chunk.startswith(b'%PDF'):
                print(f"⚠️ URL {url} doesn't serve PDF content (got {content_type})")
                return None
        
        response.raise_for_status()
        
        with open(full_path, "wb") as f:
            # Write the first chunk if we read it
            if 'first_chunk' in locals():
                f.write(first_chunk)
            
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"📄 PDF saved at: {full_path}")
        
        # Return relative path for database
        relative_path = os.path.relpath(full_path, BASE_FOLDER)
        return f"localrepo/{relative_path}"
        
    except requests.exceptions.Timeout:
        print(f"⏱️ PDF download timeout for {url}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"🔌 Connection error for {url}: {str(e)[:100]}...")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"🚫 HTTP error for {url}: {e}")
        return None
    except Exception as e:
        print(f"❌ Failed to download PDF from {url}: {str(e)[:100]}...")
        return None


def save_page_with_singlefile(url, scraped_id, module_info=None):
    """Save HTML page with organized structure and improved timeout handling"""
    folder_path, date_folder = create_organized_folder_structure(scraped_id, url, module_info)
    output_path = os.path.join(folder_path, "index.html")

    chrome_path = get_chrome_path()

    command = [
        SINGLEFILE_PATH,
        url,
        output_path,
        "--browser-executable-path",
        chrome_path,
        "--browser-timeout",
        "25000",  # 25 second timeout
        "--max-resource-size-enabled",
        "--max-resource-size",
        "10"  # 10MB max resource size
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print(f"🌐 HTML saved at: {output_path}")
            
            # Return relative path for database
            relative_path = os.path.relpath(output_path, BASE_FOLDER)
            return f"localrepo/{relative_path}"
        else:
            error_msg = result.stderr[:200] if result.stderr else "Unknown error"
            print(f"⚠️ Single-file error for {url}: {error_msg}...")
            return None
    except subprocess.TimeoutExpired:
        print(f"⏱️ Single-file timeout for {url}")
        return None
    except Exception as e:
        print(f"❌ Error saving {url}: {str(e)[:100]}...")
        return None


def create_scan_summary(date_folder):
    """Create a summary of the scan session"""
    scan_folder = os.path.join(BASE_FOLDER, date_folder)
    summary_path = os.path.join(scan_folder, "SCAN_SUMMARY.md")
    
    if not os.path.exists(scan_folder):
        return
    
    # Count files and modules
    modules = {}
    total_files = 0
    
    for root, dirs, files in os.walk(scan_folder):
        for file in files:
            if file in ['index.html', 'document.pdf']:
                total_files += 1
                # Extract module name from path
                path_parts = root.split(os.sep)
                if len(path_parts) >= 3:
                    module_name = path_parts[-3]  # Module name is 3 levels up
                    content_type = path_parts[-2]  # Content type is 2 levels up
                    
                    if module_name not in modules:
                        modules[module_name] = {'html': 0, 'pdf': 0}
                    modules[module_name][content_type] += 1
    
    # Write summary
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(f"# Scan Summary - {date_folder}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total Files:** {total_files}\n")
        f.write(f"**Modules Scanned:** {len(modules)}\n\n")
        
        f.write("## Files by Module:\n\n")
        for module, counts in sorted(modules.items()):
            f.write(f"### {module}\n")
            f.write(f"- HTML pages: {counts['html']}\n")
            f.write(f"- PDF documents: {counts['pdf']}\n")
            f.write(f"- Total: {counts['html'] + counts['pdf']}\n\n")
        
        f.write("## Directory Structure:\n")
        f.write("```\n")
        f.write(f"{date_folder}/\n")
        for module in sorted(modules.keys()):
            f.write(f"├── {module}/\n")
            f.write(f"│   ├── html/\n")
            f.write(f"│   │   └── [scraped_id]/\n")
            f.write(f"│   │       ├── index.html\n")
            f.write(f"│   │       ├── metadata.json\n")
            f.write(f"│   │       └── README.md\n")
            f.write(f"│   └── pdf/\n")
            f.write(f"│       └── [scraped_id]/\n")
            f.write(f"│           ├── document.pdf\n")
            f.write(f"│           ├── metadata.json\n")
            f.write(f"│           └── README.md\n")
        f.write("```\n")
    
    print(f"📊 Scan summary created at: {summary_path}")


def download_all_safe_links():
    """Download all safe links with improved organization and concurrent processing"""
    try:
        response = requests.get(f"{API_BASE}/scrapedcontents/safe")
        response.raise_for_status()
        safe_links = response.json()
    except Exception as e:
        print(f"❌ Failed to fetch safe links: {e}")
        return

    if not safe_links:
        print("ℹ️ No safe links found to download")
        return

    print(f"🔄 Processing {len(safe_links)} safe links...")
    
    # Track scan session
    current_time = datetime.now()
    date_folder = current_time.strftime("scan-%Y-%m-%d-%H-%M")
    processed_count = 0
    
    # Use ThreadPoolExecutor for concurrent processing
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    def process_link(link):
        """Process a single link with improved error handling"""
        try:
            status = link.get("risk_category")
            if status == "UNAVAILABLE" or status == "LOGIN":
                return None

            scraped_id = link.get("scraped_id") or link.get("scrapeID")
            raw_url = link.get("url_link") or link.get("url")
            
            if not scraped_id:
                print("⏭️ Skipping link without scraped_id:", link)
                return None
            
            # Clean and validate URL
            url = clean_and_validate_url(raw_url)
            if not url:
                print(f"⏭️ Skipping invalid URL for scraped_id={scraped_id}: {raw_url}")
                return None

            print(f"🔄 Processing scraped_id={scraped_id}: {url}")

            # Get cached module info or use default
            cached_module = get_cached_module_info(scraped_id)
            if cached_module:
                module_name = cached_module.get('unit_code', 'UNKNOWN_MODULE')
            else:
                module_name = link.get('module_name', 'UNKNOWN_MODULE')
            
            # Prepare module info
            module_info = {
                'module_name': module_name,
                'content_type': 'pdf' if '.pdf' in url.lower() else 'html',
                'source_url': url,
                'title': link.get('title', 'Untitled'),
                'scraped_date': current_time.isoformat(),
                'scraped_id': scraped_id,
                'risk_category': status
            }
            
            # Add additional module info if available
            if cached_module:
                module_info.update({
                    'unit_code': cached_module.get('unit_code', 'Unknown'),
                    'module_full_name': cached_module.get('module_full_name', 'Unknown'),
                    'module_id': cached_module.get('module_id', scraped_id)
                })

            # Save based on content type
            if ".pdf" in url.lower():
                local_path = save_pdf_file(url, scraped_id, module_info)
            else:
                local_path = save_page_with_singlefile(url, scraped_id, module_info)

            if not local_path:
                print(f"⚠️ Could not save for scraped_id={scraped_id}")
                return None

            # Update database with new path
            try:
                encoded_path = quote(local_path, safe="")
                update_url = f"{API_BASE}/scrapedcontents/localurl/{scraped_id}?localurl={encoded_path}"
                update_res = requests.put(update_url, timeout=5)
                update_res.raise_for_status()
                print(f"✅ Updated scraped_id={scraped_id} with {local_path}")
                return scraped_id
            except Exception as e:
                print(f"❌ Failed to update backend for scraped_id={scraped_id}: {str(e)[:100]}...")
                return None
                
        except KeyboardInterrupt:
            print(f"\n⏹️ Processing interrupted for scraped_id={scraped_id}")
            return None
        except Exception as e:
            print(f"❌ Error processing scraped_id={scraped_id}: {str(e)[:100]}...")
            return None
    
    # Process links concurrently with limited workers
    max_workers = 4  # Limit concurrent downloads
    failed_links = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_link = {executor.submit(process_link, link): link for link in safe_links}
        
        # Process completed tasks with progress tracking
        total_links = len(safe_links)
        for i, future in enumerate(as_completed(future_to_link), 1):
            link = future_to_link[future]
            try:
                result = future.result()
                if result is not None:
                    processed_count += 1
                else:
                    failed_links.append(link)
            except Exception as e:
                print(f"❌ Future exception for {link.get('scraped_id', 'unknown')}: {str(e)[:100]}...")
                failed_links.append(link)
            
            # Show progress every 10 files or at the end
            if i % 10 == 0 or i == total_links:
                print(f"📈 Progress: {i}/{total_links} files processed ({processed_count} successful, {len(failed_links)} failed)")

    # Report failed links
    if failed_links:
        print(f"\n⚠️ {len(failed_links)} links failed to process:")
        for link in failed_links[:10]:  # Show first 10 failed links
            scraped_id = link.get('scraped_id', 'unknown')
            url = link.get('url_link', 'unknown')
            print(f"  - scraped_id={scraped_id}: {url[:80]}...")
        if len(failed_links) > 10:
            print(f"  ... and {len(failed_links) - 10} more")

    # Create scan summary
    create_scan_summary(date_folder)
    
    print(f"\n🎉 Scan complete! Processed {processed_count} files.")
    print(f"📁 Files saved in: {os.path.join(BASE_FOLDER, date_folder)}")
    print(f"📊 Success rate: {processed_count}/{len(safe_links)} ({processed_count/len(safe_links)*100:.1f}%)")
    print(f"⚠️ Failed: {len(failed_links)} links")
    
    return {
        'processed': processed_count,
        'failed': len(failed_links),
        'total': len(safe_links),
        'success_rate': processed_count/len(safe_links)*100 if safe_links else 0
    }

def clean_and_validate_url(url):
    """Clean and validate URL before processing"""
    if not url or not isinstance(url, str):
        return None
    
    # Remove extra parentheses and trailing dots
    url = re.sub(r'^\(+|\)+$|^\s+|\s+$', '', url)
    url = re.sub(r'[.)]+$', '', url)
    
    # Skip complex text that contains URLs but isn't a URL itself
    if any(word in url.lower() for word in ['available from', 'ontario, canada', 'university of']):
        return None
    
    # Skip obviously invalid URLs
    if url in ['https://', 'http://', '', 'www.', '.']:
        return None
    
    # Add protocol if missing
    if url.startswith('www.'):
        url = 'https://' + url
    elif not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Basic URL validation - must have domain with at least one dot
    if not re.match(r'^https?://[^/]+\.[^/]+', url):
        return None
    
    return url

if __name__ == "__main__":
    download_all_safe_links()

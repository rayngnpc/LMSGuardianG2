import subprocess
import os
import platform
import requests
from urllib.parse import urlparse, quote
from datetime import datetime

SINGLEFILE_PATH = "/usr/bin/single-file"
BASE_FOLDER = "/var/www/html/localrepo"
API_BASE = "http://10.51.33.25:8000"


def get_chrome_path():
    return (
        "/usr/bin/chromium"
        if platform.system() != "Windows"
        else r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    )


def sanitize_filename(s):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def save_pdf_file(url, scraped_id):
    folder_path = os.path.join(BASE_FOLDER, str(scraped_id))
    os.makedirs(folder_path, exist_ok=True)
    full_path = os.path.join(folder_path, "document.pdf")

    try:
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()
        with open(full_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"📄 PDF saved at: {full_path}")
        return f"localrepo/{scraped_id}/document.pdf"
    except Exception as e:
        print(f"❌ Failed to download PDF from {url}: {e}")
        return None


def save_page_with_singlefile(url, scraped_id):
    save_dir = os.path.join(BASE_FOLDER, str(scraped_id))
    output_path = os.path.join(save_dir, "index.html")

    os.makedirs(save_dir, exist_ok=True)
    chrome_path = get_chrome_path()

    command = [
        SINGLEFILE_PATH,
        url,
        output_path,
        "--browser-executable-path",
        chrome_path,
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"🌐 HTML saved at: {output_path}")
        return f"localrepo/{scraped_id}/index.html"
    else:
        print(f"❌ Error saving {url}:\n{result.stderr}")
        return None


def download_all_safe_links():
    try:
        response = requests.get(f"{API_BASE}/scrapedcontents/safe")
        response.raise_for_status()
        safe_links = response.json()
    except Exception as e:
        print(f"❌ Failed to fetch safe links: {e}")
        return

    for link in safe_links:
        status = link.get("risk_category")
        if status == "UNAVAILABLE" or status == "LOGIN":
            continue

        scraped_id = link.get("scraped_id") or link.get("scrapeID")
        url = link.get("url_link") or link.get("url")
        if not scraped_id or not url:
            print("⏭️  Skipping invalid link:", link)
            continue

        print(f"🔄 Processing scraped_id={scraped_id}: {url}")

        if ".pdf" in url.lower():
            local_path = save_pdf_file(url, scraped_id)
        else:
            local_path = save_page_with_singlefile(url, scraped_id)

        if not local_path:
            print(f"⚠️ Could not save for scraped_id={scraped_id}")
            continue

        try:
            encoded_path = quote(local_path, safe="")
            update_url = f"{API_BASE}/scrapedcontents/localurl/{scraped_id}?localurl={encoded_path}"
            update_res = requests.put(update_url)
            update_res.raise_for_status()
            print(f"✅ Updated scraped_id={scraped_id} with {local_path}")
        except Exception as e:
            print(f"❌ Failed to update backend for scraped_id={scraped_id}: {e}")


if __name__ == "__main__":
    download_all_safe_links()

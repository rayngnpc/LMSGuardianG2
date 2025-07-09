__all__ = [
    "normalize_url",
    "is_internal",
    "should_exclude_url",
    "is_possibly_malicious",
    "getFileExtension",
]

import os
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import Page
from dotenv import load_dotenv

load_dotenv(override=True)

USERNAME = os.getenv("MOODLE_USERNAME")
PASSWORD = os.getenv("MOODLE_PASSWORD")

# PRODUCTION ENVIRONMENT
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

# ────────────────────────────────────────────────────────────────
# 📍 URL + DOMAIN HELPERS
# ────────────────────────────────────────────────────────────────


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    important_keys = {"id", "d", "cmid", "attempt"}
    filtered_query = {k: v for k, v in query.items() if k in important_keys}
    normalized_query = urlencode(filtered_query, doseq=True)
    return urlunparse(parsed._replace(query=normalized_query, fragment=""))


ALLOWED_INTERNAL_DOMAIN = "10.51.33.25"


def is_internal(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.hostname == ALLOWED_INTERNAL_DOMAIN
    except:
        return False


from urllib.parse import urlparse

IGNORED_INTERNAL_DOMAINS = [
    "www.murdoch.edu.au",
    "library.murdoch.edu.au",
    "mymurdoch.murdoch.edu.au",
]


def should_exclude_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or ""

        # Already existing logic
        for prefix in EXCLUDED_PATH_PREFIXES:
            if path.startswith(prefix):
                return True

        # NEW: skip known Murdoch-wide internal domains
        for ignored in IGNORED_INTERNAL_DOMAINS:
            if ignored in domain:
                return True

        return False
    except Exception as e:
        print(f"❌ Error parsing URL for exclusion: {e}")
        return True  # safer to exclude if unsure


def is_possibly_malicious(url: str, mime_type: str) -> bool:
    suspicious_mime_subtypes = {
        "x-msdownload",
        "x-executable",
        "x-sh",
        "x-python",
        "x-msdos-program",
        "vnd.microsoft.portable-executable",
        "x-bat",
    }
    try:
        subtype = mime_type.split("/")[1]
        return subtype in suspicious_mime_subtypes
    except IndexError:
        return True


# ────────────────────────────────────────────────────────────────
# 📂 FILE STORAGE
# ────────────────────────────────────────────────────────────────


def getFileExtension(ftype: str) -> str:
    mime_to_ext = {
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "application/msword": ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
        "application/vnd.ms-powerpoint": ".ppt",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "application/vnd.ms-excel": ".xls",
        "application/octet-stream": ".bin",
        "application/x-executable": ".exe",
        "application/x-msdownload": ".exe",
        "application/x-sh": ".sh",
        "application/x-python": ".py",
        "application/json": ".json",
        "text/html": ".html",
        "application/x-zip-compressed": ".zip",
        "application/x-rar-compressed": ".rar",
    }
    return mime_to_ext.get(ftype.strip().lower(), ".bin")

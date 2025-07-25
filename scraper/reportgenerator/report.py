import os
import smtplib
from datetime import datetime, UTC
from typing import List, Tuple
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from email.message import EmailMessage
from dotenv import load_dotenv
import pytz
import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import sys

from docx import Document
from docx.shared import Inches
from datetime import datetime
import os


from docx import Document
from datetime import datetime
import os
from collections import defaultdict
from docx import Document
from datetime import datetime
import os
from collections import defaultdict


from docx import Document
from collections import defaultdict
from datetime import datetime
import os


from docx import Document
from docx.shared import Inches
from docx.enum.section import WD_ORIENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from collections import defaultdict
from datetime import datetime
import os
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.section import WD_ORIENT
from collections import defaultdict
from datetime import datetime
import os
from docx import Document
from docx.shared import Inches
from docx.enum.section import WD_ORIENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from collections import defaultdict
from datetime import datetime
import os
import requests
from docx import Document
from datetime import datetime
import pytz
import os
from typing import List


# Add parent directory to path for content filter
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from content_filter import content_filter

    CONTENT_FILTER_AVAILABLE = True
except ImportError:
    print("⚠️ Content filter not available - continuing without filtering")
    CONTENT_FILTER_AVAILABLE = False

load_dotenv(override=True)


def should_exclude_from_apa_citation(
    url: str, title: str = "", is_paywall: bool = False, is_pornography: bool = False
) -> Tuple[bool, str]:
    """Check if content should be excluded from APA citation generation"""
    if not CONTENT_FILTER_AVAILABLE:
        return False, ""

    # Check for pornography first
    if is_pornography:
        return True, "Inappropriate content (pornography)"

    # Check using content filter
    should_exclude, reason = content_filter.should_exclude_from_apa_citation(
        url, title, "", is_paywall
    )
    if should_exclude:
        print(f"🚫 Excluding from APA citation: {url[:50]}... - {reason}")
        return True, reason

    return False, ""


def fetch_all_links_by_module():
    """Fetch latest scanned links grouped by module and sorted by highest risk score"""
    url = "http://127.0.0.1:8000/scrapedcontents/scan"
    try:
        res = requests.get(url)
        res.raise_for_status()
        all_data = res.json()

        modules_data = {}

        for item in all_data:
            module_id = item.get("module_id")
            if not module_id:
                continue
            if module_id not in modules_data:
                modules_data[module_id] = []
            modules_data[module_id].append(item)

        # Sort each module's links by descending risk_score (None treated as -1)
        for module_id, links in modules_data.items():
            modules_data[module_id] = sorted(
                links,
                key=lambda x: (
                    x.get("risk_score") if x.get("risk_score") is not None else -1
                ),
                reverse=True,
            )

        # Print summary
        # total = len(all_data)
        # print(f"\n📊 MODULE LINK SUMMARY:")
        # print(f"   Total links: {total}")
        # for module_id, links in modules_data.items():
        #     top_score = links[0].get("risk_score") if links else None
        #     with_risk = sum(
        #         1
        #         for link in links
        #         if link.get("risk_score") is not None
        #         or (
        #             link.get("risk_category")
        #             and link.get("risk_category") not in [None, "None", ""]
        #         )
        #     )
        #     print(
        #         f"   Module {module_id}: {len(links)} links ({with_risk} with risk analysis), Highest Risk Score: {top_score}"
        #     )

        return modules_data

    except Exception as e:
        print(f"Failed to fetch latest scanned links: {e}")
        return {}


def get_module_details():
    """Get module details from the backend"""
    try:
        res = requests.get("http://127.0.0.1:8000/modules/")
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"Failed to fetch module details: {e}")
        return []


def fetch_all_links_for_session(session_id):
    # Fetch all scraped links for the session from the backend
    # Note: The API filtering by session_id seems to have issues, so we fetch all and filter manually
    url = f"http://127.0.0.1:8000/scrapedcontents/"
    try:
        res = requests.get(url)
        res.raise_for_status()
        all_data = res.json()
        # Filter manually for the specific session
        session_data = [
            item for item in all_data if item.get("session_id") == session_id
        ]
        return session_data
    except Exception as e:
        print(f"Failed to fetch all links for session {session_id}: {e}")
        return []


def format_scraped_at(raw_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(raw_ts)
        sg = pytz.timezone("Asia/Singapore")
        dt = dt.astimezone(sg)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw_ts or ""


def generatePDF(ucname: str, moduleCode: str, urls: List[dict], baseUrl: str) -> str:
    from docx.shared import Inches, Pt
    from docx.enum.table import WD_ALIGN_VERTICAL
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    template_path = os.path.join("scraper", "reportgenerator", "reportChau.docx")
    doc = Document(template_path)

    # Replace placeholders in paragraphs
    for para in doc.paragraphs:
        if "<unit_id>" in para.text:
            para.text = para.text.replace("<unit_id>", moduleCode)
        if "<uc_name>" in para.text:
            para.text = para.text.replace("<uc_name>", ucname)
        if "<course_url>" in para.text:
            para.text = para.text.replace("<course_url>", baseUrl)

    table = doc.tables[0]
    table.autofit = False  # Ensure fixed column widths

    column_widths = [
        Inches(2.0),  # Link URL
        Inches(2.0),  # Link Location
        Inches(0.4),  # Risk Score
        Inches(1.8),  # Risk Category
        Inches(0.8),  # Detected on
        Inches(2.8),  # Action to be taken
    ]

    for link in urls:
        row = table.add_row().cells
        row[0].text = link.get("url_link", "")

        row[1].text = link.get("content_location", "") or ""
        row[2].text = str(link.get("risk_score", ""))
        reason = "No action required."
        risk_category = link.get("risk_category", "")
        if link.get("is_paywall", False):
            reason = "This is a paywalled content. Please remove it unless access is verified and permitted."
            risk_category = "Paywalled Content"
        row[3].text = risk_category
        row[4].text = format_scraped_at(link.get("scraped_at", ""))

        # Determine action

        if "SITE UNREACHABLE" in (link.get("risk_category") or ""):
            reason = "This is an unreachable domain or broken link. Please rectify it immediately to maintain content availability."
        elif "EDUCATION DOMAIN" in (link.get("risk_category") or ""):
            reason = "This is content hosted on an educational institution's domain. Please ensure content is used only if an agreement exists with the institution."
        elif link.get("risk_score", 0) < 0:
            reason = "This link has a high risk score and is likely to be malicious. Please remove it immediately."

        row[5].text = reason

        # Apply widths, wrapping and vertical alignment
        for idx, cell in enumerate(row):
            cell.width = column_widths[idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.TOP

            # Force Word to wrap text in cell
            tc = cell._tc
            tcPr = tc.get_or_add_tcPr()
            tcW = OxmlElement("w:tcW")
            tcW.set(
                qn("w:w"), str(int(column_widths[idx].inches * 1000))
            )  # width in twips
            tcW.set(qn("w:type"), "dxa")
            tcPr.append(tcW)

    # Save to report folder
    sg = pytz.timezone("Asia/Singapore")
    safe_code = datetime.now(sg).strftime("%Y-%m-%d")
    filename = f"{safe_code}_{moduleCode}_report.docx"
    output_dir = os.path.join("scraper", "reportgenerator", "report")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)
    doc.save(output_path)

    print(f"✅ Report saved to: {output_path}")
    return output_path


import csv
import os
from datetime import datetime
import pytz
from typing import List


def generateCSV(ucname: str, moduleCode: str, urls: List[dict], baseUrl: str) -> str:
    sg = pytz.timezone("Asia/Singapore")
    safe_code = datetime.now(sg).strftime("%Y-%m-%d")
    filename = f"{safe_code}_{moduleCode}_report.csv"
    output_dir = os.path.join("scraper", "reportgenerator", "report")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file, delimiter=",")

        # Header content
        writer.writerow(
            ["LMS Information Security Asssessment Tool Report for Unit Coordinators"]
        )
        writer.writerow([])  # Empty row
        writer.writerow(["Unit Coordinator", ucname])
        writer.writerow(["Module code", moduleCode])
        writer.writerow(["Course Page URL", baseUrl])
        writer.writerow([])  # Empty row

        # Header for links table (bolded in Word, plain in CSV)
        writer.writerow(
            [
                "Link URL",
                "Link Location",
                "Risk Score",
                "Risk Category",
                "Detected on",
                "Action to be taken",
            ]
        )

        # Link entries
        for link in urls:
            url_link = link.get("url_link", "")
            content_location = link.get("content_location", "")
            risk_score = link.get("risk_score", "")
            risk_category = link.get("risk_category", "")

            if link.get("is_paywall", False):
                reason = "This is a paywalled content. Please remove it unless access is verified and permitted."
                risk_category = "Paywalled Content"
            elif "SITE UNREACHABLE" in (risk_category or ""):
                reason = "This is an unreachable domain or broken link. Please rectify it immediately to maintain content availability."
            elif "EDUCATION DOMAIN" in (risk_category or ""):
                reason = "This is content hosted on an educational institution's domain. Please ensure content is used only if an agreement exists with the institution."
            elif risk_score != "" and risk_score < 0:
                reason = "This link has a high risk score and is likely to be malicious. Please remove it immediately."
            else:
                reason = "No action required."

            writer.writerow(
                [
                    url_link,
                    content_location,
                    risk_score,
                    risk_category,
                    link.get("scraped_at", ""),
                    reason,
                ]
            )

    print(f"✅ CSV report saved to: {output_path}")
    return output_path


# def generatePDF(ucname: str, moduleCode: str, urls: List[dict], baseUrl: str) -> str:
#     # Create a new blank document to avoid logo duplication issues
#     doc = Document()

#     # Landscape orientation and margins
#     section = doc.sections[0]
#     section.orientation = WD_ORIENT.LANDSCAPE
#     section.page_width, section.page_height = section.page_height, section.page_width
#     section.left_margin = Inches(0.3)
#     section.right_margin = Inches(0.3)
#     section.top_margin = Inches(0.8)  # More space for logo
#     section.bottom_margin = Inches(0.5)

#     # Ensure headers are different for first page (so logo doesn't repeat)
#     section.different_first_page_header_footer = True

#     # Add logo at the very top of the first page ONLY
#     # Get absolute path to ensure logo is found regardless of working directory
#     current_dir = os.path.dirname(os.path.abspath(__file__))
#     logo_path = os.path.join(current_dir, "logo.png")
#     if os.path.exists(logo_path):
#         logo_para = doc.add_paragraph()
#         logo_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
#         run = logo_para.add_run()
#         run.add_picture(logo_path, width=Inches(2.2))
#         logo_para.space_after = Pt(16)  # Space after logo

#     # Professional title and subtitle - directly below logo
#     title = doc.add_paragraph()
#     title.alignment = WD_ALIGN_PARAGRAPH.CENTER
#     run = title.add_run("LMS External Link Risk & Paywall Report")
#     run.bold = True
#     run.font.size = Pt(18)
#     title.space_after = Pt(8)

#     subtitle = doc.add_paragraph()
#     subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
#     run2 = subtitle.add_run(f"Unit: {moduleCode} | Coordinator: {ucname}")
#     run2.font.size = Pt(12)
#     subtitle.space_after = Pt(8)

#     # Course info paragraph
#     info_para = doc.add_paragraph()
#     info_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
#     run3 = info_para.add_run(f"Course URL: {baseUrl}")
#     run3.font.size = Pt(10)
#     run3.italic = True
#     info_para.space_after = Pt(16)

#     # Replace placeholders
#     replacements = {
#         "<Name>": ucname,
#         "<Module code>": moduleCode,
#         "<URL>": baseUrl,
#     }
#     for para in doc.paragraphs:
#         for key, value in replacements.items():
#             if key in para.text:
#                 para.text = para.text.replace(key, value)

#     # Table headers - Removed "Local Path" column
#     headers = [
#         "Link URL",
#         "Risk Status",
#         "Paywall",
#         "Downloadable",
#         "File Type",
#         "Detected On",
#         "APA7 Citation",
#         "LMS Context",
#         "Warning",
#     ]

#     # Create the table
#     table = doc.add_table(rows=1, cols=len(headers))
#     table.style = "Table Grid"

#     # Set column widths - Reduced Link URL column width, redistributed space
#     column_widths = [
#         Inches(1.3),
#         Inches(1.5),
#         Inches(0.8),
#         Inches(1.0),
#         Inches(1.0),
#         Inches(1.3),
#         Inches(3.5),
#         Inches(1.5),
#         Inches(1.8),
#     ]

#     # Format header row
#     header_row = table.rows[0]
#     for i, header in enumerate(headers):
#         cell = header_row.cells[i]
#         cell.text = header
#         # Make header bold and centered
#         for paragraph in cell.paragraphs:
#             for run in paragraph.runs:
#                 run.font.bold = True
#                 run.font.size = Pt(10)
#             paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
#         # Set column width
#         table.columns[i].width = column_widths[i]

#     # --- Build citation map for deduplication ---
#     citation_map = {}
#     for link in urls:
#         url = link.get("url_link", "")
#         if not url:
#             continue
#         # Only generate citation if needed and not already present
#         if url not in citation_map:
#             existing_apa7 = link.get("apa7", "") or ""
#             if not existing_apa7 and needs_apa7_citation(url):
#                 # Enhanced pornography detection using API categories
#                 is_pornography = link.get("is_pornography", False)
#                 risk_category = link.get("risk_category", "")
#                 if not is_pornography and CONTENT_FILTER_AVAILABLE:
#                     is_porn, _ = content_filter.is_pornography_url(
#                         url, link.get("title", ""), "", risk_category
#                     )
#                     is_pornography = is_porn
#                 should_exclude_apa, exclude_reason = should_exclude_from_apa_citation(
#                     url,
#                     link.get("title", ""),
#                     link.get("is_paywall", False),
#                     is_pornography,
#                 )
#                 if should_exclude_apa:
#                     citation_map[url] = f"APA Citation not generated ({exclude_reason})"
#                 else:
#                     citation_map[url] = generate_apa7_citation(
#                         url, link.get("scraped_at", "")
#                     )
#             else:
#                 citation_map[url] = existing_apa7

#     # Add data rows
#     for link in urls:
#         row = table.add_row().cells
#         # ENHANCED: URL normalization and display
#         raw_url = link.get("url_link", "")
#         # Normalize URL formatting
#         if raw_url:
#             if raw_url.startswith("http:\\"):
#                 raw_url = raw_url.replace("http:\\", "http://")
#             elif raw_url.startswith("https:\\"):
#                 raw_url = raw_url.replace("https:\\", "https://")
#             elif not raw_url.startswith(("http://", "https://")):
#                 raw_url = "https://" + raw_url
#             if "://" in raw_url:
#                 protocol, rest = raw_url.split("://", 1)
#                 rest = rest.replace("//", "/")
#                 raw_url = protocol + "://" + rest
#         url = raw_url
#         row[0].text = url

#         # ...existing risk display logic...
#         risk_score = link.get("risk_score")
#         risk_category = link.get("risk_category", "")
#         is_malicious_content = False
#         if CONTENT_FILTER_AVAILABLE:
#             is_malicious_content, _ = content_filter.is_malicious_url(
#                 url, link.get("title", ""), "", risk_category
#             )
#         malicious_indicators = [
#             "malicious",
#             "spyware",
#             "malware",
#             "compromised",
#             "phishing",
#             "trojan",
#             "virus",
#         ]
#         if risk_category and any(
#             indicator in risk_category.lower() for indicator in malicious_indicators
#         ):
#             is_malicious_content = True
#         is_trusted_url = False
#         if not is_malicious_content:
#             try:
#                 import sys

#                 sys.path.append(
#                     "/home/administrator/Test-Chau-LMS/LMSTest/scraper/reputation"
#                 )
#                 from checker import is_trusted_domain

#                 is_trusted_url = is_trusted_domain(url)
#             except:
#                 pass
#         if is_malicious_content:
#             risk_display = "🚨 MALICIOUS: Security Threat Detected"
#         elif is_trusted_url:
#             risk_display = "✅ Trusted Institution"
#         elif risk_score is not None:
#             if risk_category and risk_category.strip():
#                 clean_category = (
#                     risk_category.replace("_", " ").replace("-", " ").title()
#                 )
#                 high_risk_keywords = [
#                     "porn",
#                     "pornography",
#                     "adult content",
#                     "sexually explicit",
#                     "phishing",
#                     "malware",
#                     "trackers",
#                     "nsfw",
#                 ]
#                 is_high_risk = any(
#                     keyword in risk_category.lower() for keyword in high_risk_keywords
#                 )
#                 if is_high_risk:
#                     risk_display = f"🚨 HIGH RISK: {clean_category} ({risk_score}%)"
#                 elif risk_score == 0:
#                     risk_display = f"✅ Safe: {clean_category}"
#                 elif risk_score <= 20:
#                     risk_display = f"✅ Low Risk: {clean_category} ({risk_score}%)"
#                 elif risk_score <= 50:
#                     risk_display = f"⚠️ Medium Risk: {clean_category} ({risk_score}%)"
#                 else:
#                     risk_display = f"🚨 High Risk: {clean_category} ({risk_score}%)"
#             else:
#                 if risk_score == 0:
#                     risk_display = "✅ Safe"
#                 elif risk_score <= 20:
#                     risk_display = f"✅ Low Risk ({risk_score}%)"
#                 elif risk_score <= 50:
#                     risk_display = f"⚠️ Medium Risk ({risk_score}%)"
#                 else:
#                     risk_display = f"🚨 High Risk ({risk_score}%)"
#         else:
#             if risk_category and risk_category.strip():
#                 clean_category = (
#                     risk_category.replace("_", " ").replace("-", " ").title()
#                 )
#                 if risk_category.lower() in ["trusted_domain", "trusted"]:
#                     risk_display = "✅ Trusted Institution"
#                 else:
#                     risk_display = f"External: {clean_category}"
#             else:
#                 risk_display = "External (Not analyzed)"
#         row[1].text = risk_display

#         row[2].text = "Yes" if link.get("is_paywall") else "No"

#         # ...existing downloadable/file type logic...
#         downloadable = "No"
#         file_type = "Web Page"
#         file_type_mapping = {
#             ".pdf": "PDF Document",
#             ".doc": "Word Document",
#             ".docx": "Word Document",
#             ".txt": "Text File",
#             ".rtf": "Rich Text Format",
#             ".odt": "OpenDocument Text",
#             ".xls": "Excel Spreadsheet",
#             ".xlsx": "Excel Spreadsheet",
#             ".csv": "CSV File",
#             ".ods": "OpenDocument Spreadsheet",
#             ".ppt": "PowerPoint Presentation",
#             ".pptx": "PowerPoint Presentation",
#             ".odp": "OpenDocument Presentation",
#             ".zip": "ZIP Archive",
#             ".rar": "RAR Archive",
#             ".7z": "7-Zip Archive",
#             ".tar": "TAR Archive",
#             ".gz": "GZip Archive",
#             ".jpg": "JPEG Image",
#             ".jpeg": "JPEG Image",
#             ".png": "PNG Image",
#             ".gif": "GIF Image",
#             ".bmp": "Bitmap Image",
#             ".svg": "SVG Image",
#             ".mp4": "MP4 Video",
#             ".avi": "AVI Video",
#             ".mov": "QuickTime Video",
#             ".wmv": "Windows Media Video",
#             ".mp3": "MP3 Audio",
#             ".wav": "WAV Audio",
#             ".flac": "FLAC Audio",
#             ".py": "Python Script",
#             ".js": "JavaScript File",
#             ".html": "HTML Document",
#             ".css": "CSS Stylesheet",
#             ".xml": "XML Document",
#             ".json": "JSON Data",
#         }
#         url_lower = url.lower()
#         detected_extension = None
#         for ext, type_name in file_type_mapping.items():
#             if (
#                 url_lower.endswith(ext)
#                 or f"{ext}?" in url_lower
#                 or f"{ext}#" in url_lower
#             ):
#                 downloadable = "Yes"
#                 file_type = type_name
#                 detected_extension = ext
#                 break
#         if not detected_extension:
#             download_indicators = [
#                 "/download/",
#                 "/files/",
#                 "/attachments/",
#                 "/documents/",
#                 "/uploads/",
#                 "/media/",
#                 "/assets/",
#                 "download.php",
#                 "file.php",
#                 "attachment.php",
#             ]
#             if any(indicator in url_lower for indicator in download_indicators):
#                 downloadable = "Possible"
#                 file_type = "Download Link"
#         row[3].text = downloadable
#         row[4].text = file_type
#         raw_ts = link.get("scraped_at", "")
#         row[5].text = format_scraped_at(raw_ts)

#         # --- Use deduplicated citation ---
#         row[6].text = citation_map.get(link.get("url_link", ""), "")

#         # LMS context (scraping page URL for each occurrence)
#         row[7].text = link.get("lms_context", "") or ""

#         # ...existing warning logic...
#         warnings = []
#         if link.get("is_paywall"):
#             warnings.append("Paywalled/Controlled Access")
#         is_pornography = link.get("is_pornography", False)
#         risk_category = link.get("risk_category", "")
#         if is_pornography:
#             warnings.append("Inappropriate Content")
#         elif CONTENT_FILTER_AVAILABLE:
#             is_porn, _ = content_filter.is_pornography_url(
#                 url, link.get("title", ""), "", risk_category
#             )
#             if is_porn:
#                 warnings.append("Inappropriate Content")
#         risk_category = link.get("risk_category", "")
#         if CONTENT_FILTER_AVAILABLE:
#             is_malicious, _ = content_filter.is_malicious_url(
#                 url, link.get("title", ""), "", risk_category
#             )
#             if is_malicious and not is_malicious_content:
#                 warnings.append("Malicious Content")
#         if warnings:
#             row[8].text = "Warning: " + ", ".join(warnings)
#         else:
#             row[8].text = ""
#         for idx, cell in enumerate(row):
#             cell.paragraphs[0].alignment = (
#                 WD_ALIGN_PARAGRAPH.LEFT if idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
#             )
#             cell.paragraphs[0].runs[0].font.size = Pt(9)

#     # Add a professional footer
#     footer = doc.sections[0].footer
#     footer_para = footer.paragraphs[0]
#     footer_para.text = "Generated by LMS Guardian | Confidential"
#     footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
#     footer_para.runs[0].font.size = Pt(8)
#     footer_para.runs[0].italic = True

#     sg = pytz.timezone("Asia/Singapore")
#     safe_code = datetime.now(sg).strftime("%Y-%m-%d")
#     filename = f"{safe_code}_{moduleCode}_report.docx"
#     # Get absolute path to ensure reports are saved in the correct location
#     current_dir = os.path.dirname(os.path.abspath(__file__))
#     output_dir = os.path.join(current_dir, "report")
#     os.makedirs(output_dir, exist_ok=True)
#     output_path = os.path.join(output_dir, filename)
#     doc.save(output_path)

#     print(f"✅ Report saved to: {output_path}")
#     return output_path


import os
import smtplib
from email.message import EmailMessage

import os
import smtplib
from email.message import EmailMessage
import traceback


def send_email_with_report(
    to_email: str, doc_path: str, csv_path: str, moduleCode: str, ucname: str
):
    EMAIL_ADDRESS = os.getenv("EMAIL_USER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("❌ Email credentials not set in environment.")
        return

    # Validate attachment paths
    if not os.path.exists(doc_path):
        print(f"❌ DOCX report not found: {doc_path}")
        return
    if not os.path.exists(csv_path):
        print(f"❌ CSV report not found: {csv_path}")
        return

    msg = EmailMessage()
    msg["From"] = f"LMS Guardian <{EMAIL_ADDRESS}>"
    msg["To"] = to_email
    msg["Subject"] = f"[ALERT] High-risk links detected in {moduleCode}"
    msg["Reply-To"] = "noreply@example.com"

    body = f"""
Dear {ucname},

We wish to inform you that high-risk external links have been detected on the LMS course site for {moduleCode}. As the Unit Coordinator, your attention is required to review and address the issues identified in the attached report.

Please find both a Word document and CSV version of the report enclosed for your reference.

(This is an automatically generated notification. Please do not reply.)

Best regards,  
LMS Guardian Team
"""
    msg.set_content(body)

    # Attach DOCX report
    try:
        with open(doc_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="application",
                subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
                filename=os.path.basename(doc_path),
            )
        print(f"📎 Attached DOCX: {os.path.basename(doc_path)}")
    except Exception as e:
        print(f"❌ Failed to attach DOCX: {e}")
        traceback.print_exc()

    # Attach CSV report
    try:
        with open(csv_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="text",
                subtype="csv",
                filename=os.path.basename(csv_path),
            )
        print(f"📎 Attached CSV: {os.path.basename(csv_path)}")
    except Exception as e:
        print(f"❌ Failed to attach CSV: {e}")
        traceback.print_exc()

    # Send email via Gmail SMTP
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            # smtp.set_debuglevel(1)  # Enable SMTP debug logging
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)

        print(f"📨 Email sent to {to_email} ✅")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        traceback.print_exc()


def generate_apa7_citation(url: str, scraped_date: str = None) -> str:
    """Generate APA7 citation for a URL"""
    try:
        # Parse URL for basic info
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace("www.", "")

        # Determine file type
        file_extension = None
        for ext in [".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx"]:
            if ext.lower() in url.lower():
                file_extension = ext
                break

        # Improved title extraction from URL path
        title = "Untitled Document"
        author = None
        pub_date = None

        # Extract potential publication year from URL path first
        url_year = None
        # Look for year patterns in the URL path (e.g., /2018/08/, /2016/, etc.)
        year_patterns = [
            r"/(\d{4})/",  # /2018/
            r"/(\d{4})-",  # /2018-
            r"(\d{4})\.",  # 2018.pdf
            r"(\d{4})guide",  # 2016guide
            r"project(\d{4})",  # project2016
            r"(\d{4})report",  # 2018report
            r"-(\d{4})-",  # -2020-
            r"(\d{4})$",  # ends with year
        ]

        for pattern in year_patterns:
            match = re.search(pattern, url.lower())
            if match:
                year = int(match.group(1))
                # Only accept reasonable publication years (1990-current year)
                if 1990 <= year <= datetime.now().year:
                    url_year = year
                    break

        # Extract title from URL path as fallback
        path_parts = parsed_url.path.split("/")
        if path_parts:
            filename = path_parts[-1]
            if filename and "." in filename:
                # Clean up filename to make a better title
                title = (
                    filename.split(".")[0].replace("-", " ").replace("_", " ").title()
                )

                # If we found a year in URL, remove it from title to avoid duplication
                if url_year:
                    # Remove year patterns from title more thoroughly
                    year_str = str(url_year)
                    title = re.sub(rf"{year_str}", "", title).strip()
                    title = re.sub(
                        r"Project\s*", "Project ", title, flags=re.IGNORECASE
                    )  # Clean up "Project" spacing
                    title = re.sub(
                        r"Analysis\s*", "Analysis ", title, flags=re.IGNORECASE
                    )  # Clean up "Analysis" spacing
                    title = re.sub(
                        r"Report\s*$", "", title, flags=re.IGNORECASE
                    )  # Remove trailing "Report"
                    title = re.sub(r"\s+", " ", title)  # Clean up extra spaces
                    title = title.strip()

                # Clean up common patterns
                title = re.sub(r"[^\w\s\-\.\,\:\;\(\)]", "", title)
                if len(title) > 80:
                    title = title[:77] + "..."

        # Enhanced metadata extraction with better error handling
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }

            # Disable SSL warnings for this request
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(url, headers=headers, timeout=8, verify=False)

            if response.status_code == 200 and "text/html" in response.headers.get(
                "content-type", ""
            ):
                soup = BeautifulSoup(response.content, "html.parser")

                # Extract title with better cleaning
                title_tag = soup.find("title")
                if title_tag and title_tag.get_text().strip():
                    extracted_title = title_tag.get_text().strip()
                    # Clean up title
                    extracted_title = re.sub(r"\s+", " ", extracted_title)
                    extracted_title = re.sub(
                        r"[^\w\s\-\.\,\:\;\(\)]", "", extracted_title
                    )
                    if (
                        len(extracted_title) > 5
                        and "untitled" not in extracted_title.lower()
                    ):
                        title = (
                            extracted_title[:100] + "..."
                            if len(extracted_title) > 100
                            else extracted_title
                        )

                # Extract author from various meta tags
                for author_selector in [
                    'meta[name="author"]',
                    'meta[name="dc.creator"]',
                    'meta[property="article:author"]',
                    ".author",
                    ".byline",
                ]:
                    author_elem = soup.select_one(author_selector)
                    if author_elem:
                        if author_elem.name == "meta":
                            author = author_elem.get("content", "").strip()
                        else:
                            author = author_elem.get_text().strip()
                        if author:
                            break

                # Extract publication date
                for date_selector in [
                    'meta[name="dc.date"]',
                    'meta[property="article:published_time"]',
                    'meta[name="pubdate"]',
                    "time[datetime]",
                ]:
                    date_elem = soup.select_one(date_selector)
                    if date_elem:
                        if date_elem.name == "meta":
                            pub_date = date_elem.get("content", "").strip()
                        else:
                            pub_date = (
                                date_elem.get("datetime")
                                or date_elem.get_text().strip()
                            )
                        if pub_date:
                            break

        except Exception as e:
            # Silently continue with URL-based title
            pass

        # Determine resource type for citation
        if file_extension:
            if file_extension.lower() == ".pdf":
                resource_type = "[PDF document]"
            else:
                resource_type = f"[{file_extension.upper().replace('.', '')} document]"
        elif any(edu_domain in domain for edu_domain in ["edu.au", ".edu"]):
            resource_type = "[Educational website]"
        elif any(
            keyword in url.lower() for keyword in ["research", "journal", "academic"]
        ):
            resource_type = "[Research resource]"
        else:
            resource_type = "[Website]"

        # Use scraped date or current date for access date
        if scraped_date:
            try:
                access_date = datetime.fromisoformat(
                    scraped_date.replace("Z", "+00:00")
                )
                access_date_str = access_date.strftime("%B %d, %Y")
            except:
                access_date_str = datetime.now().strftime("%B %d, %Y")
        else:
            access_date_str = datetime.now().strftime("%B %d, %Y")

        # Properly format site name for APA7 (capitalize first letter)
        site_name = (
            domain.replace(".com", "")
            .replace(".au", "")
            .replace(".org", "")
            .replace(".edu", "")
            .replace(".gov", "")
            .title()
        )

        # Remove resource type from title if it's already mentioned
        if resource_type in title:
            title = title.replace(resource_type, "").strip()

        # Clean up title formatting
        title = re.sub(r"\s+", " ", title).strip()
        if not title.endswith("."):
            title += "."

        # Determine if we need "Retrieved" statement (only for likely-to-change content)
        needs_retrieved = any(
            keyword in url.lower()
            for keyword in ["news", "blog", "wiki", "forum", "comment", "social"]
        )

        # Generate APA7 citation based on available information
        if author and pub_date:
            # Full citation with author and date
            try:
                pub_year = re.search(r"(\d{4})", pub_date).group(1)
                if needs_retrieved:
                    citation = f"{author} ({pub_year}). {title} {site_name}. Retrieved {access_date_str}, from {url}"
                else:
                    citation = f"{author} ({pub_year}). {title} {site_name}. {url}"
            except:
                # If no pub_date year found, use URL year if available
                if url_year:
                    if needs_retrieved:
                        citation = f"{author} ({url_year}). {title} {site_name}. Retrieved {access_date_str}, from {url}"
                    else:
                        citation = f"{author} ({url_year}). {title} {site_name}. {url}"
                else:
                    if needs_retrieved:
                        citation = f"{author} (n.d.). {title} {site_name}. Retrieved {access_date_str}, from {url}"
                    else:
                        citation = f"{author} (n.d.). {title} {site_name}. {url}"
        elif author:
            # Citation with author but no date - use URL year if available
            if url_year:
                if needs_retrieved:
                    citation = f"{author} ({url_year}). {title} {site_name}. Retrieved {access_date_str}, from {url}"
                else:
                    citation = f"{author} ({url_year}). {title} {site_name}. {url}"
            else:
                if needs_retrieved:
                    citation = f"{author} (n.d.). {title} {site_name}. Retrieved {access_date_str}, from {url}"
                else:
                    citation = f"{author} (n.d.). {title} {site_name}. {url}"
        else:
            # Basic citation without author - use URL year if available
            if url_year:
                if needs_retrieved:
                    citation = f"{title} ({url_year}). {site_name}. Retrieved {access_date_str}, from {url}"
                else:
                    citation = f"{title} ({url_year}). {site_name}. {url}"
            else:
                if needs_retrieved:
                    citation = f"{title} (n.d.). {site_name}. Retrieved {access_date_str}, from {url}"
                else:
                    citation = f"{title} (n.d.). {site_name}. {url}"

        return citation

    except Exception as e:
        # Fallback citation if all else fails
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace("www.", "")
        site_name = (
            domain.replace(".com", "")
            .replace(".au", "")
            .replace(".org", "")
            .replace(".edu", "")
            .replace(".gov", "")
            .title()
        )
        access_date_str = datetime.now().strftime("%B %d, %Y")

        # Only use retrieved if likely to change
        needs_retrieved = any(
            keyword in url.lower()
            for keyword in ["news", "blog", "wiki", "forum", "comment", "social"]
        )
        if needs_retrieved:
            return (
                f"Resource (n.d.). {site_name}. Retrieved {access_date_str}, from {url}"
            )
        else:
            return f"Resource (n.d.). {site_name}. {url}"


def needs_apa7_citation(url: str) -> bool:
    """Determine if a URL needs an APA7 citation"""
    # Check for downloadable academic files
    academic_extensions = [".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx"]
    for ext in academic_extensions:
        if ext.lower() in url.lower():
            return True

    # Check for academic domains
    academic_domains = [
        "edu.au",
        ".edu",
        "researchgate",
        "scholar.google",
        "jstor",
        "arxiv",
    ]
    for domain in academic_domains:
        if domain in url.lower():
            return True

    # Check for research/academic keywords
    academic_keywords = [
        "research",
        "paper",
        "journal",
        "study",
        "publication",
        "thesis",
        "academic",
    ]
    for keyword in academic_keywords:
        if keyword in url.lower():
            return True

    return False


def generate_and_send_module_reports():
    # Get module details
    modules = get_module_details()
    module_info = {m["module_id"]: m for m in modules}

    # Fetch all unit coordinators once
    response = requests.get("http://10.51.33.25:8000/unitcoordinator/")
    unit_coordinators = response.json()

    # Get all links grouped by module
    modules_data = fetch_all_links_by_module()

    for module_id in sorted(modules_data.keys()):
        links = modules_data[module_id]

        sorted_links = sorted(
            links,
            key=lambda x: (
                x.get("risk_score", 0) >= 0,
                not x.get("is_paywall", False),
                x.get("risk_score", 0),
            ),
        )

        # Filter to only include risky links (risk_score < 0)
        filtered_links = [
            link for link in sorted_links if link.get("risk_score", 0) < 0
        ]

        if not filtered_links:
            print(f"⚠️ No risky links to report for module {module_id}. Skipping.")
            continue

        print(f"\n📦 Module {module_id} ({len(filtered_links)} risky links):")
        for link in filtered_links:
            print(
                f"  🔗 scraped_id={link['scraped_id']} | "
                f"score={link['risk_score']} | "
                f"paywall={link['is_paywall']} | "
                f"url={link['url_link']}"
            )

        # Module metadata
        module = module_info.get(module_id, {})
        uc_id = module.get("uc_id")
        ucname = "MISSING ERROR"
        to_email = None

        # Find matching UC info
        for uc in unit_coordinators:
            if uc["uc_id"] == uc_id:
                ucname = uc.get("full_name", "MISSING NAME")
                to_email = uc.get("email")
                break

        if not to_email:
            print(f"❌ No email found for uc_id={uc_id} (module_id={module_id})")
            continue

        module_code = f"{module.get('unit_code', '')} {module.get('module_name', '').strip()} {module.get('semester', '')}, {module.get('teaching_period', '')}".strip()
        print(f"[Module CODE]{module_code}")
        base_url = f"http://10.51.33.25/moodle/course/view.php?id={module_id+1}"

        try:
            # Generate reports
            report_path = generatePDF(ucname, module_code, filtered_links, base_url)
            print(f"[GENERATED] Word report: {report_path}")

            csv_path = generateCSV(ucname, module_code, filtered_links, base_url)
            print(f"[GENERATED] CSV report: {csv_path}")

            # Send email with both attachments
            send_email_with_report(
                to_email=to_email,
                doc_path=report_path,
                csv_path=csv_path,
                moduleCode=module_code,
                ucname=ucname,
            )

        except Exception as e:
            print(f"[FAILURE] Failed for module {module_id}: {e}")

    print(f"\n[SUCCESS] All reports processed for {len(modules_data)} modules.")


def generateDocumentReportForSecurityOfficer(all_links):
    if not all_links:
        print("⚠️ No links provided for security officer report.")
        return None

    # Clean input
    all_links = [l for l in all_links if isinstance(l, dict)]

    # Create document
    document = Document()

    # Set landscape layout
    section = document.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.top_margin = section.bottom_margin = section.left_margin = (
        section.right_margin
    ) = Inches(0.5)

    # Title and intro
    document.add_heading("LMS Security Officer Report", 0)
    document.add_paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    document.add_paragraph(
        "This document summarizes all scanned external links, grouped by module."
    )

    # Group links by module
    grouped = defaultdict(list)
    for link in all_links:
        module_id = link.get("module_id", "UNKNOWN")
        grouped[module_id].append(link)

    # Define column headers and widths
    headers = [
        "Module ID",
        "URL Link",
        "APA7",
        "LMS Location",
        "Risk Score",
        "Risk Category",
        "Local URL",
        "Scraped ID",
        "Detect At",
    ]
    col_widths = [
        Inches(0.8),
        Inches(2),
        Inches(2),
        Inches(2),
        Inches(0.5),
        Inches(2),
        Inches(2),
        Inches(1),
        Inches(1),
    ]

    for module_id, links in grouped.items():
        if not links:
            continue

        module_code = f"MODULE_{module_id}"
        document.add_heading(f"Module: {module_code} (ID: {module_id})", level=1)

        # Create table
        table = document.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"

        # Disable auto-fit
        tbl = table._tbl
        tblPr = tbl.tblPr
        tblLayout = OxmlElement("w:tblLayout")
        tblLayout.set(qn("w:type"), "fixed")
        tblPr.append(tblLayout)

        # Add header row
        hdr_cells = table.rows[0].cells
        for idx, cell in enumerate(hdr_cells):
            cell.text = headers[idx]
            cell.width = col_widths[idx]
            for p in cell.paragraphs:
                if p.runs:
                    p.runs[0].font.bold = True

        # Add data rows

        for link in links:
            try:
                row = table.add_row().cells
                formattedtime = format_scraped_at(link.get("scraped_at", ""))

                values = [
                    str(module_id),
                    str(link.get("url_link") or "N/A"),
                    str(link.get("apa7") or "N/A"),
                    str(link.get("content_location") or "N/A"),
                    (
                        str(link.get("risk_score"))
                        if link.get("risk_score") is not None
                        else "N/A"
                    ),
                    str(link.get("risk_category") or "N/A"),
                    str(link.get("localurl") or "N/A"),
                    str(link.get("scraped_id") or "N/A"),
                    str(formattedtime),
                ]
                for idx, cell in enumerate(row):
                    cell.text = values[idx]
                    cell.width = col_widths[idx]
            except Exception as e:
                print(f"[FAILURE] Error writing row: {e}")
                continue

    # Save document
    base_dir = os.path.dirname(os.path.abspath(__file__))  # ~/.../reportgenerator
    output_dir = os.path.join(base_dir, "report")
    filename = f"{output_dir}/SecurityReport_AllModules_{datetime.now().strftime('%Y%m%d')}.docx"
    document.save(filename)
    print(f"[SUCCESS] Report saved: {filename}")
    return filename


import csv
from datetime import datetime
import os


def generateCSVForSecurityOfficer(all_links):
    base_dir = os.path.dirname(os.path.abspath(__file__))  # ~/.../reportgenerator
    output_dir = os.path.join(base_dir, "report")

    os.makedirs(output_dir, exist_ok=True)

    filename = f"{output_dir}/SecurityReport_AllModules_{datetime.now().strftime('%Y%m%d')}.csv"

    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # Write header
        writer.writerow(
            [
                "Module ID",
                "URL Link",
                "LMS Location",
                "Risk Score",
                "Risk Category",
                "Local URL",
                "Scraped ID",
                "Scraped At",
            ]
        )

        for link in all_links:
            writer.writerow(
                [
                    link.get("module_id", "UNKNOWN"),
                    link.get("url_link", "N/A"),
                    link.get("content_location", "N/A"),
                    link.get("risk_score", "N/A"),
                    link.get("risk_category", "N/A"),
                    link.get("localurl", "N/A"),
                    link.get("scraped_id", "N/A"),
                    link.get("scraped_at", "N/A"),
                ]
            )

    return filename


def generate_and_send_module_reports_to_security_officer():
    # Step 1: Get module metadata
    modules = get_module_details()
    module_info = {m["module_id"]: m for m in modules}

    # Step 3: Get all scanned link data grouped by module
    modules_data = fetch_all_links_by_module()

    if not modules_data or not isinstance(modules_data, dict):
        print("❌ No module data returned — cannot generate report.")
        return

    # Step 4: Flatten and sort all links
    all_links = []
    print(f"\nMODULE LINK SUMMARY:")
    for module_id in sorted(modules_data.keys()):
        links = modules_data[module_id]
        if not links:
            continue

        sorted_links = sorted(
            links,
            key=lambda x: (
                (
                    0
                    if x.get("is_paywall", False)
                    else 1 if x.get("risk_score", 0) < 0 else 2
                ),
                x.get("risk_score", 0),
            ),
        )
        all_links.extend(sorted_links)

        scores = [l.get("risk_score", 0) for l in links]
        max_risk = max(scores) if scores else "N/A"
        print(
            f"   Module {module_id}: {len(links)} links, Highest Risk Score: {max_risk}"
        )

    print(f"   Total links: {len(all_links)}")

    # Step 5: Generate reports
    try:

        report_path = generateDocumentReportForSecurityOfficer(all_links)
        print(f"[GENERATED] Word report: {report_path}")

        csv_path = generateCSVForSecurityOfficer(all_links)
        print(f"[GENERATED] CSV report: {csv_path}")

        ucname = "Murdoch Security Officer"
        to_email = "syafiqwork2023@gmail.com"

        # Step 6: Send email with both reports
        send_email_with_report(
            to_email=to_email,
            doc_path=report_path,
            csv_path=csv_path,
            moduleCode="ALL_MODULES",
            ucname=ucname,
        )

    except Exception as e:
        print(f"[FAILURE] Failed to generate/send security officer report: {e}")

    print(
        f"\n [SUCCESS] Full security report completed for {len(modules_data)} modules."
    )


# === MAIN TEST ===
if __name__ == "__main__":
    # Generate and send module-specific reports
    print("🚀 Starting module-specific report generation...")
    # for all UCs
    generate_and_send_module_reports()
    # for ISO next
    generate_and_send_module_reports_to_security_officer()

    # OLD SINGLE REPORT METHOD (commented out)
    # session_id = 24  # Use session 24 which has the most comprehensive risk analysis data
    # all_links = fetch_all_links_for_session(session_id)
    # test_uc = "Peter Cole"
    # test_module = "ICT302"
    # base_url = "http://10.51.33.25/moodle/course/view.php?id=2"
    # report_path = generatePDF(test_uc, test_module, all_links, base_url)
    # send_email_with_report("coordinator@university.edu.au", report_path, test_module, test_uc)

    # MAIN TEST (unchanged, for reference)
    # test_email = "coordinator@university.edu.au"
    # test_module = "ICT302"
    # test_uc = "Peter Cole"
    # base_url = "http://10.51.33.25/moodle/course/view.php?id=2"
    # test_urls = [
    #     {
    #         "url_link": "https://example.com",
    #         "risk_score": "phishing",
    #         "scraped_at": "2025-06-14",
    #         "file_type": "text/html"
    #     },
    #     {
    #         "url_link": "https://www.wsj.com/finance/banking/goldman-sachs-greece-hotel-sell-34b5353a",
    #         "risk_status": "unknown",
    #         "scraped_at": "2025-06-14",
    #         "is_paywall": True,
    #         "file_type": "text/html"
    #     },
    #     {
    #         "url_link": "https://www.nea.gov.sg/docs/default-source/dpc/floatsam-2024.pdf",
    #         "risk_status": "clean",
    #         "scraped_at": "2025-06-14",
    #         "file_type": "application/pdf"
    #     },
    # ]

    # report_path = generatePDF(test_uc, test_module, test_urls, base_url)
    # send_email_with_report(test_email, report_path, test_module, test_uc)

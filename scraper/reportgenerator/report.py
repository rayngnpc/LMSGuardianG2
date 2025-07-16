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

# Add parent directory to path for content filter
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from content_filter import content_filter
    CONTENT_FILTER_AVAILABLE = True
except ImportError:
    print("⚠️ Content filter not available - continuing without filtering")
    CONTENT_FILTER_AVAILABLE = False

load_dotenv(override=True)

def should_exclude_from_apa_citation(url: str, title: str = "", is_paywall: bool = False, is_pornography: bool = False) -> Tuple[bool, str]:
    """Check if content should be excluded from APA citation generation"""
    if not CONTENT_FILTER_AVAILABLE:
        return False, ""
    
    # Check for pornography first
    if is_pornography:
        return True, "Inappropriate content (pornography)"
    
    # Check using content filter
    should_exclude, reason = content_filter.should_exclude_from_apa_citation(url, title, "", is_paywall)
    if should_exclude:
        print(f"🚫 Excluding from APA citation: {url[:50]}... - {reason}")
        return True, reason
    
    return False, ""

def format_scraped_at(raw_ts):
    try:
        dt = datetime.fromisoformat(raw_ts)
        return dt.strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return raw_ts

def fetch_all_links_by_module():
    """Fetch all scraped links grouped by module from the backend with deduplication and proper module association"""
    url = "http://127.0.0.1:8000/scrapedcontents/"
    try:
        res = requests.get(url)
        res.raise_for_status()
        all_data = res.json()
        
        # Step 1: Find the latest/best session for each module
        module_sessions = {}
        for item in all_data:
            module_id = item.get('module_id')
            session_id = item.get('session_id')
            
            if module_id not in module_sessions:
                module_sessions[module_id] = {'sessions': set(), 'latest_session': 0}
            
            module_sessions[module_id]['sessions'].add(session_id)
            module_sessions[module_id]['latest_session'] = max(
                module_sessions[module_id]['latest_session'], session_id
            )
        
        print(f"📊 MODULE SESSIONS ANALYSIS:")
        for module_id, info in module_sessions.items():
            print(f"   Module {module_id}: Sessions {sorted(info['sessions'])}, Latest: {info['latest_session']}")
        
        # Step 2: Group data by module with smart deduplication
        modules_data = {}
        url_tracking = {}  # Track URL -> {module_id: latest_session}
        
        for item in all_data:
            module_id = item.get('module_id')
            session_id = item.get('session_id')
            url_link = item.get('url_link', '')
            
            # Skip empty URLs
            if not url_link or url_link == 'https://example.com/test-external-link':
                continue
            
            # Track which module/session this URL belongs to
            if url_link not in url_tracking:
                url_tracking[url_link] = {}
            
            if module_id not in url_tracking[url_link]:
                url_tracking[url_link][module_id] = session_id
            else:
                # Keep the latest session for this module
                url_tracking[url_link][module_id] = max(
                    url_tracking[url_link][module_id], session_id
                )
        
        # Step 3: Assign each URL to the most appropriate module
        for url_link, module_sessions in url_tracking.items():
            # If URL appears in multiple modules, assign to the one with latest session
            if len(module_sessions) > 1:
                best_module = max(module_sessions.keys(), key=lambda m: module_sessions[m])
                print(f"🔄 URL in multiple modules: {url_link[:50]}... -> Assigned to Module {best_module}")
            else:
                best_module = list(module_sessions.keys())[0]
            
            # Find the actual data item for this URL and module
            matching_items = [item for item in all_data 
                            if item.get('url_link') == url_link and 
                               item.get('module_id') == best_module and
                               item.get('session_id') == module_sessions[best_module]]
            
            if matching_items:
                item = matching_items[0]  # Take the first matching item
                
                if best_module not in modules_data:
                    modules_data[best_module] = []
                
                modules_data[best_module].append(item)
        
        # Print summary
        total_before = len(all_data)
        total_after = sum(len(links) for links in modules_data.values())
        print(f"\\n📊 DEDUPLICATION & MODULE ASSIGNMENT SUMMARY:")
        print(f"   Before: {total_before} total entries")
        print(f"   After: {total_after} unique URLs properly assigned")
        print(f"   Removed: {total_before - total_after} duplicates")
        
        for module_id, links in modules_data.items():
            with_risk = sum(1 for link in links if link.get('risk_score') is not None or 
                           (link.get('risk_category') and link.get('risk_category') not in [None, 'None', '']))
            print(f"   Module {module_id}: {len(links)} unique URLs ({with_risk} with risk analysis)")
        
        return modules_data
    except Exception as e:
        print(f"Failed to fetch links by module: {e}")
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

def generate_and_send_module_reports():
    """Generate separate reports for each module and send to appropriate coordinators"""
    # Module to coordinator mapping (corrected after database fix)
    module_coordinator_map = {
        1: {
            'coordinator_name': 'BSC203 Coordinator',
            'coordinator_email': 'noreplytestict302@gmail.com',  # Your email for testing
            'base_url': 'http://10.51.33.25/moodle/course/view.php?id=2'
        },
        2: {
            'coordinator_name': 'ICT280 Coordinator', 
            'coordinator_email': 'noreplytestict302@gmail.com',  # Your email for testing
            'base_url': 'http://10.51.33.25/moodle/course/view.php?id=3'
        }
        # Add more modules as needed:
        # 3: {
        #     'coordinator_name': 'Module 3 Coordinator',
        #     'coordinator_email': 'module3@university.edu.au',
        #     'base_url': 'http://10.51.33.25/moodle/course/view.php?id=4'
        # }
    }
    
    # Get module details
    modules = get_module_details()
    module_info = {m['module_id']: m for m in modules}
    
    # Get all links grouped by module
    modules_data = fetch_all_links_by_module()
    
    print(f"Found data for {len(modules_data)} modules")
    
    reports_generated = []
    
    for module_id, links in modules_data.items():
        if module_id not in module_info:
            print(f"⚠️ Module {module_id} not found in module details, skipping")
            continue
            
        if module_id not in module_coordinator_map:
            print(f"⚠️ No coordinator mapped for module {module_id}, skipping")
            continue
        
        module = module_info[module_id]
        coordinator = module_coordinator_map[module_id]
        
        # Now use the corrected database values
        unit_code = module.get('unit_code', f'MODULE{module_id}')
        module_name = module.get('module_name', f'Module {module_id}')
        
        coordinator_name = coordinator['coordinator_name']
        coordinator_email = coordinator['coordinator_email']
        base_url = coordinator['base_url']
        
        # Filter links with risk analysis for this module
        links_with_risk = [link for link in links if 
                          link.get('risk_score') is not None or 
                          (link.get('risk_category') and link.get('risk_category') not in [None, 'None', ''])]
        
        total_links = len(links)
        risk_analyzed_links = len(links_with_risk)
        high_risk_links = sum(1 for link in links if 
                             link.get('risk_category') and 
                             any(keyword in link.get('risk_category', '').lower() 
                                 for keyword in ['porn', 'pornography', 'adult content', 'sexually explicit']))
        
        print(f"\\n📊 Module {module_id} ({unit_code}) - {module_name}")
        print(f"   Total links: {total_links}")
        print(f"   Risk analyzed: {risk_analyzed_links}")
        print(f"   High-risk links: {high_risk_links}")
        print(f"   Coordinator: {coordinator_name} ({coordinator_email})")
        
        if risk_analyzed_links == 0:
            print(f"   ⚠️ No risk analysis data available for {unit_code}, skipping report generation")
            continue
        
        # Generate report for this module
        print(f"   📝 Generating report for {unit_code}...")
        try:
            report_path = generatePDF(coordinator_name, unit_code, links, base_url)
            
            # Send email to coordinator
            print(f"   📧 Sending report to {coordinator_email}...")
            send_email_with_report(coordinator_email, report_path, unit_code, coordinator_name)
            
            reports_generated.append({
                'module_id': module_id,
                'unit_code': unit_code,
                'report_path': report_path,
                'coordinator_email': coordinator_email,
                'total_links': total_links,
                'high_risk_links': high_risk_links
            })
            
        except Exception as e:
            print(f"   ❌ Failed to generate/send report for {unit_code}: {e}")
    
    # Summary
    print(f"\\n🎯 SUMMARY:")
    print(f"   Reports generated: {len(reports_generated)}")
    for report in reports_generated:
        print(f"   ✅ {report['unit_code']}: {report['total_links']} links, {report['high_risk_links']} high-risk -> {report['coordinator_email']}")
    
    return reports_generated

def fetch_all_links_for_session(session_id):
    # Fetch all scraped links for the session from the backend
    # Note: The API filtering by session_id seems to have issues, so we fetch all and filter manually
    url = f"http://127.0.0.1:8000/scrapedcontents/"
    try:
        res = requests.get(url)
        res.raise_for_status()
        all_data = res.json()
        # Filter manually for the specific session
        session_data = [item for item in all_data if item.get('session_id') == session_id]
        return session_data
    except Exception as e:
        print(f"Failed to fetch all links for session {session_id}: {e}")
        return []

def generatePDF(ucname: str, moduleCode: str, urls: List[dict], baseUrl: str) -> str:
    # Create a new blank document to avoid logo duplication issues
    doc = Document()

    # Landscape orientation and margins
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.left_margin = Inches(0.3)
    section.right_margin = Inches(0.3)
    section.top_margin = Inches(0.8)  # More space for logo
    section.bottom_margin = Inches(0.5)
    
    # Ensure headers are different for first page (so logo doesn't repeat)
    section.different_first_page_header_footer = True

    # Add logo at the very top of the first page ONLY
    # Get absolute path to ensure logo is found regardless of working directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(current_dir, "logo.png")
    if os.path.exists(logo_path):
        logo_para = doc.add_paragraph()
        logo_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = logo_para.add_run()
        run.add_picture(logo_path, width=Inches(2.2))
        logo_para.space_after = Pt(16)  # Space after logo

    # Professional title and subtitle - directly below logo
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("LMS External Link Risk & Paywall Report")
    run.bold = True
    run.font.size = Pt(18)
    title.space_after = Pt(8)
    
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = subtitle.add_run(f"Unit: {moduleCode} | Coordinator: {ucname}")
    run2.font.size = Pt(12)
    subtitle.space_after = Pt(8)

    # Course info paragraph
    info_para = doc.add_paragraph()
    info_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run3 = info_para.add_run(f"Course URL: {baseUrl}")
    run3.font.size = Pt(10)
    run3.italic = True
    info_para.space_after = Pt(16)

    # Replace placeholders
    replacements = {
        "<Name>": ucname,
        "<Module code>": moduleCode,
        "<URL>": baseUrl,
    }
    for para in doc.paragraphs:
        for key, value in replacements.items():
            if key in para.text:
                para.text = para.text.replace(key, value)

    # Table headers - Removed "Local Path" column
    headers = [
        "Link URL", "Risk Status", "Paywall", "Downloadable", "File Type", "Detected On",
        "APA7 Citation", "LMS Context", "Warning"
    ]
    
    # Create the table
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = 'Table Grid'
    
    # Set column widths - Removed Local Path column, redistributed space
    column_widths = [
        Inches(2.5), Inches(1.5), Inches(0.8), Inches(1.0), Inches(1.0), Inches(1.3),
        Inches(3.5), Inches(1.5), Inches(1.8)
    ]
    
    # Format header row
    header_row = table.rows[0]
    for i, header in enumerate(headers):
        cell = header_row.cells[i]
        cell.text = header
        # Make header bold and centered
        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.bold = True
                run.font.size = Pt(10)
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        # Set column width
        table.columns[i].width = column_widths[i]

    # Add data rows
    for link in urls:
            row = table.add_row().cells
            # ENHANCED: URL normalization and display
            raw_url = link.get("url_link", "")
            
            # Normalize URL formatting
            if raw_url:
                # Fix common URL format issues
                if raw_url.startswith('http:\\\\'):
                    raw_url = raw_url.replace('http:\\\\', 'http://')
                elif raw_url.startswith('https:\\\\'):
                    raw_url = raw_url.replace('https:\\\\', 'https://')
                elif not raw_url.startswith(('http://', 'https://')):
                    raw_url = 'https://' + raw_url
                
                # Clean up double slashes (except in protocol)
                if '://' in raw_url:
                    protocol, rest = raw_url.split('://', 1)
                    rest = rest.replace('//', '/')
                    raw_url = protocol + '://' + rest
            
            url = raw_url
            row[0].text = url
            
            # ENHANCED: Comprehensive risk display with trusted domain detection
            risk_score = link.get("risk_score")
            risk_category = link.get("risk_category", "")
            
            # Check for malicious content first (higher priority than other categorizations)
            is_malicious_content = False
            if CONTENT_FILTER_AVAILABLE:
                is_malicious_content, _ = content_filter.is_malicious_url(url, link.get("title", ""), "", risk_category)
            
            # Also check if risk_category itself indicates malicious content
            malicious_indicators = ["malicious", "spyware", "malware", "compromised", "phishing", "trojan", "virus"]
            if risk_category and any(indicator in risk_category.lower() for indicator in malicious_indicators):
                is_malicious_content = True
            
            # Check if this is a trusted domain (but override if malicious)
            is_trusted_url = False
            if not is_malicious_content:
                try:
                    # Import trusted domain checker
                    import sys
                    sys.path.append('/home/administrator/Test-Chau-LMS/LMSTest/scraper/reputation')
                    from checker import is_trusted_domain
                    is_trusted_url = is_trusted_domain(url)
                except:
                    pass
            
            # Determine risk display based on priority: Malicious > Trusted > Score/Category
            if is_malicious_content:
                risk_display = "🚨 MALICIOUS: Security Threat Detected"
            elif is_trusted_url:
                risk_display = "✅ Trusted Institution"
            elif risk_score is not None:
                # Has a risk score - show enhanced format
                if risk_category and risk_category.strip():
                    # Clean up category name
                    clean_category = risk_category.replace('_', ' ').replace('-', ' ').title()
                    
                    # Check for high-risk categories
                    high_risk_keywords = ["porn", "pornography", "adult content", "sexually explicit", "phishing", "malware", "trackers", "nsfw"]
                    is_high_risk = any(keyword in risk_category.lower() for keyword in high_risk_keywords)
                    
                    if is_high_risk:
                        risk_display = f"🚨 HIGH RISK: {clean_category} ({risk_score}%)"
                    elif risk_score == 0:
                        risk_display = f"✅ Safe: {clean_category}"
                    elif risk_score <= 20:
                        risk_display = f"✅ Low Risk: {clean_category} ({risk_score}%)"
                    elif risk_score <= 50:
                        risk_display = f"⚠️ Medium Risk: {clean_category} ({risk_score}%)"
                    else:
                        risk_display = f"🚨 High Risk: {clean_category} ({risk_score}%)"
                else:
                    # Score only
                    if risk_score == 0:
                        risk_display = "✅ Safe"
                    elif risk_score <= 20:
                        risk_display = f"✅ Low Risk ({risk_score}%)"
                    elif risk_score <= 50:
                        risk_display = f"⚠️ Medium Risk ({risk_score}%)"
                    else:
                        risk_display = f"🚨 High Risk ({risk_score}%)"
            else:
                # No risk score available
                if risk_category and risk_category.strip():
                    clean_category = risk_category.replace('_', ' ').replace('-', ' ').title()
                    if risk_category.lower() in ["trusted_domain", "trusted"]:
                        risk_display = "✅ Trusted Institution"
                    else:
                        risk_display = f"External: {clean_category}"
                else:
                    risk_display = "External (Not analyzed)"
            
            row[1].text = risk_display
            
            row[2].text = "Yes" if link.get("is_paywall") else "No"
            
            # ENHANCED: Comprehensive downloadable and file type detection
            downloadable = "No"
            file_type = "Web Page"
            
            # Comprehensive file type detection
            file_type_mapping = {
                # Documents
                '.pdf': 'PDF Document',
                '.doc': 'Word Document',
                '.docx': 'Word Document',
                '.txt': 'Text File',
                '.rtf': 'Rich Text Format',
                '.odt': 'OpenDocument Text',
                
                # Spreadsheets
                '.xls': 'Excel Spreadsheet',
                '.xlsx': 'Excel Spreadsheet',
                '.csv': 'CSV File',
                '.ods': 'OpenDocument Spreadsheet',
                
                # Presentations
                '.ppt': 'PowerPoint Presentation',
                '.pptx': 'PowerPoint Presentation',
                '.odp': 'OpenDocument Presentation',
                
                # Archives
                '.zip': 'ZIP Archive',
                '.rar': 'RAR Archive',
                '.7z': '7-Zip Archive',
                '.tar': 'TAR Archive',
                '.gz': 'GZip Archive',
                
                # Media
                '.jpg': 'JPEG Image',
                '.jpeg': 'JPEG Image',
                '.png': 'PNG Image',
                '.gif': 'GIF Image',
                '.bmp': 'Bitmap Image',
                '.svg': 'SVG Image',
                '.mp4': 'MP4 Video',
                '.avi': 'AVI Video',
                '.mov': 'QuickTime Video',
                '.wmv': 'Windows Media Video',
                '.mp3': 'MP3 Audio',
                '.wav': 'WAV Audio',
                '.flac': 'FLAC Audio',
                
                # Code/Development
                '.py': 'Python Script',
                '.js': 'JavaScript File',
                '.html': 'HTML Document',
                '.css': 'CSS Stylesheet',
                '.xml': 'XML Document',
                '.json': 'JSON Data'
            }
            
            # Check for file extensions in URL
            url_lower = url.lower()
            detected_extension = None
            
            for ext, type_name in file_type_mapping.items():
                if url_lower.endswith(ext) or f'{ext}?' in url_lower or f'{ext}#' in url_lower:
                    downloadable = "Yes"
                    file_type = type_name
                    detected_extension = ext
                    break
            
            # Additional check for common download patterns
            if not detected_extension:
                download_indicators = [
                    '/download/', '/files/', '/attachments/', '/documents/', 
                    '/uploads/', '/media/', '/assets/', 'download.php',
                    'file.php', 'attachment.php'
                ]
                if any(indicator in url_lower for indicator in download_indicators):
                    downloadable = "Possible"
                    file_type = "Download Link"
            
            row[3].text = downloadable
            row[4].text = file_type
            raw_ts = link.get("scraped_at", "")
            row[5].text = format_scraped_at(raw_ts)
            
            # Generate APA7 citation if needed - but exclude pornography, paywall, and malicious content
            existing_apa7 = link.get("apa7", "") or ""
            if not existing_apa7 and needs_apa7_citation(url):
                # Enhanced pornography detection using API categories
                is_pornography = link.get("is_pornography", False)
                risk_category = link.get("risk_category", "")
                
                if not is_pornography and CONTENT_FILTER_AVAILABLE:
                    # Check using content filter with API risk category
                    is_porn, _ = content_filter.is_pornography_url(url, link.get("title", ""), "", risk_category)
                    is_pornography = is_porn
                
                # Check if content should be excluded from APA citation
                should_exclude_apa, exclude_reason = should_exclude_from_apa_citation(
                    url, 
                    link.get("title", ""), 
                    link.get("is_paywall", False), 
                    is_pornography
                )
                if should_exclude_apa:
                    row[6].text = f"APA Citation not generated ({exclude_reason})"
                    print(f"🚫 APA blocked for {url[:50]}... - {exclude_reason}")
                else:
                    print(f"   📚 Generating APA7 citation for: {url[:50]}...")
                    apa7_citation = generate_apa7_citation(url, raw_ts)
                    row[6].text = apa7_citation
            else:
                row[6].text = existing_apa7
            
            row[7].text = link.get("lms_context", "") or ""
            
            # Updated Warning column logic - removed Local Path (was row[8])
            warnings = []
            
            # Check for paywall
            if link.get("is_paywall"):
                warnings.append("Paywalled/Controlled Access")
            
            # Check for pornography/inappropriate content using API categories
            is_pornography = link.get("is_pornography", False)
            risk_category = link.get("risk_category", "")
            
            if is_pornography:
                warnings.append("Inappropriate Content")
            elif CONTENT_FILTER_AVAILABLE:
                # Check using content filter with API risk category
                is_porn, _ = content_filter.is_pornography_url(url, link.get("title", ""), "", risk_category)
                if is_porn:
                    warnings.append("Inappropriate Content")
            
            # Check for malicious content
            risk_category = link.get("risk_category", "")
            if CONTENT_FILTER_AVAILABLE:
                is_malicious, _ = content_filter.is_malicious_url(url, link.get("title", ""), "", risk_category)
                # Only add warning if not already shown in risk display
                if is_malicious and not is_malicious_content:
                    warnings.append("Malicious Content")
            
            # Set warning text
            if warnings:
                row[8].text = "Warning: " + ", ".join(warnings)
            else:
                row[8].text = ""
            for idx, cell in enumerate(row):
                cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT if idx == 0 else WD_ALIGN_PARAGRAPH.CENTER
                cell.paragraphs[0].runs[0].font.size = Pt(9)

    # Add a professional footer
    footer = doc.sections[0].footer
    footer_para = footer.paragraphs[0]
    footer_para.text = "Generated by LMS Guardian | Confidential"
    footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer_para.runs[0].font.size = Pt(8)
    footer_para.runs[0].italic = True

    sg = pytz.timezone("Asia/Singapore")
    safe_code = datetime.now(sg).strftime("%Y-%m-%d")
    filename = f"{safe_code}_{moduleCode}_report.docx"
    # Get absolute path to ensure reports are saved in the correct location
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(current_dir, "report")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)
    doc.save(output_path)

    print(f"✅ Report saved to: {output_path}")
    return output_path

def send_email_with_report(
    to_email: str, attachment_path: str, moduleCode: str, ucname: str
):
    EMAIL_ADDRESS = os.getenv("EMAIL_USER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("Email credentials not set in environment.")
        return

    msg = EmailMessage()
    msg["From"] = f"LMS Guardian <{EMAIL_ADDRESS}>"
    msg["To"] = to_email
    msg["Subject"] = f"[ALERT] High-risk links detected in {moduleCode}"
    msg["Reply-To"] = "noreply@example.com"

    body = f"""
Dear {ucname},

We wish to inform you that high-risk external links have been detected on the LMS course site for {moduleCode}. As the Unit Coordinator, your attention is required to review and address the issues identified in the attached report.

Please find the report enclosed for your reference.

(This is an automatically generated notification. Please do not reply.)

Best regards,  
LMS Guardian Team
"""
    msg.set_content(body)

    with open(attachment_path, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=os.path.basename(attachment_path),
        )

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)

        print(f"📨 Email sent to {to_email} ✅")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def generate_apa7_citation(url: str, scraped_date: str = None) -> str:
    """Generate APA7 citation for a URL"""
    try:
        # Parse URL for basic info
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('www.', '')
        
        # Determine file type
        file_extension = None
        for ext in ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx']:
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
            r'/(\d{4})/',     # /2018/
            r'/(\d{4})-',     # /2018-
            r'(\d{4})\.',     # 2018.pdf
            r'(\d{4})guide',  # 2016guide
            r'project(\d{4})', # project2016
            r'(\d{4})report', # 2018report
            r'-(\d{4})-',     # -2020-
            r'(\d{4})$',      # ends with year
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
        path_parts = parsed_url.path.split('/')
        if path_parts:
            filename = path_parts[-1]
            if filename and '.' in filename:
                # Clean up filename to make a better title
                title = filename.split('.')[0].replace('-', ' ').replace('_', ' ').title()
                
                # If we found a year in URL, remove it from title to avoid duplication
                if url_year:
                    # Remove year patterns from title more thoroughly
                    year_str = str(url_year)
                    title = re.sub(rf'{year_str}', '', title).strip()
                    title = re.sub(r'Project\s*', 'Project ', title, flags=re.IGNORECASE)  # Clean up "Project" spacing
                    title = re.sub(r'Analysis\s*', 'Analysis ', title, flags=re.IGNORECASE)  # Clean up "Analysis" spacing
                    title = re.sub(r'Report\s*$', '', title, flags=re.IGNORECASE)  # Remove trailing "Report"
                    title = re.sub(r'\s+', ' ', title)  # Clean up extra spaces
                    title = title.strip()
                
                # Clean up common patterns
                title = re.sub(r'[^\w\s\-\.\,\:\;\(\)]', '', title)
                if len(title) > 80:
                    title = title[:77] + "..."
        
        # Enhanced metadata extraction with better error handling
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Disable SSL warnings for this request
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = requests.get(url, headers=headers, timeout=8, verify=False)
            
            if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract title with better cleaning
                title_tag = soup.find('title')
                if title_tag and title_tag.get_text().strip():
                    extracted_title = title_tag.get_text().strip()
                    # Clean up title
                    extracted_title = re.sub(r'\s+', ' ', extracted_title)
                    extracted_title = re.sub(r'[^\w\s\-\.\,\:\;\(\)]', '', extracted_title)
                    if len(extracted_title) > 5 and 'untitled' not in extracted_title.lower():
                        title = extracted_title[:100] + "..." if len(extracted_title) > 100 else extracted_title
                
                # Extract author from various meta tags
                for author_selector in [
                    'meta[name="author"]',
                    'meta[name="dc.creator"]',
                    'meta[property="article:author"]',
                    '.author', '.byline'
                ]:
                    author_elem = soup.select_one(author_selector)
                    if author_elem:
                        if author_elem.name == 'meta':
                            author = author_elem.get('content', '').strip()
                        else:
                            author = author_elem.get_text().strip()
                        if author:
                            break
                
                # Extract publication date
                for date_selector in [
                    'meta[name="dc.date"]',
                    'meta[property="article:published_time"]',
                    'meta[name="pubdate"]',
                    'time[datetime]'
                ]:
                    date_elem = soup.select_one(date_selector)
                    if date_elem:
                        if date_elem.name == 'meta':
                            pub_date = date_elem.get('content', '').strip()
                        else:
                            pub_date = date_elem.get('datetime') or date_elem.get_text().strip()
                        if pub_date:
                            break
                
        except Exception as e:
            # Silently continue with URL-based title
            pass
        
        # Determine resource type for citation
        if file_extension:
            if file_extension.lower() == '.pdf':
                resource_type = "[PDF document]"
            else:
                resource_type = f"[{file_extension.upper().replace('.', '')} document]"
        elif any(edu_domain in domain for edu_domain in ['edu.au', '.edu']):
            resource_type = "[Educational website]"
        elif any(keyword in url.lower() for keyword in ['research', 'journal', 'academic']):
            resource_type = "[Research resource]"
        else:
            resource_type = "[Website]"
        
        # Use scraped date or current date for access date
        if scraped_date:
            try:
                access_date = datetime.fromisoformat(scraped_date.replace('Z', '+00:00'))
                access_date_str = access_date.strftime("%B %d, %Y")
            except:
                access_date_str = datetime.now().strftime("%B %d, %Y")
        else:
            access_date_str = datetime.now().strftime("%B %d, %Y")
        
        # Properly format site name for APA7 (capitalize first letter)
        site_name = domain.replace('.com', '').replace('.au', '').replace('.org', '').replace('.edu', '').replace('.gov', '').title()
        
        # Remove resource type from title if it's already mentioned
        if resource_type in title:
            title = title.replace(resource_type, '').strip()
        
        # Clean up title formatting
        title = re.sub(r'\s+', ' ', title).strip()
        if not title.endswith('.'):
            title += '.'
        
        # Determine if we need "Retrieved" statement (only for likely-to-change content)
        needs_retrieved = any(keyword in url.lower() for keyword in ['news', 'blog', 'wiki', 'forum', 'comment', 'social'])
        
        # Generate APA7 citation based on available information
        if author and pub_date:
            # Full citation with author and date
            try:
                pub_year = re.search(r'(\d{4})', pub_date).group(1)
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
        domain = parsed_url.netloc.replace('www.', '')
        site_name = domain.replace('.com', '').replace('.au', '').replace('.org', '').replace('.edu', '').replace('.gov', '').title()
        access_date_str = datetime.now().strftime("%B %d, %Y")
        
        # Only use retrieved if likely to change
        needs_retrieved = any(keyword in url.lower() for keyword in ['news', 'blog', 'wiki', 'forum', 'comment', 'social'])
        if needs_retrieved:
            return f"Resource (n.d.). {site_name}. Retrieved {access_date_str}, from {url}"
        else:
            return f"Resource (n.d.). {site_name}. {url}"

def needs_apa7_citation(url: str) -> bool:
    """Determine if a URL needs an APA7 citation"""
    # Check for downloadable academic files
    academic_extensions = ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx']
    for ext in academic_extensions:
        if ext.lower() in url.lower():
            return True
    
    # Check for academic domains
    academic_domains = ['edu.au', '.edu', 'researchgate', 'scholar.google', 'jstor', 'arxiv']
    for domain in academic_domains:
        if domain in url.lower():
            return True
    
    # Check for research/academic keywords
    academic_keywords = ['research', 'paper', 'journal', 'study', 'publication', 'thesis', 'academic']
    for keyword in academic_keywords:
        if keyword in url.lower():
            return True
    
    return False

# === MAIN TEST ===
if __name__ == "__main__":
    # Generate and send module-specific reports
    print("🚀 Starting module-specific report generation...")
    reports = generate_and_send_module_reports()
    
    if reports:
        print(f"\\n✅ Successfully generated and sent {len(reports)} module-specific reports!")
    else:
        print("\\n❌ No reports were generated. Check the data and configuration.")
    
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

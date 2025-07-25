"""
APA 7th Edition Citation Generator
Automatically extracts metadata and generates proper APA citations for websites and downloadable files.
"""

import requests
from bs4 import BeautifulSoup
import PyPDF2
import docx
from pptx import Presentation
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
import re
import os
from urllib.parse import urlparse, unquote
from typing import Dict, List, Optional, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APACitationGenerator:
    """
    Generates APA 7th edition citations by extracting metadata from websites and files.
    """
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def generate_citation(self, url: str, title: str = None) -> Dict[str, str]:
        """
        Generate APA citation for a given URL.
        
        Args:
            url (str): The URL to analyze
            title (str): Optional title if already known
            
        Returns:
            Dict containing citation components and formatted citation
        """
        try:
            # Determine if URL is a downloadable file or website
            file_extension = self._get_file_extension(url)
            
            if file_extension:
                return self._generate_file_citation(url, file_extension, title)
            else:
                return self._generate_website_citation(url, title)
                
        except Exception as e:
            logger.error(f"Error generating citation for {url}: {str(e)}")
            return self._generate_fallback_citation(url, title)
    
    def _get_file_extension(self, url: str) -> Optional[str]:
        """Extract file extension from URL."""
        parsed_url = urlparse(url)
        path = unquote(parsed_url.path.lower())
        
        # Common downloadable file extensions
        file_extensions = ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.rtf']
        
        for ext in file_extensions:
            if path.endswith(ext):
                return ext.replace('.', '')
        return None
    
    def _generate_website_citation(self, url: str, title: str = None) -> Dict[str, str]:
        """Generate APA citation for website."""
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract metadata
            metadata = self._extract_website_metadata(soup, url)
            
            # Use provided title if available
            if title:
                metadata['title'] = title
            
            # Format APA citation
            formatted_citation = self._format_website_citation(metadata)
            
            return {
                'type': 'website',
                'citation': formatted_citation,
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f"Error processing website {url}: {str(e)}")
            return self._generate_fallback_citation(url, title)
    
    def _extract_website_metadata(self, soup: BeautifulSoup, url: str) -> Dict[str, str]:
        """Extract metadata from website HTML."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y"),
            'site_name': self._extract_site_name(url)
        }
        
        # Extract title
        title = self._extract_title(soup)
        if title:
            metadata['title'] = title
        
        # Extract author(s)
        authors = self._extract_authors(soup)
        if authors:
            metadata['authors'] = authors
        
        # Extract publication date
        pub_date = self._extract_publication_date(soup)
        if pub_date:
            metadata['publication_date'] = pub_date
        
        # Extract organization/publisher
        organization = self._extract_organization(soup)
        if organization:
            metadata['organization'] = organization
            
        return metadata
    
    def _extract_title(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract title from various sources."""
        # Try meta property="og:title"
        og_title = soup.find('meta', property='og:title')
        if og_title and og_title.get('content'):
            return og_title['content'].strip()
        
        # Try meta name="title"
        meta_title = soup.find('meta', attrs={'name': 'title'})
        if meta_title and meta_title.get('content'):
            return meta_title['content'].strip()
        
        # Try <title> tag
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()
        
        # Try h1 tag
        h1_tag = soup.find('h1')
        if h1_tag:
            return h1_tag.get_text().strip()
        
        return None
    
    def _extract_authors(self, soup: BeautifulSoup) -> List[str]:
        """Extract author information from website."""
        authors = []
        
        # Try meta tags
        author_meta_tags = [
            'author', 'article:author', 'DC.creator', 'citation_author'
        ]
        
        for tag_name in author_meta_tags:
            meta_tags = soup.find_all('meta', attrs={'name': tag_name}) + \
                       soup.find_all('meta', property=tag_name)
            
            for tag in meta_tags:
                content = tag.get('content', '').strip()
                if content and content not in authors:
                    authors.append(content)
        
        # Try structured data (JSON-LD)
        json_ld_authors = self._extract_json_ld_authors(soup)
        authors.extend(json_ld_authors)
        
        # Try common author selectors
        author_selectors = [
            '.author', '.byline', '.author-name', '.writer', 
            '[rel="author"]', '.post-author', '.article-author'
        ]
        
        for selector in author_selectors:
            elements = soup.select(selector)
            for element in elements:
                author_text = element.get_text().strip()
                # Clean up author text
                author_text = re.sub(r'^(by|author:?)\s*', '', author_text, flags=re.IGNORECASE)
                if author_text and len(author_text) < 100 and author_text not in authors:
                    authors.append(author_text)
        
        return authors[:5]  # Limit to 5 authors
    
    def _extract_json_ld_authors(self, soup: BeautifulSoup) -> List[str]:
        """Extract authors from JSON-LD structured data."""
        authors = []
        
        try:
            json_scripts = soup.find_all('script', type='application/ld+json')
            for script in json_scripts:
                import json
                data = json.loads(script.string)
                
                # Handle different JSON-LD structures
                if isinstance(data, list):
                    for item in data:
                        authors.extend(self._extract_authors_from_json_object(item))
                else:
                    authors.extend(self._extract_authors_from_json_object(data))
                    
        except Exception as e:
            logger.debug(f"Error parsing JSON-LD: {str(e)}")
        
        return authors
    
    def _extract_authors_from_json_object(self, obj: dict) -> List[str]:
        """Extract authors from JSON-LD object."""
        authors = []
        
        if 'author' in obj:
            author_data = obj['author']
            if isinstance(author_data, list):
                for author in author_data:
                    if isinstance(author, dict) and 'name' in author:
                        authors.append(author['name'])
                    elif isinstance(author, str):
                        authors.append(author)
            elif isinstance(author_data, dict) and 'name' in author_data:
                authors.append(author_data['name'])
            elif isinstance(author_data, str):
                authors.append(author_data)
        
        return authors
    
    def _extract_publication_date(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract publication date from website."""
        date_selectors = [
            'meta[property="article:published_time"]',
            'meta[name="DC.date"]',
            'meta[name="citation_publication_date"]',
            'meta[name="date"]',
            'time[datetime]',
            '.date', '.published', '.publish-date'
        ]
        
        for selector in date_selectors:
            element = soup.select_one(selector)
            if element:
                # Try to get datetime attribute first
                date_str = element.get('datetime') or element.get('content') or element.get_text()
                if date_str:
                    parsed_date = self._parse_date(date_str.strip())
                    if parsed_date:
                        return parsed_date
        
        return None
    
    def _parse_date(self, date_str: str) -> Optional[str]:
        """Parse various date formats into APA format."""
        try:
            # Common date patterns
            patterns = [
                r'(\d{4})-(\d{1,2})-(\d{1,2})',  # YYYY-MM-DD
                r'(\d{1,2})/(\d{1,2})/(\d{4})',  # MM/DD/YYYY
                r'(\d{1,2})-(\d{1,2})-(\d{4})',  # MM-DD-YYYY
                r'(\d{4})',  # Just year
            ]
            
            for pattern in patterns:
                match = re.search(pattern, date_str)
                if match:
                    if len(match.groups()) == 3:
                        year, month, day = match.groups()
                        if '/' in date_str or (pattern.startswith(r'(\d{1,2})') and '-' in date_str):
                            # MM/DD/YYYY or MM-DD-YYYY format
                            month, day, year = match.groups()
                        
                        try:
                            date_obj = datetime(int(year), int(month), int(day))
                            return date_obj.strftime("%Y, %B %d")
                        except ValueError:
                            continue
                    else:
                        # Just year
                        return match.group(1)
            
        except Exception as e:
            logger.debug(f"Error parsing date {date_str}: {str(e)}")
        
        return None
    
    def _extract_organization(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract organization/publisher from website."""
        # Try meta tags
        org_meta_tags = [
            'og:site_name', 'application-name', 'DC.publisher', 'citation_publisher'
        ]
        
        for tag_name in org_meta_tags:
            meta_tag = soup.find('meta', attrs={'name': tag_name}) or \
                      soup.find('meta', property=tag_name)
            if meta_tag and meta_tag.get('content'):
                return meta_tag['content'].strip()
        
        # Try common organization selectors
        org_selectors = [
            '.site-name', '.publisher', '.organization', '.brand'
        ]
        
        for selector in org_selectors:
            element = soup.select_one(selector)
            if element:
                org_text = element.get_text().strip()
                if org_text and len(org_text) < 100:
                    return org_text
        
        return None
    
    def _extract_site_name(self, url: str) -> str:
        """Extract site name from URL."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Capitalize first letter of each word
        return domain.replace('.', ' ').title()
    
    def _generate_file_citation(self, url: str, file_extension: str, title: str = None) -> Dict[str, str]:
        """Generate APA citation for downloadable files."""
        try:
            # Download file temporarily to extract metadata
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            # Create temporary file
            temp_filename = f"temp_file.{file_extension}"
            with open(temp_filename, 'wb') as f:
                f.write(response.content)
            
            try:
                # Extract metadata based on file type
                if file_extension == 'pdf':
                    metadata = self._extract_pdf_metadata(temp_filename, url)
                elif file_extension in ['doc', 'docx']:
                    metadata = self._extract_word_metadata(temp_filename, url)
                elif file_extension in ['ppt', 'pptx']:
                    metadata = self._extract_powerpoint_metadata(temp_filename, url)
                else:
                    metadata = self._extract_generic_file_metadata(url, title)
                
                # Use provided title if available
                if title:
                    metadata['title'] = title
                
                # Format APA citation
                formatted_citation = self._format_file_citation(metadata, file_extension)
                
                return {
                    'type': 'file',
                    'file_type': file_extension,
                    'citation': formatted_citation,
                    'metadata': metadata
                }
                
            finally:
                # Clean up temporary file
                if os.path.exists(temp_filename):
                    os.remove(temp_filename)
                    
        except Exception as e:
            logger.error(f"Error processing file {url}: {str(e)}")
            return self._generate_fallback_citation(url, title)
    
    def _extract_pdf_metadata(self, filename: str, url: str) -> Dict[str, str]:
        """Extract metadata from PDF file."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y")
        }
        
        try:
            with open(filename, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                if pdf_reader.metadata:
                    # Extract title
                    if pdf_reader.metadata.get('/Title'):
                        metadata['title'] = str(pdf_reader.metadata['/Title']).strip()
                    
                    # Extract author
                    if pdf_reader.metadata.get('/Author'):
                        author_str = str(pdf_reader.metadata['/Author']).strip()
                        metadata['authors'] = [author_str]
                    
                    # Extract creation date
                    if pdf_reader.metadata.get('/CreationDate'):
                        creation_date = str(pdf_reader.metadata['/CreationDate'])
                        parsed_date = self._parse_pdf_date(creation_date)
                        if parsed_date:
                            metadata['publication_date'] = parsed_date
                    
                    # Extract subject/keywords
                    if pdf_reader.metadata.get('/Subject'):
                        metadata['subject'] = str(pdf_reader.metadata['/Subject']).strip()
                
        except Exception as e:
            logger.error(f"Error extracting PDF metadata: {str(e)}")
        
        return metadata
    
    def _parse_pdf_date(self, date_str: str) -> Optional[str]:
        """Parse PDF date format (D:YYYYMMDDHHmmSSOHH'mm)."""
        try:
            # PDF date format: D:YYYYMMDDHHmmSSOHH'mm
            if date_str.startswith('D:'):
                date_part = date_str[2:10]  # YYYYMMDD
                if len(date_part) >= 8:
                    year = int(date_part[:4])
                    month = int(date_part[4:6])
                    day = int(date_part[6:8])
                    
                    date_obj = datetime(year, month, day)
                    return date_obj.strftime("%Y")
            
        except Exception as e:
            logger.debug(f"Error parsing PDF date {date_str}: {str(e)}")
        
        return None
    
    def _extract_word_metadata(self, filename: str, url: str) -> Dict[str, str]:
        """Extract metadata from Word document."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y")
        }
        
        try:
            if filename.endswith('.docx'):
                doc = docx.Document(filename)
                core_props = doc.core_properties
                
                # Extract title
                if core_props.title:
                    metadata['title'] = core_props.title.strip()
                
                # Extract author
                if core_props.author:
                    metadata['authors'] = [core_props.author.strip()]
                
                # Extract creation date
                if core_props.created:
                    metadata['publication_date'] = core_props.created.strftime("%Y")
                
                # Extract subject
                if core_props.subject:
                    metadata['subject'] = core_props.subject.strip()
                    
            else:
                # For .doc files, try to extract using python-docx2txt or similar
                # This is more complex and may require additional libraries
                pass
                
        except Exception as e:
            logger.error(f"Error extracting Word metadata: {str(e)}")
        
        return metadata
    
    def _extract_powerpoint_metadata(self, filename: str, url: str) -> Dict[str, str]:
        """Extract metadata from PowerPoint presentation."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y")
        }
        
        try:
            if filename.endswith('.pptx'):
                prs = Presentation(filename)
                core_props = prs.core_properties
                
                # Extract title
                if core_props.title:
                    metadata['title'] = core_props.title.strip()
                
                # Extract author
                if core_props.author:
                    metadata['authors'] = [core_props.author.strip()]
                
                # Extract creation date
                if core_props.created:
                    metadata['publication_date'] = core_props.created.strftime("%Y")
                
                # Extract subject
                if core_props.subject:
                    metadata['subject'] = core_props.subject.strip()
                    
        except Exception as e:
            logger.error(f"Error extracting PowerPoint metadata: {str(e)}")
        
        return metadata
    
    def _extract_generic_file_metadata(self, url: str, title: str = None) -> Dict[str, str]:
        """Extract basic metadata for generic files."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y")
        }
        
        if title:
            metadata['title'] = title
        else:
            # Extract filename from URL as title
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)
            if filename:
                # Remove extension and format as title
                title_from_filename = os.path.splitext(filename)[0].replace('_', ' ').replace('-', ' ').title()
                metadata['title'] = title_from_filename
        
        return metadata
    
    def _format_website_citation(self, metadata: Dict[str, str]) -> str:
        """Format APA 7th edition citation for website."""
        citation_parts = []
        
        # Author(s) - if available
        if 'authors' in metadata and metadata['authors']:
            authors = metadata['authors']
            if len(authors) == 1:
                citation_parts.append(f"{authors[0]}.")
            elif len(authors) <= 20:
                formatted_authors = []
                for i, author in enumerate(authors):
                    if i == len(authors) - 1 and len(authors) > 1:
                        formatted_authors.append(f"& {author}")
                    else:
                        formatted_authors.append(author)
                citation_parts.append(f"{', '.join(formatted_authors)}.")
            else:
                # More than 20 authors
                first_19 = ', '.join(metadata['authors'][:19])
                last_author = metadata['authors'][-1]
                citation_parts.append(f"{first_19}, ... {last_author}.")
        
        # Title (without italics for web pages)
        if 'title' in metadata:
            title = metadata['title']
            # Remove extra spaces and format
            title = re.sub(r'\s+', ' ', title).strip()
            citation_parts.append(f"{title}.")
        
        # Publication date
        if 'publication_date' in metadata and metadata['publication_date'] != 'n.d.':
            citation_parts.append(f"({metadata['publication_date']}).")
        else:
            # Try to extract year from current year or assume current year for active websites
            current_year = datetime.now().year
            citation_parts.append(f"({current_year}).")
        
        # Website name
        if 'organization' in metadata:
            citation_parts.append(f"{metadata['organization']}.")
        elif 'site_name' in metadata:
            citation_parts.append(f"{metadata['site_name']}.")
        
        # URL (no "Retrieved" text for regular websites)
        citation_parts.append(metadata['url'])
        
        return ' '.join(citation_parts)
    
    def _format_file_citation(self, metadata: Dict[str, str], file_type: str) -> str:
        """Format APA 7th edition citation for downloadable file."""
        citation_parts = []
        
        # Author(s)
        if 'authors' in metadata and metadata['authors']:
            authors = metadata['authors']
            if len(authors) == 1:
                citation_parts.append(f"{authors[0]}.")
            elif len(authors) <= 20:
                formatted_authors = []
                for i, author in enumerate(authors):
                    if i == len(authors) - 1 and len(authors) > 1:
                        formatted_authors.append(f"& {author}")
                    else:
                        formatted_authors.append(author)
                citation_parts.append(f"{', '.join(formatted_authors)}.")
        
        # Publication date
        if 'publication_date' in metadata:
            citation_parts.append(f"({metadata['publication_date']}).")
        else:
            citation_parts.append("(n.d.).")
        
        # Title with format description
        if 'title' in metadata:
            title = metadata['title']
            title = re.sub(r'\s+', ' ', title).strip()
            
            # Add format description
            format_descriptions = {
                'pdf': 'PDF',
                'doc': 'Word document',
                'docx': 'Word document', 
                'ppt': 'PowerPoint presentation',
                'pptx': 'PowerPoint presentation',
                'xls': 'Excel spreadsheet',
                'xlsx': 'Excel spreadsheet'
            }
            
            format_desc = format_descriptions.get(file_type, f'{file_type.upper()} file')
            citation_parts.append(f"*{title}* [{format_desc}].")
        
        # URL and access date
        citation_parts.append(f"Retrieved {metadata['access_date']}, from {metadata['url']}")
        
        return ' '.join(citation_parts)
    
    def _generate_fallback_citation(self, url: str, title: str = None) -> Dict[str, str]:
        """Generate basic citation when metadata extraction fails."""
        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%B %d, %Y"),
            'site_name': self._extract_site_name(url)
        }
        
        if title:
            metadata['title'] = title
        
        # Basic citation format following APA 7th edition
        citation_parts = []
        
        if title:
            citation_parts.append(f"{title}.")
        
        # Use current year for active websites
        current_year = datetime.now().year
        citation_parts.append(f"({current_year}).")
        citation_parts.append(f"{metadata['site_name']}.")
        citation_parts.append(url)
        
        formatted_citation = ' '.join(citation_parts)
        
        return {
            'type': 'fallback',
            'citation': formatted_citation,
            'metadata': metadata
        }

# Example usage function
def generate_apa_citation(url: str, title: str = None) -> Dict[str, str]:
    """
    Generate APA 7th edition citation for a given URL.
    
    Args:
        url (str): The URL to analyze
        title (str): Optional title if already known
        
    Returns:
        Dict containing citation and metadata
    """
    generator = APACitationGenerator()
    return generator.generate_citation(url, title)

if __name__ == "__main__":
    # Test the citation generator
    test_urls = [
        "https://www.apa.org/science/about/psa/2017/10/effective-communication",
        "https://example.com/document.pdf",
        "https://murdoch.edu.au/about/governance"
    ]
    
    generator = APACitationGenerator()
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = generator.generate_citation(url)
        print(f"Citation: {result['citation']}")
        print(f"Type: {result['type']}")

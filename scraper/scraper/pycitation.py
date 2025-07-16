import requests
from bs4 import BeautifulSoup
import dateparser
import json
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple


class APA7CitationGenerator:
    """
    Advanced APA 7th Edition citation generator with comprehensive metadata extraction
    """
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        # Common author meta tags
        self.author_selectors = [
            'meta[name="author"]',
            'meta[name="citation_author"]',
            'meta[property="article:author"]',
            'meta[name="dcterms.creator"]',
            'meta[name="DC.Creator"]',
            '.author',
            '.byline',
            '.article-author',
            '[rel="author"]'
        ]
        
        # Common date meta tags
        self.date_selectors = [
            'meta[property="article:published_time"]',
            'meta[property="article:modified_time"]',
            'meta[name="citation_publication_date"]',
            'meta[name="dcterms.created"]',
            'meta[name="DC.Date"]',
            'meta[name="date"]',
            'meta[name="pubdate"]',
            'meta[itemprop="datePublished"]',
            'meta[itemprop="dateModified"]',
            'time[datetime]',
            '.date',
            '.published',
            '.article-date'
        ]
        
        # Common title selectors
        self.title_selectors = [
            'meta[property="og:title"]',
            'meta[name="citation_title"]',
            'meta[name="dcterms.title"]',
            'meta[name="DC.Title"]',
            'h1',
            '.title',
            '.article-title',
            '.entry-title'
        ]
        
        # Common publisher selectors
        self.publisher_selectors = [
            'meta[property="og:site_name"]',
            'meta[name="citation_publisher"]',
            'meta[name="DC.Publisher"]',
            'meta[name="publisher"]',
            '.publisher',
            '.site-name'
        ]

    def extract_metadata(self, url: str) -> Dict:
        """Extract comprehensive metadata from webpage"""
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            
            metadata = {
                'url': url,
                'title': self._extract_title(soup),
                'authors': self._extract_authors(soup),
                'date': self._extract_date(soup),
                'publisher': self._extract_publisher(soup, url),
                'description': self._extract_description(soup),
                'doi': self._extract_doi(soup),
                'journal': self._extract_journal(soup),
                'volume': self._extract_volume(soup),
                'issue': self._extract_issue(soup),
                'pages': self._extract_pages(soup),
                'accessed_date': datetime.now().strftime("%Y, %B %d")
            }
            
            return metadata
            
        except Exception as e:
            print(f"❌ Error extracting metadata from {url}: {e}")
            return {'url': url, 'error': str(e)}

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract title with fallback hierarchy"""
        # Try structured data first
        title = self._extract_from_jsonld(soup, 'headline') or self._extract_from_jsonld(soup, 'name')
        if title:
            return title
        
        # Try meta tags
        for selector in self.title_selectors[:4]:  # Meta tags first
            element = soup.select_one(selector)
            if element:
                content = element.get('content', '').strip()
                if content:
                    return content
        
        # Try HTML elements
        for selector in self.title_selectors[4:]:
            element = soup.select_one(selector)
            if element:
                text = element.get_text(strip=True)
                if text and len(text) > 5:  # Reasonable title length
                    return text
        
        # Final fallback to page title
        if soup.title:
            return soup.title.get_text(strip=True)
        
        return "No title available"

    def _extract_authors(self, soup: BeautifulSoup) -> List[str]:
        """Extract authors with proper formatting"""
        authors = []
        
        # Try structured data first
        jsonld_authors = self._extract_authors_from_jsonld(soup)
        if jsonld_authors:
            return jsonld_authors
        
        # Try meta tags
        for selector in self.author_selectors[:6]:  # Meta tags first
            elements = soup.select(selector)
            for element in elements:
                content = element.get('content', '').strip()
                if content:
                    # Split multiple authors
                    author_list = self._split_authors(content)
                    authors.extend(author_list)
        
        # Try HTML elements
        if not authors:
            for selector in self.author_selectors[6:]:
                elements = soup.select(selector)
                for element in elements:
                    text = element.get_text(strip=True)
                    if text and len(text) > 2:
                        author_list = self._split_authors(text)
                        authors.extend(author_list)
        
        # Clean and format authors
        cleaned_authors = []
        for author in authors:
            formatted = self._format_author_apa7(author)
            if formatted and formatted not in cleaned_authors:
                cleaned_authors.append(formatted)
        
        return cleaned_authors[:10]  # Limit to reasonable number

    def _extract_date(self, soup: BeautifulSoup) -> Optional[datetime]:
        """Extract publication date with multiple fallbacks"""
        # Try structured data first
        date_str = self._extract_from_jsonld(soup, 'datePublished') or self._extract_from_jsonld(soup, 'dateModified')
        if date_str:
            parsed_date = dateparser.parse(date_str)
            if parsed_date:
                return parsed_date
        
        # Try meta tags
        for selector in self.date_selectors:
            element = soup.select_one(selector)
            if element:
                content = element.get('content') or element.get('datetime', '')
                if content:
                    parsed_date = dateparser.parse(content)
                    if parsed_date:
                        return parsed_date
        
        # Try HTML elements
        for selector in self.date_selectors[9:]:  # HTML elements
            element = soup.select_one(selector)
            if element:
                text = element.get_text(strip=True)
                if text:
                    parsed_date = dateparser.parse(text)
                    if parsed_date:
                        return parsed_date
        
        return None

    def _extract_publisher(self, soup: BeautifulSoup, url: str) -> str:
        """Extract publisher with domain fallback"""
        # Try structured data first
        publisher = self._extract_from_jsonld(soup, 'publisher')
        if publisher:
            return publisher
        
        # Try meta tags
        for selector in self.publisher_selectors:
            element = soup.select_one(selector)
            if element:
                content = element.get('content', '').strip()
                if content:
                    return content
        
        # Fallback to domain
        try:
            domain = urlparse(url).netloc
            # Clean domain
            domain = domain.replace('www.', '').replace('.com', '').replace('.org', '').replace('.edu', '')
            return domain.title()
        except:
            return "Unknown Publisher"

    def _extract_description(self, soup: BeautifulSoup) -> str:
        """Extract description/abstract"""
        selectors = [
            'meta[name="description"]',
            'meta[property="og:description"]',
            'meta[name="citation_abstract"]',
            '.abstract',
            '.description',
            '.summary'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                content = element.get('content') or element.get_text(strip=True)
                if content and len(content) > 20:
                    return content[:500] + "..." if len(content) > 500 else content
        
        return ""

    def _extract_doi(self, soup: BeautifulSoup) -> str:
        """Extract DOI if available"""
        selectors = [
            'meta[name="citation_doi"]',
            'meta[name="DC.Identifier.DOI"]',
            'a[href*="doi.org"]'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                content = element.get('content') or element.get('href', '')
                if 'doi.org' in content:
                    return content
        
        return ""

    def _extract_journal(self, soup: BeautifulSoup) -> str:
        """Extract journal name"""
        selectors = [
            'meta[name="citation_journal_title"]',
            'meta[name="citation_conference_title"]',
            'meta[name="DC.Source"]'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                content = element.get('content', '').strip()
                if content:
                    return content
        
        return ""

    def _extract_volume(self, soup: BeautifulSoup) -> str:
        """Extract volume number"""
        element = soup.select_one('meta[name="citation_volume"]')
        return element.get('content', '') if element else ""

    def _extract_issue(self, soup: BeautifulSoup) -> str:
        """Extract issue number"""
        element = soup.select_one('meta[name="citation_issue"]')
        return element.get('content', '') if element else ""

    def _extract_pages(self, soup: BeautifulSoup) -> str:
        """Extract page numbers"""
        first_page = soup.select_one('meta[name="citation_firstpage"]')
        last_page = soup.select_one('meta[name="citation_lastpage"]')
        
        if first_page and last_page:
            return f"{first_page.get('content', '')}-{last_page.get('content', '')}"
        elif first_page:
            return first_page.get('content', '')
        
        return ""

    def _extract_from_jsonld(self, soup: BeautifulSoup, field: str) -> Optional[str]:
        """Extract data from JSON-LD structured data"""
        scripts = soup.find_all("script", type="application/ld+json")
        for script in scripts:
            try:
                data = json.loads(script.string.strip())
                if isinstance(data, list):
                    data = data[0]
                
                if isinstance(data, dict):
                    value = data.get(field)
                    if value:
                        return str(value)
            except:
                continue
        return None

    def _extract_authors_from_jsonld(self, soup: BeautifulSoup) -> List[str]:
        """Extract authors from JSON-LD structured data"""
        scripts = soup.find_all("script", type="application/ld+json")
        for script in scripts:
            try:
                data = json.loads(script.string.strip())
                if isinstance(data, list):
                    data = data[0]
                
                if isinstance(data, dict) and 'author' in data:
                    author_data = data['author']
                    authors = []
                    
                    if isinstance(author_data, list):
                        for author in author_data:
                            if isinstance(author, dict):
                                name = author.get('name', '')
                                if name:
                                    authors.append(name)
                    elif isinstance(author_data, dict):
                        name = author_data.get('name', '')
                        if name:
                            authors.append(name)
                    
                    return authors
            except:
                continue
        return []

    def _split_authors(self, author_string: str) -> List[str]:
        """Split author string into individual authors"""
        # Common separators
        separators = [';', ',', ' and ', ' & ', ' AND ', '|']
        
        authors = [author_string]
        for sep in separators:
            new_authors = []
            for author in authors:
                new_authors.extend([a.strip() for a in author.split(sep) if a.strip()])
            authors = new_authors
        
        return [a for a in authors if len(a) > 2 and not a.lower().startswith('by')]

    def _format_author_apa7(self, name: str) -> str:
        """Format author name according to APA 7th edition"""
        name = name.strip()
        
        # Remove common prefixes
        prefixes = ['by', 'author:', 'written by', 'por', 'de']
        for prefix in prefixes:
            if name.lower().startswith(prefix):
                name = name[len(prefix):].strip()
        
        # Handle different name formats
        if ',' in name:
            # Already in "Last, First" format
            parts = name.split(',', 1)
            last_name = parts[0].strip()
            first_part = parts[1].strip()
            
            # Extract initials
            initials = self._extract_initials(first_part)
            return f"{last_name}, {initials}"
        else:
            # "First Last" format
            parts = name.split()
            if len(parts) >= 2:
                last_name = parts[-1]
                first_names = parts[:-1]
                initials = ' '.join([f"{n[0].upper()}." for n in first_names if n])
                return f"{last_name}, {initials}"
            else:
                return name  # Single name fallback

    def _extract_initials(self, name_part: str) -> str:
        """Extract initials from name part"""
        parts = name_part.split()
        initials = []
        
        for part in parts:
            if part and part[0].isalpha():
                initials.append(f"{part[0].upper()}.")
        
        return ' '.join(initials)

    def generate_citation(self, url: str) -> Dict:
        """Generate APA 7th edition citation"""
        metadata = self.extract_metadata(url)
        
        if 'error' in metadata:
            return {
                'citation': f"Retrieved from {url}",
                'error': metadata['error'],
                'confidence': 'low'
            }
        
        # Build citation components
        citation_parts = []
        
        # Authors
        if metadata['authors']:
            if len(metadata['authors']) == 1:
                citation_parts.append(metadata['authors'][0])
            elif len(metadata['authors']) <= 20:
                authors_str = ', '.join(metadata['authors'][:-1])
                citation_parts.append(f"{authors_str}, & {metadata['authors'][-1]}")
            else:
                # 21+ authors - use first 19, ellipsis, then last
                first_19 = ', '.join(metadata['authors'][:19])
                citation_parts.append(f"{first_19}, ... {metadata['authors'][-1]}")
        
        # Date
        if metadata['date']:
            date_str = metadata['date'].strftime("(%Y, %B %d)")
        else:
            date_str = "(n.d.)"
        citation_parts.append(date_str)
        
        # Title
        title = metadata['title']
        if metadata['journal']:
            # Journal article - title in sentence case
            title = self._to_sentence_case(title)
        else:
            # Web page - title in italics
            title = f"*{title}*"
        citation_parts.append(f"{title}.")
        
        # Journal information
        if metadata['journal']:
            journal_part = f"*{metadata['journal']}*"
            if metadata['volume']:
                journal_part += f", {metadata['volume']}"
                if metadata['issue']:
                    journal_part += f"({metadata['issue']})"
            if metadata['pages']:
                journal_part += f", {metadata['pages']}"
            citation_parts.append(f"{journal_part}.")
        
        # DOI or URL
        if metadata['doi']:
            citation_parts.append(f"https://doi.org/{metadata['doi'].replace('https://doi.org/', '')}")
        else:
            citation_parts.append(f"Retrieved {metadata['accessed_date']}, from {metadata['url']}")
        
        # Join citation
        citation = ' '.join(citation_parts)
        
        # Determine confidence
        confidence = 'high' if metadata['authors'] and metadata['date'] else 'medium'
        if not metadata['authors'] and not metadata['date']:
            confidence = 'low'
        
        return {
            'citation': citation,
            'metadata': metadata,
            'confidence': confidence
        }

    def _to_sentence_case(self, text: str) -> str:
        """Convert text to sentence case for APA format"""
        if not text:
            return text
        
        # Capitalize first letter and after colons
        result = text[0].upper() + text[1:].lower() if len(text) > 1 else text.upper()
        
        # Handle colons (subtitle capitalization)
        if ':' in result:
            parts = result.split(':')
            parts = [part.strip() for part in parts]
            if len(parts) > 1:
                parts[1] = parts[1][0].upper() + parts[1][1:] if parts[1] else parts[1]
                result = ': '.join(parts)
        
        return result


def format_author_apa(name):
    """Legacy function for backward compatibility"""
    generator = APA7CitationGenerator()
    return generator._format_author_apa7(name)


def generate_simple_citation(url):
    """Legacy function - now uses advanced generator"""
    generator = APA7CitationGenerator()
    result = generator.generate_citation(url)
    
    print(f"📄 Title: {result['metadata'].get('title', 'No title')}")
    print(f"✍️ Authors: {result['metadata'].get('authors', ['No authors'])}")
    print(f"📅 Date: {result['metadata'].get('date', 'No date')}")
    print(f"🏢 Publisher: {result['metadata'].get('publisher', 'No publisher')}")
    print(f"🔗 URL: {url}")
    print(f"📊 Confidence: {result['confidence']}")
    print("\n✅ APA 7th Edition Citation:")
    print(result['citation'])
    print("-" * 80)
    
    return result['citation']


def generate_advanced_citation(url: str) -> Dict:
    """Generate advanced APA citation with full metadata"""
    generator = APA7CitationGenerator()
    return generator.generate_citation(url)
# Test the improved citation system
if __name__ == "__main__":
    test_urls = [
        "https://saturncloud.io/blog/how-to-read-data-from-google-sheets-using-colaboratory-google/",
        "https://d2l.ai/",
        "https://masterofcode.com/blog/generative-ai-in-banking",
        "https://www.geeksforgeeks.org/dsa/linked-list-data-structure/",
        "https://rl.talis.com/3/murdoch/lists/62562748-16DF-53E1-D32E-81C662867B97.html?lang=en-GB"
    ]
    
    print("🔬 Testing Advanced APA 7th Edition Citation Generator\n")
    
    for url in test_urls:
        print(f"🌐 Testing: {url}")
        try:
            result = generate_advanced_citation(url)
            print(f"✅ Success - Confidence: {result['confidence']}")
            print(f"📝 Citation: {result['citation']}")
        except Exception as e:
            print(f"❌ Error: {e}")
        print("-" * 100)

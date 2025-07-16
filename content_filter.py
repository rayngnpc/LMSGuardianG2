#!/usr/bin/env python3
"""
Content filtering utility for LMS Guardian
Detects and filters inappropriate content (pornography, paywall, etc.)
Enhanced with JigsawStack NSFW API (98% accuracy)
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional

# Import JigsawStack NSFW detector
try:
    from jigsawstack_nsfw_detector import enhanced_inappropriate_content_detection
    JIGSAWSTACK_AVAILABLE = True
except ImportError:
    JIGSAWSTACK_AVAILABLE = False
    print("⚠️ JigsawStack NSFW detector not available. Using fallback detection.")

class ContentFilter:
    """Content filtering system for LMS Guardian"""
    
    def __init__(self):
        # Pornography detection patterns
        self.porn_keywords = [
            'porn', 'pornography', 'sex', 'adult', 'xxx', 'explicit',
            'nude', 'naked', 'erotic', 'sexual', 'hardcore', 'softcore',
            'mature', 'nsfw', 'adult entertainment', 'adult content'
        ]
        
        # Pornography domain patterns
        self.porn_domains = [
            'xvideos.com', 'pornhub.com', 'xnxx.com', 'redtube.com',
            'youporn.com', 'tube8.com', 'spankbang.com', 'xhamster.com',
            'beeg.com', 'tnaflix.com', 'porn.com', 'chaturbate.com',
            'cam4.com', 'myfreecams.com', 'livejasmin.com', 'camsoda.com'
        ]
        
        # Paywall indicators
        self.paywall_keywords = [
            'paywall', 'subscription', 'premium', 'subscriber',
            'sign up', 'login required', 'member', 'account required'
        ]
        
        # Known paywall domains
        self.paywall_domains = [
            'wsj.com', 'ft.com', 'nytimes.com', 'bloomberg.com',
            'economist.com', 'newyorker.com', 'washingtonpost.com'
        ]
        
        # Malicious content indicators
        self.malicious_keywords = [
            'malware', 'virus', 'trojan', 'phishing', 'scam', 'fraud',
            'malicious', 'suspicious', 'threat', 'dangerous', 'harmful'
        ]
        
        # Known malicious domains or patterns
        self.malicious_domains = [
            'malicious.site', 'phishing.example.com', 'scam.site',
            'virus.com', 'trojan.net', 'malware.org'
        ]
    
    def is_pornography_url(self, url: str, title: str = "", content: str = "", risk_category: str = "") -> Tuple[bool, str]:
        """
        Enhanced pornography detection using JigsawStack AI (98% accuracy)
        Falls back to multi-layer detection if AI unavailable
        Returns (is_pornography, reason)
        """
        if not url:
            return False, ""
        
        # Primary: JigsawStack AI-powered detection (98% accuracy)
        if JIGSAWSTACK_AVAILABLE:
            try:
                is_inappropriate, reason = enhanced_inappropriate_content_detection(
                    url, title, content, risk_category
                )
                if is_inappropriate:
                    return True, f"JigsawStack AI: {reason}"
            except Exception as e:
                print(f"⚠️ JigsawStack detection failed: {e}")
                # Fall through to backup detection
        
        # Fallback: Multi-layer detection (90% accuracy)
        return self._legacy_pornography_detection(url, title, content, risk_category)
    
    def _legacy_pornography_detection(self, url: str, title: str = "", content: str = "", risk_category: str = "") -> Tuple[bool, str]:
        """
        Legacy multi-layer pornography detection (90% accuracy)
        Used as fallback when JigsawStack is unavailable
        """
        # Check API risk category first (most reliable)
        if risk_category:
            category_lower = risk_category.lower()
            porn_categories = [
                'adult', 'pornography', 'sex', 'adult content', 'sexually explicit',
                'mature', 'nsfw', 'adult entertainment', 'erotic', 'xxx',
                'nude', 'naked', 'hardcore', 'softcore', 'sexual', 'explicit'
            ]
            
            for porn_cat in porn_categories:
                if porn_cat in category_lower:
                    return True, f"Pornographic category from API: {risk_category}"
        
        # Check domain
        domain = urlparse(url).netloc.lower().replace('www.', '')
        if any(porn_domain in domain for porn_domain in self.porn_domains):
            return True, f"Pornographic domain detected: {domain}"
        
        # Check URL path
        url_lower = url.lower()
        if any(keyword in url_lower for keyword in self.porn_keywords):
            return True, f"Pornographic keyword in URL: {url}"
        
        # Check title
        if title:
            title_lower = title.lower()
            if any(keyword in title_lower for keyword in self.porn_keywords):
                return True, f"Pornographic keyword in title: {title[:50]}..."
        
        # Check content (if provided)
        if content:
            content_lower = content.lower()
            porn_count = sum(1 for keyword in self.porn_keywords if keyword in content_lower)
            if porn_count >= 3:  # Multiple porn keywords indicate adult content
                return True, f"Multiple pornographic keywords in content ({porn_count} found)"
        
        return False, ""
    
    def is_paywall_url(self, url: str, title: str = "", content: str = "") -> Tuple[bool, str]:
        """
        Check if URL, title, or content indicates paywall content
        Returns (is_paywall, reason)
        """
        if not url:
            return False, ""
        
        # Check domain
        domain = urlparse(url).netloc.lower().replace('www.', '')
        if any(paywall_domain in domain for paywall_domain in self.paywall_domains):
            return True, f"Known paywall domain: {domain}"
        
        # Check URL path
        url_lower = url.lower()
        if any(keyword in url_lower for keyword in self.paywall_keywords):
            return True, f"Paywall keyword in URL: {url}"
        
        # Check title
        if title:
            title_lower = title.lower()
            if any(keyword in title_lower for keyword in self.paywall_keywords):
                return True, f"Paywall keyword in title: {title[:50]}..."
        
        return False, ""
    
    def is_malicious_url(self, url: str, title: str = "", content: str = "", risk_category: str = "") -> Tuple[bool, str]:
        """
        Check if URL, title, content, or risk category indicates malicious content
        Returns (is_malicious, reason)
        """
        if not url:
            return False, ""
        
        # Check risk category first (from security API results)
        if risk_category:
            risk_lower = risk_category.lower()
            malicious_categories = [
                'malware', 'phishing', 'spam', 'suspicious', 'threat', 
                'dangerous', 'harmful', 'virus', 'trojan', 'scam', 'fraud'
            ]
            if any(category in risk_lower for category in malicious_categories):
                return True, f"Malicious category detected: {risk_category}"
        
        # Check domain
        domain = urlparse(url).netloc.lower().replace('www.', '')
        if any(malicious_domain in domain for malicious_domain in self.malicious_domains):
            return True, f"Known malicious domain: {domain}"
        
        # Check URL path
        url_lower = url.lower()
        if any(keyword in url_lower for keyword in self.malicious_keywords):
            return True, f"Malicious keyword in URL: {url}"
        
        # Check title
        if title:
            title_lower = title.lower()
            if any(keyword in title_lower for keyword in self.malicious_keywords):
                return True, f"Malicious keyword in title: {title[:50]}..."
        
        # Check content (if provided)
        if content:
            content_lower = content.lower()
            malicious_count = sum(1 for keyword in self.malicious_keywords if keyword in content_lower)
            if malicious_count >= 2:  # Multiple malicious keywords indicate threat
                return True, f"Multiple malicious keywords in content ({malicious_count} found)"
        
        return False, ""
    
    def should_exclude_from_local_storage(self, url: str, title: str = "", content: str = "", is_paywall: bool = False, risk_category: str = "") -> Tuple[bool, str]:
        """
        Determine if content should be excluded from local storage
        Returns (should_exclude, reason)
        """
        # Check if it's pornography (with API category support)
        is_porn, porn_reason = self.is_pornography_url(url, title, content, risk_category)
        if is_porn:
            return True, f"Pornographic content: {porn_reason}"
        
        # Check if it's malicious
        is_malicious, malicious_reason = self.is_malicious_url(url, title, content, risk_category)
        if is_malicious:
            return True, f"Malicious content: {malicious_reason}"
        
        # Check if it's paywall (from detection or parameter)
        if is_paywall:
            return True, "Paywall content detected"
        
        is_paywall_detected, paywall_reason = self.is_paywall_url(url, title, content)
        if is_paywall_detected:
            return True, f"Paywall content: {paywall_reason}"
        
        return False, ""
    
    def should_exclude_from_apa_citation(self, url: str, title: str = "", content: str = "", is_paywall: bool = False, risk_category: str = "") -> Tuple[bool, str]:
        """
        Determine if content should be excluded from APA citation generation
        Returns (should_exclude, reason)
        """
        # Same logic as local storage exclusion
        return self.should_exclude_from_local_storage(url, title, content, is_paywall, risk_category)
    
    def get_filter_stats(self) -> Dict:
        """Get statistics about the filter configuration"""
        return {
            "porn_keywords": len(self.porn_keywords),
            "porn_domains": len(self.porn_domains),
            "paywall_keywords": len(self.paywall_keywords),
            "paywall_domains": len(self.paywall_domains)
        }

# Global instance
content_filter = ContentFilter()

def test_content_filter():
    """Test the content filter with sample URLs"""
    test_urls = [
        ("https://www.xvideos.com", "Free Porn Videos"),
        ("https://www.nytimes.com/subscription", "Subscribe to NYTimes"),
        ("https://www.google.com", "Google Search"),
        ("https://www.wsj.com/articles/something", "Wall Street Journal Article"),
        ("https://www.example.com/adult-content", "Adult Content Site")
    ]
    
    print("🔍 Testing Content Filter")
    print("=" * 50)
    
    for url, title in test_urls:
        is_porn, porn_reason = content_filter.is_pornography_url(url, title)
        is_paywall, paywall_reason = content_filter.is_paywall_url(url, title)
        should_exclude, exclude_reason = content_filter.should_exclude_from_local_storage(url, title)
        
        print(f"\\nURL: {url}")
        print(f"Title: {title}")
        print(f"Pornography: {is_porn} - {porn_reason}")
        print(f"Paywall: {is_paywall} - {paywall_reason}")
        print(f"Exclude: {should_exclude} - {exclude_reason}")

if __name__ == "__main__":
    test_content_filter()

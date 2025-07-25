"""
APA Citation Wrapper
Simple wrapper to avoid import issues in the crawler
"""

def generate_apa_citation(url: str) -> str:
    """
    Generate APA citation with proper error handling and import isolation
    """
    try:
        # Try to import and use the enhanced citation system
        import sys
        import os
        
        # Add the parent directory to sys.path for absolute imports
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        from scraper.citation.apa_generator import APACitationGenerator
        
        # Generate citation
        apa_gen = APACitationGenerator()
        result = apa_gen.generate_citation(url)
        return result.get('citation', '')
        
    except Exception as e:
        print(f"⚠️ Enhanced APA citation failed: {e}")
        return ""  # Return empty string for fallback handling

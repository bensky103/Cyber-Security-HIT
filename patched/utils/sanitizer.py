"""
HTML sanitization utilities to prevent XSS attacks in comments.
"""
import html

# Try to import bleach, use a fallback if not available
try:
    import bleach
except ImportError:
    # Create a simple fallback if bleach is not installed
    class MockBleach:
        @staticmethod
        def clean(text, tags=None, attributes=None, strip=None):
            # More comprehensive sanitization
            result = text
            
            # Remove script tags and their content
            import re
            result = re.sub(r'<script.*?>.*?</script>', '', result, flags=re.DOTALL | re.IGNORECASE)
            
            # Remove dangerous attributes like onerror, onclick, etc.
            result = re.sub(r'on\w+=".*?"', '', result, flags=re.IGNORECASE)
            result = re.sub(r"on\w+='.*?'", '', result, flags=re.IGNORECASE)
            
            # If tags specified, only keep those tags
            if tags:
                # Keep only allowed tags
                for tag in tags:
                    # Placeholder to preserve allowed tags
                    result = re.sub(f'<{tag}(.*?)>', f'__KEEP_{tag}_START__\\1__KEEP_END__', result, flags=re.IGNORECASE)
                    result = re.sub(f'</{tag}>', f'__KEEP_{tag}_END__', result, flags=re.IGNORECASE)
                
                # Replace all remaining tags
                result = re.sub(r'<[^>]*>', '', result)
                
                # Restore allowed tags
                for tag in tags:
                    result = result.replace(f'__KEEP_{tag}_START__', f'<{tag}')
                    result = result.replace('__KEEP_END__', '>')
                    result = result.replace(f'__KEEP_{tag}_END__', f'</{tag}>')
            else:
                # Replace all HTML tags with entities
                result = result.replace('<', '&lt;').replace('>', '&gt;')
                
            return result
    
    bleach = MockBleach

class HTMLSanitizer:
    """
    A utility class for sanitizing HTML content to prevent XSS attacks.
    """
    
    def __init__(self):
        # Define allowed tags and attributes for sanitization
        self.allowed_tags = [
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code'
        ]
        
        self.allowed_attributes = {
            '*': ['class', 'id'],  # Allow class and id on any allowed element
            'a': ['href', 'title', 'rel'],  # Allow href, title, and rel on anchors
        }

    def sanitize(self, html_content):
        """
        Sanitize the provided HTML content by removing disallowed tags and attributes.
        
        Args:
            html_content (str): Raw HTML content to sanitize
            
        Returns:
            str: Sanitized HTML content
        """
        if not html_content:
            return ""
            
        try:
            # Use bleach to remove unsafe tags and attributes
            clean_html = bleach.clean(
                html_content,
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                strip=True
            )
            return clean_html
        except Exception as e:
            # If sanitization fails, escape all HTML
            return html.escape(html_content)
    
    def escape(self, text):
        """
        Escape HTML special characters in the provided text.
        
        Args:
            text (str): Text to escape
            
        Returns:
            str: Escaped text safe for HTML context
        """
        if not text:
            return ""
            
        return html.escape(text)

# Create a singleton instance
sanitizer = HTMLSanitizer()

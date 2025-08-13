"""
Security Headers middleware for HTTP responses.
"""
from functools import wraps

# Import conditionally to handle the case when flask is not installed
try:
    from flask import make_response, request as flask_request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create minimal mock for testing
    def make_response(response):
        return response
    flask_request = None

def add_security_headers(response):
    """
    Add security headers to an HTTP response.
    
    The following headers are added:
    - Content-Security-Policy: Prevents inline scripts execution
    - X-Content-Type-Options: Prevents MIME type sniffing
    - Referrer-Policy: Controls referrer information
    - X-Frame-Options: Prevents clickjacking
    """
    # Content Security Policy
    # Default: strict, no inline scripts, self only
    csp = "default-src 'self'; script-src 'self'; object-src 'none';"

    # Special-case: Swagger UI (/docs) needs to load CDN assets and uses inline init script
    try:
        path = getattr(flask_request, 'path', None) if FLASK_AVAILABLE else None
    except Exception:
        path = None

    if path == '/docs':
        # Allow unpkg CDN for scripts/styles/fonts/images and inline for this page only
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; "
            "img-src 'self' data: https://unpkg.com; "
            "font-src 'self' data: https://unpkg.com; "
            "object-src 'none';"
        )

    response.headers['Content-Security-Policy'] = csp
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Control referrer information
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    return response

def security_headers(f):
    """
    Decorator to add security headers to responses.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        return add_security_headers(response)
    return decorated

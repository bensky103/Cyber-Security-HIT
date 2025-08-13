"""
CSRF Protection middleware for secure endpoints.
"""
from functools import wraps

# Import conditionally to handle the case when flask is not installed
try:
    from flask import request, jsonify, g, has_request_context
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create minimal mocks for testing
    class MockRequest:
        method = "GET"
        headers = {}
        remote_addr = "127.0.0.1"
        
    class MockG:
        user = None
        
    request = MockRequest()
    g = MockG()
    
    def has_request_context():
        return False
    
    def jsonify(data):
        return data

from ..logging.logger import security_logger

def csrf_protect(f):
    """
    Decorator to enforce CSRF protection on mutating endpoints (POST, PUT, DELETE).
    - Checks for X-CSRF-Token header
    - Validates the token against the one from login
    - Logs at different levels based on the validation result
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # If there's no active Flask request context (e.g., unit tests calling directly),
        # skip CSRF enforcement and allow the function to run.
        if not FLASK_AVAILABLE or not has_request_context():
            return f(*args, **kwargs)

        # Get the request method
        method = request.method
        
        # Only check CSRF for mutating methods
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get the CSRF token from the header
            csrf_token = request.headers.get('X-CSRF-Token')
            
            # Get client information for logging
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip_address and ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
            
            user = getattr(g, 'user', None)
            username = user.username if user else 'anonymous'
            request_id = request.headers.get('X-Request-ID', 'no-request-id')
            
            # User should be authenticated at this point
            if not hasattr(g, 'user') or not g.user:
                security_logger.error(
                    "CSRF validation failed - User not authenticated",
                    ip=ip_address,
                    user=username,
                    request_id=request_id
                )
                return jsonify({"error": "Authentication required"}), 401
            
            # Check if token is missing
            if not csrf_token:
                security_logger.warning(
                    "Missing CSRF token",
                    ip=ip_address,
                    user=username,
                    request_id=request_id
                )
                return jsonify({"error": "CSRF token required"}), 403
            
            # Double-submit cookie: compare header token to csrf_token cookie
            cookie_token = request.cookies.get('csrf_token')
            if not cookie_token or csrf_token != cookie_token:
                security_logger.error(
                    "CSRF validation failed - Invalid token",
                    ip=ip_address,
                    user=username,
                    request_id=request_id
                )
                return jsonify({"error": "Invalid CSRF token"}), 403
            
            # Log successful validation
            security_logger.info(
                f"Valid CSRF token for {method} request",
                ip=ip_address,
                user=username,
                request_id=request_id
            )
            
        # Continue with the request
        return f(*args, **kwargs)
        
    return decorated

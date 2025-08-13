"""
Shared authentication decorators for routes.
"""
from functools import wraps

# Import conditionally to handle cases where Flask may not be installed
try:
    from flask import request, jsonify, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    class MockRequest:
        headers = {}
        remote_addr = "127.0.0.1"
    class MockG:
        user = None
    request = MockRequest()
    g = MockG()
    def jsonify(data):
        return data

from ..logging.logger import security_logger
from .auth_handler import AuthHandler

def auth_required(f):
    """
    Require a valid JWT (Authorization: Bearer or auth_token cookie).
    On success, attaches g.user with id, username, role.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('auth_token') if hasattr(request, 'cookies') else None
        if not token:
            security_logger.warning(
                "Missing or invalid Authorization",
                ip=request.headers.get('X-Forwarded-For', request.remote_addr),
                request_id=request.headers.get('X-Request-ID', 'no-request-id')
            )
            return jsonify({"error": "Authentication required"}), 401

        # Validate token using TokenManager via AuthHandler
        db = getattr(g, 'db', None)
        auth_handler = AuthHandler(db)
        user = auth_handler.token_manager.validate_token(token)
        if not user:
            security_logger.warning(
                "Invalid token",
                ip=request.headers.get('X-Forwarded-For', request.remote_addr),
                request_id=request.headers.get('X-Request-ID', 'no-request-id')
            )
            return jsonify({"error": "Invalid token"}), 401

        g.user = user
        return f(*args, **kwargs)
    return decorated

"""
Flask routes for authentication endpoints.
"""
from flask import Blueprint, request, jsonify, make_response
import os
import uuid
from sqlalchemy.orm import Session
from app.models.models import User
from ..auth.auth_handler import AuthHandler
from ..auth.rate_limiter import rate_limit, auth_rate_limiter

# Create a blueprint for auth routes
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def get_request_info():
    """Get IP address and generate request ID."""
    # Get client IP, accounting for proxy headers
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    # Generate or get request ID
    request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    
    return ip_address, request_id

@auth_bp.route('/me', methods=['GET'])
def me(db_session: Session):
    """Return current authenticated user's full profile."""
    try:
        # Prefer Authorization header; fallback to auth_token cookie
        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('auth_token')

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        tm = AuthHandler(db_session).token_manager
        is_valid, payload, error = tm.validate_jwt_token(token)
        if not is_valid or not payload:
            return jsonify({"error": error or "Invalid token"}), 401

        user_id = payload.get('sub')
        user: User | None = db_session.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "account_locked": bool(user.account_locked),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/password-policy', methods=['GET'])
def get_password_policy(db_session: Session):
    """Get the current password policy."""
    try:
        auth_handler = AuthHandler(db_session)
        policy = auth_handler.get_password_policy()
        
        return jsonify({
            "status": "success",
            "policy": policy
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@auth_bp.route('/register', methods=['POST'])
@rate_limit()  # Apply rate limiting to register endpoint
def register(db_session: Session):
    """Register a new user."""
    data = request.get_json()
    
    # Get request info
    ip_address, request_id = get_request_info()
    
    # Validate input
    required_fields = ['username', 'email', 'password', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({
                "status": "error",
                "message": f"Missing required field: {field}"
            }), 400
    
    # Extract data
    username = data['username']
    email = data['email']
    password = data['password']
    role = data['role']
    
    # Validate role
    allowed_roles = ['admin', 'support', 'customer']
    if role not in allowed_roles:
        return jsonify({
            "status": "error",
            "message": f"Invalid role. Must be one of: {', '.join(allowed_roles)}"
        }), 400
    
    # Register user
    auth_handler = AuthHandler(db_session)
    success, user, error = auth_handler.register_user(
        username, email, password, role, ip_address, request_id
    )
    
    if success:
        # Return user data without sensitive info
        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
        }), 201
    else:
        return jsonify({
            "status": "error",
            "message": error
        }), 400

@auth_bp.route('/login', methods=['POST'])
@rate_limit()  # Apply rate limiting to login endpoint
def login(db_session: Session):
    """Login and get JWT token."""
    data = request.get_json()
    
    # Get request info
    ip_address, request_id = get_request_info()
    
    # Validate input
    if not data or 'username_or_email' not in data or 'password' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing credentials"
        }), 400
    
    # Extract data
    username_or_email = data['username_or_email']
    password = data['password']
    
    # Login user
    auth_handler = AuthHandler(db_session)
    success, response, error = auth_handler.login(
        username_or_email, password, ip_address, request_id
    )
    
    if success:
        # Create response with secure cookies
        resp = make_response(jsonify({
            "status": "success",
            "message": "Login successful",
            "csrf_token": response["csrf_token"]  # Also returned in body for convenience
        }))

        # Determine cookie security flags
        cookie_secure_env = os.environ.get('COOKIE_SECURE', '').lower() in ['1', 'true', 'yes', 'on']
        secure_flag = request.is_secure or cookie_secure_env

        # HttpOnly secure cookie with JWT (not accessible to JS)
        resp.set_cookie(
            'auth_token',
            value=response["jwt_token"],
            max_age=3600,  # 1 hour
            httponly=True,
            secure=secure_flag,
            samesite='Lax'
        )

        # CSRF token cookie for double-submit pattern (readable by JS)
        resp.set_cookie(
            'csrf_token',
            value=response["csrf_token"],
            max_age=3600,
            httponly=False,
            secure=secure_flag,
            samesite='Lax'
        )

        return resp, 200
    else:
        return jsonify({
            "status": "error",
            "message": error
        }), 401

@auth_bp.route('/change-password', methods=['POST'])
def change_password(db_session: Session):
    """Change user password."""
    data = request.get_json()
    
    # Get request info
    ip_address, request_id = get_request_info()
    
    # Validate input
    if not data or 'old_password' not in data or 'new_password' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing required fields"
        }), 400
    
    # Get user ID from JWT (Authorization Bearer or auth_token cookie)
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    else:
        token = request.cookies.get('auth_token')
    if not token:
        return jsonify({
            "status": "error",
            "message": "Authentication required"
        }), 401

    # Validate token and extract user id
    auth_token_manager = AuthHandler(db_session).token_manager
    is_valid, payload, _ = auth_token_manager.validate_jwt_token(token)
    if not is_valid or not payload or 'sub' not in payload:
        return jsonify({
            "status": "error",
            "message": "Invalid token"
        }), 401
    user_id = payload.get('sub')
    
    # Extract data
    old_password = data['old_password']
    new_password = data['new_password']
    
    # Change password
    auth_handler = AuthHandler(db_session)
    success, error = auth_handler.change_password(
        user_id, old_password, new_password, ip_address, request_id
    )
    
    if success:
        return jsonify({
            "status": "success",
            "message": "Password changed successfully"
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": error
        }), 400

@auth_bp.route('/forgot-password', methods=['POST'])
@auth_bp.route('/password-reset', methods=['POST'])
@rate_limit()  # Apply rate limiting to forgot-password endpoint
def forgot_password(db_session: Session):
    """Request password reset."""
    data = request.get_json()
    
    # Get request info
    ip_address, request_id = get_request_info()
    
    # Validate input
    if not data or 'email' not in data:
        return jsonify({
            "status": "error",
            "message": "Email required"
        }), 400
    
    # Get base reset URL
    reset_url = data.get('reset_url', request.host_url + 'auth/reset-password')
    
    # Process forgot password request
    auth_handler = AuthHandler(db_session)
    success, error = auth_handler.forgot_password(
        data['email'], reset_url, ip_address, request_id
    )
    
    # Always return success to prevent user enumeration
    return jsonify({
        "status": "success",
        "message": "If the email exists, a password reset link has been sent"
    }), 200

@auth_bp.route('/reset-password', methods=['POST'])
@auth_bp.route('/password-reset/confirm', methods=['POST'])
@rate_limit()  # Apply rate limiting to reset-password endpoint
def reset_password(db_session: Session):
    """Reset password with token."""
    data = request.get_json()
    
    # Get request info
    ip_address, request_id = get_request_info()
    
    # Validate input
    if not data or 'token' not in data or 'new_password' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing required fields"
        }), 400
    
    # Extract data
    token = data['token']
    new_password = data['new_password']
    
    # Reset password
    auth_handler = AuthHandler(db_session)
    success, error = auth_handler.reset_password(
        token, new_password, ip_address, request_id
    )
    
    if success:
        return jsonify({
            "status": "success",
            "message": "Password reset successfully"
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": error
        }), 400

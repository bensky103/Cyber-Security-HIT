"""
Authentication routes with intentional vulnerabilities for demo purposes.
IMPORTANT: This file contains intentional security vulnerabilities. DO NOT USE IN PRODUCTION.
"""
from flask import Blueprint, request, jsonify, g
from flask import current_app as app
from sqlalchemy.exc import SQLAlchemyError

from .auth_handler import VulnerableAuthHandler
from patched.logging.logger import security_logger
from patched.utils.audit_manager import create_audit_manager
from patched.auth.token_manager import TokenManager
from patched.config.config import AppConfig
from app.models.models import User

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    VULNERABLE ENDPOINT: Login with SQL injection vulnerability.
    """
    try:
        request_id = request.headers.get('X-Request-ID', 'no-request-id')
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Invalid request data"}), 400
            
        username_or_email = data.get('username_or_email')
        password = data.get('password')
        
        if not username_or_email or password is None:
            return jsonify({"error": "Username/email and password are required"}), 400
            
        # Use vulnerable auth handler with SQL injection vulnerability
        auth_handler = VulnerableAuthHandler(g.db)
        success, result, error = auth_handler.login(
            username_or_email, 
            password,
            request.remote_addr,
            request_id
        )
        
        if not success:
            return jsonify({"error": error}), 401
            
        return jsonify({
            "access_token": result["jwt_token"],
            "csrf_token": result["csrf_token"],
            "token_type": "Bearer"
        }), 200
            
    except SQLAlchemyError as e:
        security_logger.error(
            f"VULN MODE: Database error during login: {str(e)}",
            ip=request.remote_addr,
            request_id=request.headers.get('X-Request-ID', 'no-request-id')
        )
        return jsonify({"error": "Database error during login"}), 500
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error during login: {str(e)}",
            ip=request.remote_addr,
            request_id=request.headers.get('X-Request-ID', 'no-request-id')
        )
        return jsonify({"error": "Error during login"}), 500


@auth_bp.route('/me', methods=['GET'])
def me():
    """Return minimal user info by validating JWT sent via Authorization header (vulnerable mode)."""
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            token = None
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        tm = TokenManager(AppConfig.get_jwt_secret())
        is_valid, payload, error = tm.validate_jwt_token(token)
        if not is_valid or not payload:
            return jsonify({"error": error or "Invalid token"}), 401

        user_id = payload.get('sub')
        user = g.db.query(User).filter(User.id == user_id).first()
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

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registration endpoint - reuse secure implementation.
    """
    try:
        request_id = request.headers.get('X-Request-ID', 'no-request-id')
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Invalid request data"}), 400
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'customer')  # Default to customer role
        
        if not username or not email or not password:
            return jsonify({"error": "Username, email, and password are required"}), 400
            
        # We'll use the vulnerable auth handler but reuse the secure register method
        auth_handler = VulnerableAuthHandler(g.db)
        success, user, error = auth_handler.register_user(
            username, 
            email, 
            password,
            role,
            request.remote_addr,
            request_id
        )
        
        if not success:
            return jsonify({"error": error}), 400
            
        return jsonify({"message": "User registered successfully", "user_id": user.id}), 201
            
    except SQLAlchemyError as e:
        security_logger.error(
            f"VULN MODE: Database error during registration: {str(e)}",
            ip=request.remote_addr,
            request_id=request.headers.get('X-Request-ID', 'no-request-id')
        )
        return jsonify({"error": "Database error during registration"}), 500
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error during registration: {str(e)}",
            ip=request.remote_addr,
            request_id=request.headers.get('X-Request-ID', 'no-request-id')
        )
        return jsonify({"error": "Error during registration"}), 500

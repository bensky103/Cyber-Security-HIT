"""
JWT token generation and validation for authentication.
"""
import jwt
import datetime
import secrets
import hashlib
from typing import Dict, Any, Tuple, Optional

class TokenManager:
    """
    Manage JWT token generation, validation, and CSRF token handling.
    """
    def __init__(self, secret_key: str):
        """
        Initialize the token manager.
        
        Args:
            secret_key: JWT secret key
        """
        self.secret_key = secret_key
        self.algorithm = 'HS256'
        self.token_expiry = datetime.timedelta(hours=1)  # Default 1 hour token validity

    def generate_jwt_token(self, user_id: int, username: str, role: str) -> str:
        """
        Generate a JWT token for a user.
        
        Args:
            user_id: User's ID
            username: User's username
            role: User's role
            
        Returns:
            JWT token string
        """
        payload = {
            # Per RFC 7519, 'sub' should be a string; some PyJWT versions enforce this
            'sub': str(user_id),
            'username': username,
            'role': role,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + self.token_expiry,
            'jti': secrets.token_hex(16)  # JWT ID for tracking unique tokens
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Handle different return types in different jwt versions
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return token

    def validate_jwt_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate a JWT token.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Tuple of (is_valid, payload, error_message)
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return True, payload, None
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError:
            return False, None, "Invalid token"

    def validate_token(self, token: str):
        """
        Backwards-compatible validator used by route decorators.
        Returns a simple object with id, username, and role on success; otherwise None.
        """
        is_valid, payload, _ = self.validate_jwt_token(token)
        if not is_valid or not payload:
            return None
        # Create a lightweight user-like object
        class _UserCtx:
            pass
        u = _UserCtx()
        # JWT 'sub' is user_id by convention
        sub = payload.get('sub')
        # Convert numeric string ids back to int when possible
        try:
            u.id = int(sub)
        except (TypeError, ValueError):
            u.id = sub
        u.username = payload.get('username')
        u.role = payload.get('role')
        return u

    def generate_csrf_token(self) -> str:
        """
        Generate a CSRF token.
        
        Returns:
            CSRF token string
        """
        return secrets.token_hex(32)
        
    def generate_reset_token(self) -> Tuple[str, str]:
        """
        Generate a password reset token and its hash for storage.
        
        Returns:
            Tuple of (token, token_hash)
        """
        # Generate a secure random token (128 bits)
        token = secrets.token_hex(16)
        # Hash the token for storage (SHA-1)
        token_hash = hashlib.sha1(token.encode('utf-8')).hexdigest()
        return token, token_hash


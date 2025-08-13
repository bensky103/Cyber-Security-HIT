"""
Main module for authentication endpoints implementation - VULNERABLE VERSION.
IMPORTANT: This version intentionally contains SQL Injection vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION.
"""
from typing import Dict, Any, List, Tuple, Optional
import hashlib
import secrets
import datetime
from sqlalchemy import text
from sqlalchemy.orm import Session

from patched.logging.logger import security_logger
from patched.config.config import AppConfig, DatabaseConfig
from patched.auth.password_hasher import PasswordHasher
from patched.auth.password_policy import PasswordPolicyValidator
from patched.auth.token_manager import TokenManager
from patched.email.email_adapter import EmailAdapter

from app.models.models import User, PasswordHistory, PasswordResetToken, ForbiddenWord


class VulnerableAuthHandler:
    """
    Vulnerable handler for authentication operations with intentional SQL Injection vulnerability.
    """
    def __init__(self, db_session: Session):
        """
        Initialize the auth handler.
        
        Args:
            db_session: SQLAlchemy database session
        """
        # Initialize database session
        self.db_session = db_session
        
        # Get configuration
        self.db_config = DatabaseConfig(db_session)
        
        # Initialize components
        self.password_hasher = PasswordHasher(AppConfig.get_pepper_secret())
        self.token_manager = TokenManager(AppConfig.get_jwt_secret())
        self.email_adapter = EmailAdapter(AppConfig.get_smtp_config())
        
        # Load password policy and forbidden words
        self.password_policy = None
        self.forbidden_words = []
        self._load_policy_and_words()
        
    def _load_policy_and_words(self) -> None:
        """Load password policy from DB and forbidden words."""
        # Load password policy
        policy_config = self.db_config.get_password_policy()
        
        # Load forbidden words
        forbidden_words_rows = self.db_session.query(ForbiddenWord).all()
        self.forbidden_words = [row.word for row in forbidden_words_rows]
        
        # Initialize policy validator
        self.password_policy = PasswordPolicyValidator(policy_config, self.forbidden_words)
    
    def get_password_policy(self) -> Dict[str, Any]:
        """
        Get the current password policy.
        
        Returns:
            Dictionary with password policy settings
        """
        return self.db_config.get_password_policy()
    
    def register_user(self, username: str, email: str, password: str, role: str, 
                      ip_address: str, request_id: str) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Register a new user with secure password handling.
        
        Args:
            username: Username for the new user
            email: Email address for the new user
            password: Password for the new user
            role: Role for the new user
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, user, error_message)
        """
        try:
            # Check if username or email already exists
            existing_user = self.db_session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                security_logger.warning(
                    "Failed registration attempt - Username or email already exists",
                    ip=ip_address,
                    user=username,
                    request_id=request_id
                )
                return False, None, "Username or email already exists"
            
            # Validate password against policy
            is_valid, validation_errors = self.password_policy.validate(password)
            if not is_valid:
                security_logger.warning(
                    f"Failed registration attempt - Password policy violation: {', '.join(validation_errors)}",
                    ip=ip_address,
                    user=username,
                    request_id=request_id
                )
                return False, None, f"Password policy violation: {', '.join(validation_errors)}"
            
            # Hash the password with PBKDF2-HMAC-SHA256
            password_hash = self.password_hasher.hash(password)
            
            # Create the new user
            new_user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow(),
                account_locked=False,
                failed_login_attempts=0
            )
            
            self.db_session.add(new_user)
            self.db_session.flush()  # Get the user ID without committing
            
            # Add password to history
            password_history = PasswordHistory(
                user_id=new_user.id,
                password_hash=password_hash,
                created_at=datetime.datetime.utcnow()
            )
            
            self.db_session.add(password_history)
            self.db_session.commit()
            
            security_logger.info(
                f"User registered successfully: {username}",
                ip=ip_address,
                user=username,
                request_id=request_id
            )
            
            return True, new_user, None
            
        except Exception as e:
            self.db_session.rollback()
            security_logger.error(
                f"Error during user registration: {str(e)}",
                ip=ip_address,
                user=username,
                request_id=request_id
            )
            return False, None, f"Registration error: {str(e)}"
    
    def login(self, username_or_email: str, password: str, ip_address: str, request_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        VULNERABLE AUTH ENDPOINT - Authenticate a user using raw SQL with SQL injection vulnerability.
        
        Args:
            username_or_email: Username or email for login
            password: Password for login (can contain SQL injection)
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, response_data, error_message)
        """
        try:
            # VULNERABLE IMPLEMENTATION: Direct string concatenation in SQL query
            # Check if there are suspicious SQL injection patterns
            suspicious_patterns = ["--", ";", "/*", "*/", "UNION", "SELECT", "DROP", "DELETE", "INSERT", "UPDATE", 
                                  "OR 1=1", "' OR '", "' OR 1='", "1' OR '1'='1", "admin'--"]
            
            has_suspicious_pattern = any(pattern.lower() in username_or_email.lower() or 
                                        (password and pattern.lower() in password.lower()) 
                                        for pattern in suspicious_patterns)
            
            if has_suspicious_pattern:
                security_logger.warning(
                    f"VULN MODE: Suspicious SQLi pattern detected in login attempt",
                    ip=ip_address,
                    user=username_or_email,
                    request_id=request_id
                )
                # We still process the request in vulnerable mode
            
            security_logger.info(
                "VULN MODE: Processing login with direct SQL string concatenation",
                ip=ip_address,
                user=username_or_email,
                request_id=request_id
            )
            
            # Vulnerable SQL query with direct string concatenation
            vulnerable_query = f"SELECT * FROM users WHERE (username = '{username_or_email}' OR email = '{username_or_email}') AND password_hash = '{password}'"
            
            try:
                # Execute the vulnerable query
                result = self.db_session.execute(text(vulnerable_query))
                user_row = result.fetchone()
                
                if not user_row:
                    security_logger.warning(
                        f"VULN MODE: Failed login attempt - User not found: {username_or_email}",
                        ip=ip_address,
                        user=username_or_email,
                        request_id=request_id
                    )
                    return False, None, "Invalid credentials"
                
                # Get user from the result
                user = self.db_session.query(User).filter(User.id == user_row.id).first()
                
                # Generate JWT token
                jwt_token = self.token_manager.generate_jwt_token(user.id, user.username, user.role)
                
                # Generate CSRF token
                csrf_token = self.token_manager.generate_csrf_token()
                
                security_logger.info(
                    f"VULN MODE: User logged in successfully: {username_or_email}",
                    ip=ip_address,
                    user=username_or_email,
                    request_id=request_id
                )
                
                # Return token and CSRF token
                return True, {
                    "jwt_token": jwt_token,
                    "csrf_token": csrf_token
                }, None
                
            except Exception as e:
                # If direct SQL execution fails, log it and try a fallback
                security_logger.error(
                    f"VULN MODE: Error executing raw SQL login: {str(e)}",
                    ip=ip_address,
                    user=username_or_email,
                    request_id=request_id
                )
                
                # Fallback to ORM for better error handling
                user = self.db_session.query(User).filter(
                    (User.username == username_or_email) | (User.email == username_or_email)
                ).first()
                
                if not user:
                    return False, None, "Invalid credentials"
                
                # Generate JWT token
                jwt_token = self.token_manager.generate_jwt_token(user.id, user.username, user.role)
                
                # Generate CSRF token
                csrf_token = self.token_manager.generate_csrf_token()
                
                return True, {
                    "jwt_token": jwt_token,
                    "csrf_token": csrf_token
                }, None
                
        except Exception as e:
            security_logger.error(
                f"VULN MODE: Error during login: {str(e)}",
                ip=ip_address,
                user=username_or_email,
                request_id=request_id
            )
            return False, None, f"Login error: {str(e)}"

"""
Main module for secure authentication endpoints implementation.
"""
from typing import Dict, Any, List, Tuple, Optional
import hashlib
import secrets
import datetime
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..logging.logger import security_logger
from ..config.config import AppConfig, DatabaseConfig
from ..auth.password_hasher import PasswordHasher
from ..auth.password_policy import PasswordPolicyValidator
from ..auth.token_manager import TokenManager
from ..email.email_adapter import EmailAdapter

from app.models.models import User, PasswordHistory, PasswordResetToken, ForbiddenWord


class AuthHandler:
    """
    Handler for secure authentication operations.
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
        Authenticate a user and issue JWT token with CSRF protection.
        
        Args:
            username_or_email: Username or email for login
            password: Password for login
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, response_data, error_message)
        """
        try:
            # Find user by username or email
            user = self.db_session.query(User).filter(
                (User.username == username_or_email) | (User.email == username_or_email)
            ).first()
            
            if not user:
                security_logger.warning(
                    f"Failed login attempt - User not found: {username_or_email}",
                    ip=ip_address,
                    user=username_or_email,
                    request_id=request_id
                )
                return False, None, "Invalid credentials"
            
            # Check if account is locked
            if user.account_locked:
                security_logger.warning(
                    f"Failed login attempt - Account locked: {username_or_email}",
                    ip=ip_address,
                    user=username_or_email,
                    request_id=request_id
                )
                return False, None, "Account is locked due to too many failed attempts"
            
            # Verify password
            if not self.password_hasher.verify(password, user.password_hash):
                # Use MySQL stored procedure to update failed login attempts atomically
                result = self._update_login_attempts(user.id, False)
                
                if result.get("account_locked"):
                    security_logger.warning(
                        f"Account locked after failed login attempt: {username_or_email}",
                        ip=ip_address,
                        user=username_or_email,
                        request_id=request_id
                    )
                    return False, None, "Invalid credentials. Account locked due to too many failed attempts"
                else:
                    security_logger.warning(
                        f"Failed login attempt - Invalid password: {username_or_email}",
                        ip=ip_address,
                        user=username_or_email,
                        request_id=request_id
                    )
                    return False, None, "Invalid credentials"
            
            # Login successful - reset failed attempts
            self._update_login_attempts(user.id, True)
            
            # Generate JWT token
            jwt_token = self.token_manager.generate_jwt_token(user.id, user.username, user.role)
            
            # Generate CSRF token
            csrf_token = self.token_manager.generate_csrf_token()
            
            security_logger.info(
                f"User logged in successfully: {username_or_email}",
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
            security_logger.error(
                f"Error during login: {str(e)}",
                ip=ip_address,
                user=username_or_email,
                request_id=request_id
            )
            return False, None, f"Login error: {str(e)}"
    
    def _update_login_attempts(self, user_id: int, success: bool) -> Dict[str, Any]:
        """
        Update login attempts using stored procedure.
        
        Args:
            user_id: User ID
            success: Whether login was successful
            
        Returns:
            Dictionary with account_locked and lockout_time if applicable
        """
        try:
            # Call stored procedure
            result = self.db_session.execute(
                text("CALL update_login_attempts(:user_id, :success, :max_attempts, :lockout_minutes, @account_locked, @lockout_time)"),
                {
                    "user_id": user_id,
                    "success": success,
                    "max_attempts": 3,  # Max failed attempts
                    "lockout_minutes": 15  # Lockout time in minutes
                }
            )
            
            # Get output variables
            output = self.db_session.execute(text("SELECT @account_locked as account_locked, @lockout_time as lockout_time"))
            row = output.fetchone()
            
            self.db_session.commit()
            
            return {
                "account_locked": bool(row.account_locked),
                "lockout_time": row.lockout_time
            }
        except Exception as e:
            self.db_session.rollback()
            # Fallback to regular update if stored procedure fails
            user = self.db_session.query(User).filter(User.id == user_id).first()
            
            if success:
                user.failed_login_attempts = 0
                user.account_locked = False
                user.last_login = datetime.datetime.utcnow()
                self.db_session.commit()
                return {"account_locked": False, "lockout_time": None}
            else:
                user.failed_login_attempts += 1
                
                # Lock account if too many failed attempts
                if user.failed_login_attempts >= 3:
                    user.account_locked = True
                    lockout_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
                    user.lockout_until = lockout_time
                    self.db_session.commit()
                    return {"account_locked": True, "lockout_time": lockout_time}
                else:
                    self.db_session.commit()
                    return {"account_locked": False, "lockout_time": None}
    
    def change_password(self, user_id: int, old_password: str, new_password: str, 
                        ip_address: str, request_id: str) -> Tuple[bool, Optional[str]]:
        """
        Change a user's password with policy enforcement.
        
        Args:
            user_id: User ID
            old_password: Current password for verification
            new_password: New password to set
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Get user
            user = self.db_session.query(User).filter(User.id == user_id).first()
            
            if not user:
                security_logger.warning(
                    f"Change password failed - User not found: {user_id}",
                    ip=ip_address,
                    user=str(user_id),
                    request_id=request_id
                )
                return False, "User not found"
            
            # Verify old password
            if not self.password_hasher.verify(old_password, user.password_hash):
                security_logger.warning(
                    f"Change password failed - Invalid old password: {user.username}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, "Invalid old password"
            
            # Validate new password against policy
            is_valid, validation_errors = self.password_policy.validate(new_password)
            if not is_valid:
                security_logger.warning(
                    f"Change password failed - Password policy violation: {', '.join(validation_errors)}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, f"Password policy violation: {', '.join(validation_errors)}"
            
            # Get password history
            password_history = self.db_session.query(PasswordHistory).filter(
                PasswordHistory.user_id == user_id
            ).order_by(PasswordHistory.created_at.desc()).all()
            
            password_hashes = [ph.password_hash for ph in password_history]
            
            # Check if password in history
            history_valid, history_error = self.password_policy.check_history(
                new_password, 
                password_hashes,
                self.password_hasher
            )
            
            if not history_valid:
                security_logger.warning(
                    f"Change password failed - Password history violation: {user.username}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, history_error
            
            # Hash the new password
            new_password_hash = self.password_hasher.hash(new_password)
            
            # Update user's password
            user.password_hash = new_password_hash
            user.updated_at = datetime.datetime.utcnow()
            
            # Add to password history
            password_history = PasswordHistory(
                user_id=user_id,
                password_hash=new_password_hash,
                created_at=datetime.datetime.utcnow()
            )
            
            self.db_session.add(password_history)
            self.db_session.commit()
            
            security_logger.info(
                f"Password changed successfully: {user.username}",
                ip=ip_address,
                user=user.username,
                request_id=request_id
            )
            
            return True, None
            
        except Exception as e:
            self.db_session.rollback()
            security_logger.error(
                f"Error changing password: {str(e)}",
                ip=ip_address,
                user=str(user_id),
                request_id=request_id
            )
            return False, f"Password change error: {str(e)}"
    
    def forgot_password(self, email: str, reset_url: str, ip_address: str, request_id: str) -> Tuple[bool, Optional[str]]:
        """
        Process a forgot password request and generate a reset token.
        
        Args:
            email: User's email address
            reset_url: Base URL for password reset
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Find user by email
            user = self.db_session.query(User).filter(User.email == email).first()
            
            if not user:
                # Don't reveal user existence, but log the attempt
                security_logger.warning(
                    f"Forgot password attempt for non-existent email: {email}",
                    ip=ip_address,
                    user="anonymous",
                    request_id=request_id
                )
                # Still return success to avoid user enumeration
                return True, None
            
            # Generate token and hash
            token, token_hash = self.token_manager.generate_reset_token()
            
            # Set expiry time (15 minutes)
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            
            # Store token hash in database
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token_hash,
                expires_at=expires_at,
                created_at=datetime.datetime.utcnow(),
                used=False
            )
            
            self.db_session.add(reset_token)
            self.db_session.commit()
            
            # Send email with reset token
            email_sent = self.email_adapter.send_password_reset_email(
                user.email,
                user.username,
                token,
                reset_url
            )
            
            if not email_sent:
                security_logger.error(
                    f"Failed to send password reset email: {user.email}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, "Failed to send password reset email"
            
            security_logger.info(
                f"Password reset token generated for user: {user.username}",
                ip=ip_address,
                user=user.username,
                request_id=request_id
            )
            
            return True, None
            
        except Exception as e:
            self.db_session.rollback()
            security_logger.error(
                f"Error processing forgot password request: {str(e)}",
                ip=ip_address,
                user="anonymous",
                request_id=request_id
            )
            return False, f"Forgot password error: {str(e)}"
    
    def reset_password(self, token: str, new_password: str, ip_address: str, request_id: str) -> Tuple[bool, Optional[str]]:
        """
        Reset a user's password using a reset token.
        
        Args:
            token: Reset token from email
            new_password: New password to set
            ip_address: IP address of the request
            request_id: Request ID for tracking
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Hash token for lookup
            token_hash = hashlib.sha1(token.encode('utf-8')).hexdigest()
            
            # Try to validate and consume token using stored procedure
            try:
                # Call stored procedure to validate and consume token
                result = self.db_session.execute(
                    text("CALL validate_reset_token(:token_hash, @valid, @user_id)"),
                    {"token_hash": token_hash}
                )
                
                # Get output variables
                output = self.db_session.execute(text("SELECT @valid as valid, @user_id as user_id"))
                row = output.fetchone()
                
                token_valid = bool(row.valid)
                user_id = row.user_id
                
            except Exception as e:
                # Fallback if stored procedure fails
                token_record = self.db_session.query(PasswordResetToken).filter(
                    PasswordResetToken.token == token_hash,
                    PasswordResetToken.expires_at > datetime.datetime.utcnow(),
                    PasswordResetToken.used == False
                ).first()
                
                if not token_record:
                    token_valid = False
                    user_id = None
                else:
                    token_valid = True
                    user_id = token_record.user_id
                    token_record.used = True
            
            if not token_valid:
                security_logger.warning(
                    "Invalid or expired password reset token",
                    ip=ip_address,
                    user="anonymous",
                    request_id=request_id
                )
                return False, "Invalid or expired password reset token"
            
            # Get user
            user = self.db_session.query(User).filter(User.id == user_id).first()
            
            if not user:
                security_logger.error(
                    f"Reset password failed - User not found: {user_id}",
                    ip=ip_address,
                    user=str(user_id),
                    request_id=request_id
                )
                return False, "User not found"
            
            # Validate new password against policy
            is_valid, validation_errors = self.password_policy.validate(new_password)
            if not is_valid:
                security_logger.warning(
                    f"Reset password failed - Password policy violation: {', '.join(validation_errors)}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, f"Password policy violation: {', '.join(validation_errors)}"
            
            # Get password history
            password_history = self.db_session.query(PasswordHistory).filter(
                PasswordHistory.user_id == user_id
            ).order_by(PasswordHistory.created_at.desc()).all()
            
            password_hashes = [ph.password_hash for ph in password_history]
            
            # Check if password in history
            history_valid, history_error = self.password_policy.check_history(
                new_password, 
                password_hashes,
                self.password_hasher
            )
            
            if not history_valid:
                security_logger.warning(
                    f"Reset password failed - Password history violation: {user.username}",
                    ip=ip_address,
                    user=user.username,
                    request_id=request_id
                )
                return False, history_error
            
            # Hash the new password
            new_password_hash = self.password_hasher.hash(new_password)
            
            # Update user's password
            user.password_hash = new_password_hash
            user.updated_at = datetime.datetime.utcnow()
            user.account_locked = False
            user.failed_login_attempts = 0
            
            # Add to password history
            password_history = PasswordHistory(
                user_id=user_id,
                password_hash=new_password_hash,
                created_at=datetime.datetime.utcnow()
            )
            
            self.db_session.add(password_history)
            self.db_session.commit()
            
            security_logger.info(
                f"Password reset successfully: {user.username}",
                ip=ip_address,
                user=user.username,
                request_id=request_id
            )
            
            return True, None
            
        except Exception as e:
            self.db_session.rollback()
            security_logger.error(
                f"Error resetting password: {str(e)}",
                ip=ip_address,
                user="anonymous",
                request_id=request_id
            )
            return False, f"Password reset error: {str(e)}"

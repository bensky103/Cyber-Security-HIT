"""
Tests for the Phase 2 secure authentication implementation.
"""
import os
import pytest
import datetime
import hashlib
from unittest.mock import patch, MagicMock

# Configure test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-jwt-secret-key-for-testing-only"
os.environ["PEPPER_SECRET"] = "test-pepper-secret-key-for-testing-only"

# Import our auth components
from patched.auth.password_hasher import PasswordHasher
from patched.auth.password_policy import PasswordPolicyValidator
from patched.auth.token_manager import TokenManager
from patched.auth.auth_handler import AuthHandler
from app.models.models import Base, User, PasswordHistory, PasswordResetToken, ForbiddenWord

# SQLAlchemy setup for tests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session


class TestPasswordPolicy:
    """Test the password policy validator."""

    def setup_method(self):
        """Set up the test environment."""
        self.config = {
            "min_length": 10,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digit": True,
            "require_special": True,
            "history_count": 3
        }
        self.forbidden_words = ["password", "admin", "user"]
        self.validator = PasswordPolicyValidator(self.config, self.forbidden_words)

    def test_password_length(self):
        """Test password length requirement."""
        # Too short
        is_valid, errors = self.validator.validate("Short1!")
        assert not is_valid
        assert any("length" in error.lower() for error in errors)

        # Valid length
        is_valid, errors = self.validator.validate("LongEnough1!")
        assert is_valid or not any("length" in error.lower() for error in errors)

    def test_character_requirements(self):
        """Test character class requirements."""
        # Missing uppercase
        is_valid, errors = self.validator.validate("nouppercase1!")
        assert not is_valid
        assert any("uppercase" in error.lower() for error in errors)

        # Missing lowercase
        is_valid, errors = self.validator.validate("NOLOWERCASE1!")
        assert not is_valid
        assert any("lowercase" in error.lower() for error in errors)

        # Missing digit
        is_valid, errors = self.validator.validate("NoDigitsHere!")
        assert not is_valid
        assert any("digit" in error.lower() for error in errors)

        # Missing special char
        is_valid, errors = self.validator.validate("NoSpecialChars123")
        assert not is_valid
        assert any("special" in error.lower() for error in errors)

        # Valid with all requirements
        is_valid, errors = self.validator.validate("ValidP@ssw0rd")
        assert is_valid or errors == []

    def test_forbidden_words(self):
        """Test forbidden words check."""
        # Contains forbidden word
        is_valid, errors = self.validator.validate("MyPassword123!")
        assert not is_valid
        assert any("forbidden" in error.lower() for error in errors)

        # Valid without forbidden words
        is_valid, errors = self.validator.validate("Secure@Phrase123")
        assert is_valid or not any("forbidden" in error.lower() for error in errors)

    def test_password_history(self):
        """Test password history validation."""
        # Mock password hasher
        hasher = MagicMock()
        
        # Set up the mock to match first password but not second
        hasher.verify.side_effect = lambda pw, stored: pw == "OldPass123!"
        
        # Password history check
        old_passwords = ["hash1", "hash2", "hash3"]
        
        # Should fail - same as old password
        valid, error = self.validator.check_history("OldPass123!", old_passwords, hasher)
        assert not valid
        assert error is not None
        
        # Should pass - new password
        valid, error = self.validator.check_history("NewPass456@", old_passwords, hasher)
        assert valid
        assert error is None


class TestPasswordHasher:
    """Test the password hasher."""

    def setup_method(self):
        """Set up the test environment."""
        self.pepper = "test-pepper-key"
        self.hasher = PasswordHasher(self.pepper)

    def test_hash_and_verify(self):
        """Test password hashing and verification."""
        password = "SecureP@ssw0rd"
        
        # Hash the password
        password_hash = self.hasher.hash(password)
        
        # Verify components of the hash
        parts = password_hash.split('$')
        assert len(parts) == 4
        assert parts[0] == "pbkdf2_sha256"
        assert int(parts[1]) > 0  # Should have iterations
        
        # Verify correct password
        assert self.hasher.verify(password, password_hash)
        
        # Verify incorrect password fails
        assert not self.hasher.verify("WrongP@ssw0rd", password_hash)

    def test_different_passwords_produce_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "SecureP@ssw0rd1"
        password2 = "SecureP@ssw0rd2"
        
        hash1 = self.hasher.hash(password1)
        hash2 = self.hasher.hash(password2)
        
        assert hash1 != hash2

    def test_same_password_produces_different_hashes(self):
        """Test that same password produces different hashes due to salt."""
        password = "SecureP@ssw0rd"
        
        hash1 = self.hasher.hash(password)
        hash2 = self.hasher.hash(password)
        
        assert hash1 != hash2

    def test_pepper_affects_hash(self):
        """Test that changing pepper produces different verification results."""
        password = "SecureP@ssw0rd"
        
        # Hash with original pepper
        password_hash = self.hasher.hash(password)
        
        # Create new hasher with different pepper
        different_hasher = PasswordHasher("different-pepper")
        
        # Should fail verification with different pepper
        assert not different_hasher.verify(password, password_hash)


class TestAuthHandler:
    """Test the authentication handler."""

    @pytest.fixture(autouse=True)
    def setup_db(self):
        """Set up the database for tests."""
        # Create in-memory SQLite database
        self.engine = create_engine("sqlite:///:memory:")
        
        # Create all tables
        Base.metadata.create_all(self.engine)
        
        # Create session
        Session = sessionmaker(bind=self.engine)
        self.db_session = Session()
        
        # Set up forbidden words
        try:
            for word in ["password", "admin", "user"]:
                now = datetime.datetime.utcnow()
                forbidden_word = ForbiddenWord(word=word, created_at=now, updated_at=now)
                self.db_session.add(forbidden_word)
            self.db_session.commit()
        except Exception as e:
            self.db_session.rollback()
            print(f"Error setting up forbidden words: {e}")
        
        # Mock DB config for stored procedures
        self.mock_update_login = patch('patched.auth.auth_handler.AuthHandler._update_login_attempts')
        self.mock_update_login_method = self.mock_update_login.start()
        
        # Set up auth handler
        self.auth_handler = AuthHandler(self.db_session)
        
        yield
        
        # Clean up
        self.db_session.close()
        self.mock_update_login.stop()

    def test_registration_success(self):
        """Test successful user registration."""
        # Setup mock
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register user
        success, user, error = self.auth_handler.register_user(
            "testuser",
            "test@example.com",
            "SecureP@ss123",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert success
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        
        # Check password was hashed
        assert user.password_hash != "SecureP@ss123"
        assert "$" in user.password_hash
        
        # Check password history was created
        history = self.db_session.query(PasswordHistory).filter_by(user_id=user.id).all()
        assert len(history) == 1

    def test_registration_password_policy_violation(self):
        """Test registration with password policy violation."""
        # Try to register with weak password
        success, user, error = self.auth_handler.register_user(
            "testuser2",
            "test2@example.com",
            "weak",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert not success
        assert user is None
        assert "policy violation" in error.lower()

    def test_registration_forbidden_word(self):
        """Test registration with forbidden word in password."""
        # Try to register with password containing forbidden word
        success, user, error = self.auth_handler.register_user(
            "testuser3",
            "test3@example.com",
            "MyPassword123!",  # Contains "password"
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert not success
        assert user is None
        assert "forbidden" in error.lower()

    def test_login_success(self):
        """Test successful login."""
        # Setup mock
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        self.auth_handler.register_user(
            "loginuser",
            "login@example.com",
            "SecureL0gin!",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Attempt login
        success, response, error = self.auth_handler.login(
            "loginuser",
            "SecureL0gin!",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert success
        assert response is not None
        assert "jwt_token" in response
        assert "csrf_token" in response

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        # Setup mocks
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        self.auth_handler.register_user(
            "badlogin",
            "badlogin@example.com",
            "SecureL0gin!",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Attempt login with wrong password
        success, response, error = self.auth_handler.login(
            "badlogin",
            "WrongPassword!",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert not success
        assert response is None
        assert "Invalid credentials" in error

    def test_login_account_lockout(self):
        """Test account lockout after failed login attempts."""
        # Setup mocks for registration
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        self.auth_handler.register_user(
            "lockoutuser",
            "lockout@example.com",
            "SecureL0gin!",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Configure login to fail and then lock account
        self.mock_update_login_method.side_effect = [
            {"account_locked": False, "lockout_time": None},  # First failed attempt
            {"account_locked": False, "lockout_time": None},  # Second failed attempt
            {"account_locked": True, "lockout_time": datetime.datetime.now() + datetime.timedelta(minutes=15)}  # Third attempt locks
        ]
        
        # First failed attempt
        success1, _, _ = self.auth_handler.login(
            "lockoutuser",
            "WrongPassword!",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Second failed attempt
        success2, _, _ = self.auth_handler.login(
            "lockoutuser",
            "WrongPassword!",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Third failed attempt should lock the account
        success3, _, error3 = self.auth_handler.login(
            "lockoutuser",
            "WrongPassword!",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert not success1
        assert not success2
        assert not success3
        assert "locked" in error3.lower()

    def test_change_password(self):
        """Test password change functionality."""
        # Setup mock
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        success, user, _ = self.auth_handler.register_user(
            "changeuser",
            "change@example.com",
            "OldP@ssw0rd123",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Change password
        change_success, change_error = self.auth_handler.change_password(
            user.id,
            "OldP@ssw0rd123",
            "NewP@ssw0rd456",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Check results
        assert change_success
        assert change_error is None
        
        # Verify login with new password works
        login_success, _, _ = self.auth_handler.login(
            "changeuser",
            "NewP@ssw0rd456",
            "127.0.0.1",
            "test-req-id"
        )
        
        assert login_success
        
        # Verify login with old password fails
        old_login_success, _, _ = self.auth_handler.login(
            "changeuser",
            "OldP@ssw0rd123",
            "127.0.0.1",
            "test-req-id"
        )
        
        assert not old_login_success

    def test_change_password_history_violation(self):
        """Test password history enforcement."""
        # Setup mock
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        success, user, _ = self.auth_handler.register_user(
            "historyuser",
            "history@example.com",
            "FirstP@ss123",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Change password to a new one
        self.auth_handler.change_password(
            user.id,
            "FirstP@ss123",
            "SecondP@ss456",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Try to change back to the original password
        history_success, history_error = self.auth_handler.change_password(
            user.id,
            "SecondP@ss456",
            "FirstP@ss123",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Should fail due to history policy
        assert not history_success
        assert "previous passwords" in history_error.lower()

    def test_reset_token_lifecycle(self):
        """Test password reset token lifecycle."""
        # Setup mock
        self.mock_update_login_method.return_value = {"account_locked": False, "lockout_time": None}
        
        # Register a user first
        success, user, _ = self.auth_handler.register_user(
            "resetuser",
            "reset@example.com",
            "ResetP@ss123",
            "customer",
            "127.0.0.1",
            "test-req-id"
        )
        
        # Request password reset
        with patch('patched.auth.auth_handler.AuthHandler.forgot_password') as mock_forgot:
            # Configure mock to create a real token but skip email sending
            def side_effect(email, reset_url, ip_address, request_id):
                # Generate token and hash
                token, token_hash = self.auth_handler.token_manager.generate_reset_token()
                
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
                
                # Return the token for testing
                self.test_token = token
                
                return True, None
                
            mock_forgot.side_effect = side_effect
            
            # Request reset
            reset_request_success, _ = self.auth_handler.forgot_password(
                "reset@example.com",
                "http://example.com/reset",
                "127.0.0.1",
                "test-req-id"
            )
            
            assert reset_request_success
            assert hasattr(self, 'test_token')
            
            # Reset password with token
            reset_success, reset_error = self.auth_handler.reset_password(
                self.test_token,
                "NewResetP@ss456",
                "127.0.0.1",
                "test-req-id"
            )
            
            # Check results
            assert reset_success
            assert reset_error is None
            
            # Verify token is consumed (trying to use it again should fail)
            reuse_success, reuse_error = self.auth_handler.reset_password(
                self.test_token,
                "AnotherP@ss789",
                "127.0.0.1",
                "test-req-id"
            )
            
            assert not reuse_success
            assert "Invalid or expired" in reuse_error


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])

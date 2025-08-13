"""
Password policy validation and enforcement.
"""
import re
from typing import List, Dict, Tuple, Any, Optional

class PasswordPolicyValidator:
    """
    Validates passwords against a configurable password policy.
    """
    def __init__(self, config: Dict[str, Any], forbidden_words: List[str] = None):
        """
        Initialize the password policy validator.
        
        Args:
            config: Dictionary containing password policy configuration
            forbidden_words: List of words that cannot be used in passwords
        """
        self.config = config
        self.forbidden_words = forbidden_words or []
        
        # Get policy parameters
        self.min_length = config.get('min_length', 10)
        self.require_uppercase = config.get('require_uppercase', True)
        self.require_lowercase = config.get('require_lowercase', True)
        self.require_digit = config.get('require_digit', True)
        self.require_special = config.get('require_special', True)
        self.history_count = config.get('history_count', 3)
        
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate a password against the policy.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters in length")
        
        # Check character requirements
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
            
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
            
        if self.require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
            
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
        
        # Check for forbidden words
        for word in self.forbidden_words:
            if word.lower() in password.lower():
                errors.append(f"Password cannot contain forbidden word: {word}")
                break
        
        return len(errors) == 0, errors
    
    def check_history(self, password: str, password_history: List[str], hasher) -> Tuple[bool, Optional[str]]:
        """
        Check if the password is in the user's password history.
        
        Args:
            password: New password to check
            password_history: List of password hashes from history
            hasher: Password hasher instance to verify
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Only check recent passwords up to history_count
        recent_history = password_history[-self.history_count:] if password_history else []
        
        for old_hash in recent_history:
            if hasher.verify(password, old_hash):
                return False, "Password cannot be the same as your previous passwords"
                
        return True, None

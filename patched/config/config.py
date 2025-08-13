from sqlalchemy import text
from typing import Optional, Dict, List, Tuple, Any
import os
import json

class DatabaseConfig:
    """
    Load configuration parameters from the database.
    """
    def __init__(self, db_session):
        self.db_session = db_session
        self._password_policy = None
    
    def get_password_policy(self) -> Dict[str, Any]:
        """
        Get the password policy configuration from the database.
        Falls back to default values if not found.
        """
        if self._password_policy is not None:
            return self._password_policy

        # Query for password policy from database using a raw SQL query
        try:
            result = self.db_session.execute(text("SELECT * FROM config WHERE name = 'password_policy'"))
            row = result.fetchone()
            
            if row and row.value:
                self._password_policy = json.loads(row.value)
                return self._password_policy
            else:
                # Default password policy if not found in database
                default_policy = {
                    "min_length": 10,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_digit": True,
                    "require_special": True,
                    "history_count": 3
                }
                
                # Save the default policy to the database
                try:
                    self.db_session.execute(
                        text("INSERT INTO config (name, value) VALUES (:name, :value)"),
                        {"name": "password_policy", "value": json.dumps(default_policy)}
                    )
                    self.db_session.commit()
                except Exception:
                    self.db_session.rollback()
                
                self._password_policy = default_policy
                return default_policy
        
        except Exception as e:
            # If there's an error, return default policy
            default_policy = {
                "min_length": 10,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digit": True,
                "require_special": True,
                "history_count": 3
            }
            self._password_policy = default_policy
            return default_policy

class AppConfig:
    """
    General application configuration.
    """
    @staticmethod
    def get_jwt_secret() -> str:
        """Get the JWT secret from environment variables."""
        jwt_secret = os.environ.get("JWT_SECRET")
        if not jwt_secret:
            raise ValueError("JWT_SECRET environment variable not set")
        return jwt_secret

    @staticmethod
    def get_pepper_secret() -> str:
        """Get the pepper secret from environment variables."""
        pepper_secret = os.environ.get("PEPPER_SECRET")
        if not pepper_secret:
            raise ValueError("PEPPER_SECRET environment variable not set")
        return pepper_secret

    @staticmethod
    def get_smtp_config() -> Dict[str, Any]:
        """Get SMTP configuration for email sending."""
        enabled = os.environ.get("SMTP_ENABLED", "false").lower() == "true"
        
        if not enabled:
            return {"enabled": False}
        
        return {
            "enabled": enabled,
            "host": os.environ.get("SMTP_HOST", "localhost"),
            "port": int(os.environ.get("SMTP_PORT", "25")),
            "username": os.environ.get("SMTP_USERNAME", ""),
            "password": os.environ.get("SMTP_PASSWORD", ""),
            "use_tls": os.environ.get("SMTP_USE_TLS", "false").lower() == "true",
            "from_email": os.environ.get("SMTP_FROM_EMAIL", "noreply@communication-ltd.com"),
            "from_name": os.environ.get("SMTP_FROM_NAME", "Communication LTD Support")
        }

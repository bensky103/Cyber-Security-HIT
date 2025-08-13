"""
Update to database models for secure authentication.
"""

from sqlalchemy import Column, DateTime
from app.models.models import User

# Add lockout_until field to User model if it doesn't exist already
if not hasattr(User, "lockout_until"):
    User.lockout_until = Column(DateTime, nullable=True)

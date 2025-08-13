"""
Thin compatibility wrapper: import create_app from app_fixed.
Prefer importing patched.app_fixed directly in new code.
"""
from .app_fixed import create_app

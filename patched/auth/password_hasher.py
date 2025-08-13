"""
Secure password hashing using PBKDF2-HMAC-SHA256 with per-user salt and server pepper.
"""
import os
import hashlib
import binascii
import base64
import json
from typing import Dict, Any

class PasswordHasher:
    """
    Securely hash passwords using PBKDF2-HMAC-SHA256 with per-user salt and server pepper.
    """
    def __init__(self, pepper: str, iterations: int = 600000):
        """
        Initialize the password hasher.
        
        Args:
            pepper: Server-side secret pepper (from environment)
            iterations: Number of PBKDF2 iterations
        """
        self.pepper = pepper.encode('utf-8')
        self.iterations = iterations
        self.algorithm = 'pbkdf2_sha256'

    def _apply_pepper(self, password: str) -> bytes:
        """
        Apply the pepper to the password.
        
        Args:
            password: Plain text password
            
        Returns:
            Peppered password bytes
        """
        return hashlib.sha256(password.encode('utf-8') + self.pepper).digest()

    def hash(self, password: str) -> str:
        """
        Hash a password with a random salt and server pepper.
        
        Args:
            password: Plain text password
            
        Returns:
            Password hash string in the format: algorithm$iterations$salt$hash
        """
        # Apply pepper
        peppered_password = self._apply_pepper(password)
        
        # Generate a random salt
        salt = os.urandom(32)
        
        # Hash password with salt and pepper
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            peppered_password, 
            salt, 
            self.iterations, 
            dklen=64
        )
        
        # Encode salt and hash to base64 for storage
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        hash_b64 = base64.b64encode(password_hash).decode('utf-8')
        
        # Create hash string with algorithm and parameters
        hash_string = f"{self.algorithm}${self.iterations}${salt_b64}${hash_b64}"
        
        return hash_string

    def verify(self, password: str, stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Stored password hash string
            
        Returns:
            True if the password matches the hash, False otherwise
        """
        # Parse the stored hash
        try:
            algorithm, iterations, salt_b64, hash_b64 = stored_hash.split('$')
            
            # Ensure algorithm matches
            if algorithm != self.algorithm:
                return False
            
            # Convert parameters
            iterations = int(iterations)
            salt = base64.b64decode(salt_b64)
            stored_password_hash = base64.b64decode(hash_b64)
            
            # Apply pepper to input password
            peppered_password = self._apply_pepper(password)
            
            # Hash the input password with the same parameters
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                peppered_password, 
                salt, 
                iterations, 
                dklen=64
            )
            
            # Compare the generated hash to the stored hash
            return password_hash == stored_password_hash
            
        except Exception:
            # If any error occurs during verification, fail securely
            return False
    
    def get_hash_info(self, stored_hash: str) -> Dict[str, Any]:
        """
        Get information about a stored hash.
        
        Args:
            stored_hash: Stored password hash string
            
        Returns:
            Dictionary with hash information
        """
        try:
            algorithm, iterations, salt_b64, _ = stored_hash.split('$')
            return {
                'algorithm': algorithm,
                'iterations': int(iterations),
                'salt_length': len(base64.b64decode(salt_b64))
            }
        except Exception:
            return {}

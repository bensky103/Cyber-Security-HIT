"""
Rate Limiter for API protection.
"""
from functools import wraps
import time
from collections import defaultdict
from datetime import datetime

# Import conditionally to handle the case when flask is not installed
try:
    from flask import request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create minimal mocks for testing
    class MockRequest:
        method = "GET"
        headers = {}
        remote_addr = "127.0.0.1"
        
    request = MockRequest()
    
    def jsonify(data):
        return data

from ..logging.logger import security_logger

class RateLimiter:
    """
    A simple in-memory rate limiter for API endpoints.
    
    For a production environment, a distributed rate limiter 
    (e.g., using Redis) would be more appropriate.
    """
    def __init__(self, limit=5, period=10):
        """
        Initialize the rate limiter.
        
        Args:
            limit (int): Maximum number of requests allowed
            period (int): Time period in seconds
        """
        self.limit = limit
        self.period = period
        self.requests = defaultdict(list)
        
    def is_rate_limited(self, key):
        """
        Check if a key is rate limited.
        
        Args:
            key (str): The key to check (usually IP address)
            
        Returns:
            tuple: (is_limited, current_count, reset_time)
        """
        now = time.time()
        
        # Remove expired timestamps
        self.requests[key] = [ts for ts in self.requests[key] if ts > now - self.period]
        
        # Check if the key has reached its limit
        count = len(self.requests[key])
        is_limited = count >= self.limit
        
        # Calculate when the rate limit will reset
        if self.requests[key]:
            oldest = min(self.requests[key])
            reset_time = oldest + self.period
        else:
            reset_time = now + self.period
        
        # Always record this request if not limited
        if not is_limited:
            self.requests[key].append(now)
        
        return is_limited, count, reset_time
        
    def get_headers(self, key):
        """
        Generate rate limit headers.
        
        Args:
            key (str): The key to get headers for
            
        Returns:
            dict: Rate limit headers
        """
        _, count, reset_time = self.is_rate_limited(key)
        reset_time_str = datetime.fromtimestamp(reset_time).strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        return {
            'X-RateLimit-Limit': str(self.limit),
            'X-RateLimit-Remaining': str(max(0, self.limit - count)),
            'X-RateLimit-Reset': reset_time_str
        }


# Create a singleton instance for auth routes
auth_rate_limiter = RateLimiter(limit=5, period=10)  # 5 requests per 10 seconds

def rate_limit(limiter=auth_rate_limiter):
    """
    Decorator to apply rate limiting to API endpoints.
    
    Args:
        limiter (RateLimiter): Rate limiter instance to use
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get client IP
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip_address and ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
            
            # Get request info for logging
            request_id = request.headers.get('X-Request-ID', 'no-request-id')
            
            # Check if the client is rate limited
            is_limited, count, reset_time = limiter.is_rate_limited(ip_address)
            
            if count >= limiter.limit - 1 and not is_limited:
                # Log warning when approaching the limit
                security_logger.warning(
                    f"Rate limit threshold approached: {count}/{limiter.limit} requests",
                    ip=ip_address,
                    user='anonymous',
                    request_id=request_id
                )
            
            if is_limited:
                # Log error when rate limited
                security_logger.error(
                    f"Rate limit exceeded: {count}/{limiter.limit} requests",
                    ip=ip_address,
                    user='anonymous',
                    request_id=request_id
                )
                
                # Return rate limit error
                response = jsonify({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests, please try again later."
                })
                
                # Add rate limit headers
                headers = limiter.get_headers(ip_address)
                for header, value in headers.items():
                    response.headers[header] = value
                
                # Add Retry-After header
                retry_after = int(reset_time - time.time())
                response.headers['Retry-After'] = str(max(0, retry_after))
                
                return response, 429
            
            # Execute the endpoint function
            response = f(*args, **kwargs)
            
            # If it's a response object with headers
            if hasattr(response, 'headers'):
                # Add rate limit headers
                headers = limiter.get_headers(ip_address)
                for header, value in headers.items():
                    response.headers[header] = value
            
            return response
        return decorated
    return decorator

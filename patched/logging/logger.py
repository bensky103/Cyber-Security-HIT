import logging
import os
import sys
from datetime import datetime

class SecurityLogger:
    """
    A logger specifically designed for security-related events.
    """

    def __init__(self, name="security_logger", log_file=None):
        self.logger = logging.getLogger(name)
        # Allow overriding log level via env var SECURITY_LOG_LEVEL
        level_name = os.environ.get('SECURITY_LOG_LEVEL', 'INFO').upper()
        self.logger.setLevel(getattr(logging, level_name, logging.INFO))

        # Create formatter
        formatter = logging.Formatter(
            '[%(levelname)s] %(asctime)s - %(message)s - IP: %(ip)s - User: %(user)s - RequestId: %(request_id)s',
            datefmt='%Y-%m-%dT%H:%M:%SZ'
        )

        # Avoid adding duplicate handlers if logger is re-initialized
        if not self.logger.handlers:
            # Add console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Add file handler if log_file is provided or use default
        if log_file is None:
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f"security_{datetime.now().strftime('%Y%m%d')}.log")
        
        # Add file handler only once
        if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == log_file for h in self.logger.handlers):
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def _log(self, level, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log a message with the given level and context information.
        """
        extra = {
            'ip': ip,
            'user': user,
            'request_id': request_id
        }
        if level == logging.INFO:
            self.logger.info(msg, extra=extra, **kwargs)
        elif level == logging.WARNING:
            self.logger.warning(msg, extra=extra, **kwargs)
        elif level == logging.ERROR:
            self.logger.error(msg, extra=extra, **kwargs)
        elif level == logging.DEBUG:
            self.logger.debug(msg, extra=extra, **kwargs)
        elif level == logging.CRITICAL:
            self.logger.critical(msg, extra=extra, **kwargs)
    
    def info(self, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log an INFO level message.
        """
        self._log(logging.INFO, msg, ip, user, request_id, **kwargs)
    
    def warning(self, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log a WARNING level message.
        """
        self._log(logging.WARNING, msg, ip, user, request_id, **kwargs)
    
    def error(self, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log an ERROR level message.
        """
        self._log(logging.ERROR, msg, ip, user, request_id, **kwargs)
    
    def debug(self, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log a DEBUG level message.
        """
        self._log(logging.DEBUG, msg, ip, user, request_id, **kwargs)
    
    def critical(self, msg, ip="unknown", user="anonymous", request_id="no-request-id", **kwargs):
        """
        Log a CRITICAL level message.
        """
        self._log(logging.CRITICAL, msg, ip, user, request_id, **kwargs)

# Create a singleton instance
security_logger = SecurityLogger()

# Backward-compatible setup function used by some modules
def setup_logger():
    """
    Compatibility shim: returns the configured security_logger.
    Instantiating SecurityLogger above already set handlers and levels.
    """
    return security_logger

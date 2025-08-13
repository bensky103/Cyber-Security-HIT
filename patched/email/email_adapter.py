"""
Email adapter for sending password reset emails and other notifications.
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional

class EmailAdapter:
    """
    Adapter for sending emails. In development, logs to console by default.
    In production, sends emails via SMTP if configured.
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize email adapter with configuration.
        
        Args:
            config: Email configuration dictionary with SMTP settings
        """
        self.config = config
        self.enabled = config.get("enabled", False)
        self.logger = logging.getLogger("email_adapter")

    def send_email(self, to_email: str, subject: str, text_content: str, html_content: Optional[str] = None) -> bool:
        """
        Send an email or log it if SMTP is not enabled.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            text_content: Plain text email content
            html_content: HTML email content (optional)
            
        Returns:
            True if successful, False otherwise
        """
        # If SMTP is not enabled, log the email
        if not self.enabled:
            self._log_email(to_email, subject, text_content)
            return True
            
        # Otherwise, send via SMTP
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.config.get('from_name')} <{self.config.get('from_email')}>"
            msg["To"] = to_email
            
            # Add text part
            text_part = MIMEText(text_content, "plain")
            msg.attach(text_part)
            
            # Add HTML part if provided
            if html_content:
                html_part = MIMEText(html_content, "html")
                msg.attach(html_part)
                
            # Connect to SMTP server
            if self.config.get("use_tls", False):
                smtp = smtplib.SMTP(self.config.get("host"), self.config.get("port"))
                smtp.starttls()
            else:
                smtp = smtplib.SMTP(self.config.get("host"), self.config.get("port"))
                
            # Login if credentials provided
            if self.config.get("username") and self.config.get("password"):
                smtp.login(self.config.get("username"), self.config.get("password"))
                
            # Send email
            smtp.sendmail(
                self.config.get("from_email"),
                to_email,
                msg.as_string()
            )
            
            # Close connection
            smtp.quit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {str(e)}")
            # Fall back to logging
            self._log_email(to_email, subject, text_content)
            return False
            
    def _log_email(self, to_email: str, subject: str, content: str) -> None:
        """
        Log an email instead of sending it (for development).
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            content: Email content
        """
        self.logger.info(f"\n{'='*60}\nEMAIL NOTIFICATION\n{'='*60}")
        self.logger.info(f"To: {to_email}")
        self.logger.info(f"Subject: {subject}")
        self.logger.info(f"Content:\n{content}")
        self.logger.info(f"{'='*60}\n")
        
    def send_password_reset_email(self, to_email: str, username: str, reset_token: str, reset_url: str) -> bool:
        """
        Send a password reset email to a user.
        
        Args:
            to_email: User's email address
            username: User's username
            reset_token: Password reset token
            reset_url: Base URL for password reset
            
        Returns:
            True if successful, False otherwise
        """
        subject = "Password Reset Request - Communication LTD"
        
        # Construct the reset URL with token
        complete_reset_url = f"{reset_url}?token={reset_token}"
        
        text_content = f"""
Hello {username},

We received a request to reset your password for your Communication LTD account.

To reset your password, please click on the following link or paste it into your browser:

{complete_reset_url}

This link will expire in 15 minutes.

If you did not request a password reset, please ignore this email or contact our support team if you have concerns.

Best regards,
Communication LTD Support Team
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f7f7f7; padding: 20px; border-radius: 5px;">
        <h2 style="color: #0056b3;">Password Reset Request</h2>
        <p>Hello {username},</p>
        <p>We received a request to reset your password for your Communication LTD account.</p>
        <p>To reset your password, please click on the button below:</p>
        <p style="text-align: center;">
            <a href="{complete_reset_url}" style="background-color: #0056b3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </p>
        <p>Or copy and paste this URL into your browser:</p>
        <p style="background-color: #e9e9e9; padding: 10px; border-radius: 3px; word-break: break-all;">
            {complete_reset_url}
        </p>
        <p><strong>This link will expire in 15 minutes.</strong></p>
        <p>If you did not request a password reset, please ignore this email or contact our support team if you have concerns.</p>
        <p>Best regards,<br>Communication LTD Support Team</p>
    </div>
</body>
</html>
"""
        
        return self.send_email(to_email, subject, text_content, html_content)

"""
Audit logging manager for entity operations.
"""
from datetime import datetime
from ..logging.logger import security_logger
from app.models.models import AuditLog

class AuditManager:
    """
    Manager class for handling audit logging for entity operations.
    """
    
    def __init__(self, db_session):
        """
        Initialize the AuditManager with a database session.
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db_session = db_session
    
    def log_action(self, user_id, action, entity_type, entity_id, details, ip_address, user_agent=None, request_id=None):
        """
        Log an action to both the audit log table and security logger.
        
        Args:
            user_id: ID of the user performing the action (can be None for anonymous)
            action: Description of the action (e.g., "create", "update", "fetch")
            entity_type: Type of entity being acted upon (e.g., "customer", "ticket")
            entity_id: ID of the entity (can be None for operations not tied to a specific entity)
            details: Dictionary of additional details about the action
            ip_address: IP address of the client
            user_agent: User agent of the client (optional)
            request_id: Request ID for tracking (optional)
            
        Returns:
            The created AuditLog object
        """
        try:
            # Create audit log entry in database
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=datetime.utcnow()
            )
            
            self.db_session.add(audit_log)
            self.db_session.commit()
            
            # Log to security logger as well
            username = "anonymous" if user_id is None else str(user_id)
            message = f"{action.capitalize()} {entity_type} {entity_id if entity_id else ''}"
            security_logger.info(
                message,
                ip=ip_address,
                user=username,
                request_id=request_id if request_id else "no-request-id"
            )
            
            return audit_log
            
        except Exception as e:
            self.db_session.rollback()
            # Log error to security logger
            security_logger.error(
                f"Failed to create audit log for {action} {entity_type}: {str(e)}",
                ip=ip_address,
                user="anonymous" if user_id is None else str(user_id),
                request_id=request_id if request_id else "no-request-id"
            )
            return None

# Factory function to create AuditManager
def create_audit_manager(db_session):
    """
    Create an AuditManager instance with the provided database session.
    
    Args:
        db_session: SQLAlchemy database session
        
    Returns:
        AuditManager instance
    """
    return AuditManager(db_session)

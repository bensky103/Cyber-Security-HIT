"""
Ticket routes for VULNERABLE CRUD operations.
IMPORTANT: This file intentionally contains security vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION.
"""
from flask import Blueprint, request, jsonify, g
from flask import current_app as app
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError

from app.models.models import Ticket, TicketComment, Customer
from patched.auth.auth_handler import AuthHandler
from patched.logging.logger import security_logger
from patched.utils.audit_manager import create_audit_manager
from patched.utils.db_utils import DatabaseUtils

vuln_tickets_bp = Blueprint('vuln_tickets', __name__, url_prefix='/tickets')

# Authentication decorator
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            security_logger.warning(
                "Missing or invalid Authorization header",
                ip=request.remote_addr,
                request_id=request.headers.get('X-Request-ID', 'no-request-id')
            )
            return jsonify({"error": "Authentication required"}), 401
            
        token = auth_header.split(' ')[1]
        auth_handler = AuthHandler(g.db)
        user = auth_handler.token_manager.validate_token(token)
        
        if not user:
            security_logger.warning(
                "Invalid token",
                ip=request.remote_addr,
                request_id=request.headers.get('X-Request-ID', 'no-request-id')
            )
            return jsonify({"error": "Invalid token"}), 401
            
        g.user = user
        return f(*args, **kwargs)
    return decorated

@vuln_tickets_bp.route('', methods=['POST'])
@auth_required
def create_ticket():
    """Create a new ticket."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        data = request.get_json()
        
        if not data:
            security_logger.warning(
                "Invalid request data for ticket creation",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Invalid request data"}), 400
            
        required_fields = ['customer_id', 'subject', 'description', 'priority', 'category']
        for field in required_fields:
            if field not in data:
                security_logger.warning(
                    f"Missing required field: {field}",
                    ip=request.remote_addr,
                    user=user.username,
                    request_id=request_id
                )
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Verify customer exists
        customer = g.db.query(Customer).filter(Customer.id == data['customer_id']).first()
        if not customer:
            security_logger.warning(
                f"Customer not found: {data['customer_id']}",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Customer not found"}), 404
            
        # Create ticket using stored procedure
        ticket_id = DatabaseUtils.create_ticket_procedure(
            g.db,
            customer_id=data['customer_id'],
            subject=data['subject'],
            description=data['description'],
            priority=data['priority'],
            category=data['category'],
            assigned_to=data.get('assigned_to')
        )
        
        # Log successful creation
        audit_manager.log_action(
            user_id=user.id,
            action="create",
            entity_type="ticket",
            entity_id=ticket_id,
            details={"customer_id": data['customer_id'], "subject": data['subject']},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        security_logger.info(
            f"VULN MODE: Ticket created: {ticket_id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "message": "Ticket created successfully",
            "ticket_id": ticket_id
        }), 201
        
    except SQLAlchemyError as e:
        security_logger.error(
            f"VULN MODE: Database error creating ticket: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Database error creating ticket"}), 500
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error creating ticket: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Error creating ticket"}), 500

@vuln_tickets_bp.route('', methods=['GET'])
@auth_required
def get_tickets():
    """Get list of tickets."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)  # Limit to 100 per page
        offset = (page - 1) * per_page
        
        # Get tickets
        tickets = g.db.query(Ticket).limit(per_page).offset(offset).all()
        
        # Log fetch action
        audit_manager.log_action(
            user_id=user.id,
            action="fetch",
            entity_type="tickets",
            entity_id=None,
            details={"page": page, "per_page": per_page},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        # Format response
        result = []
        for ticket in tickets:
            result.append({
                "id": ticket.id,
                "customer_id": ticket.customer_id,
                "assigned_to": ticket.assigned_to,
                "subject": ticket.subject,
                "status": ticket.status,
                "priority": ticket.priority,
                "category": ticket.category,
                "created_at": ticket.created_at.isoformat(),
                "updated_at": ticket.updated_at.isoformat()
            })
            
        security_logger.info(
            f"VULN MODE: Fetched tickets list: page {page}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "tickets": result,
            "page": page,
            "per_page": per_page,
            "total": g.db.query(Ticket).count()
        }), 200
        
    except ValueError as e:
        security_logger.warning(
            f"VULN MODE: Invalid pagination parameters: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Invalid pagination parameters"}), 400
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error fetching tickets: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Error fetching tickets"}), 500

@vuln_tickets_bp.route('/<int:ticket_id>', methods=['GET'])
@auth_required
def get_ticket(ticket_id):
    """Get a specific ticket."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        # Get ticket
        ticket = g.db.query(Ticket).filter(Ticket.id == ticket_id).first()
        
        if not ticket:
            security_logger.warning(
                f"VULN MODE: Ticket not found: {ticket_id}",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Ticket not found"}), 404
            
        # Log fetch action
        audit_manager.log_action(
            user_id=user.id,
            action="fetch",
            entity_type="ticket",
            entity_id=ticket.id,
            details={"ticket_id": ticket_id},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        # Format response
        result = {
            "id": ticket.id,
            "customer_id": ticket.customer_id,
            "assigned_to": ticket.assigned_to,
            "subject": ticket.subject,
            "description": ticket.description,
            "status": ticket.status,
            "priority": ticket.priority,
            "category": ticket.category,
            "created_at": ticket.created_at.isoformat(),
            "updated_at": ticket.updated_at.isoformat(),
            "closed_at": ticket.closed_at.isoformat() if ticket.closed_at else None
        }
        
        security_logger.info(
            f"VULN MODE: Fetched ticket: {ticket_id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error fetching ticket {ticket_id}: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": f"Error fetching ticket: {str(e)}"}), 500

@vuln_tickets_bp.route('/<int:ticket_id>/comments', methods=['POST'])
@auth_required
def add_comment(ticket_id):
    """
    VULNERABLE ENDPOINT: Add a comment to a ticket WITHOUT HTML sanitization.
    This endpoint intentionally allows stored XSS attacks.
    """
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            security_logger.warning(
                "VULN MODE: Invalid request data for comment creation",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Invalid request data"}), 400
            
        # Verify ticket exists
        ticket = g.db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            security_logger.warning(
                f"VULN MODE: Ticket not found: {ticket_id}",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Ticket not found"}), 404
            
        # VULNERABLE: Store raw HTML content WITHOUT sanitization
        raw_content = data['content']
        
        # Look for potential XSS patterns
        xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "onclick="]
        
        has_xss_pattern = any(pattern.lower() in raw_content.lower() for pattern in xss_patterns)
        
        if has_xss_pattern:
            security_logger.warning(
                f"VULN MODE: Potential XSS pattern detected in comment",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            # Still process the comment in vulnerable mode
        
        security_logger.info(
            "VULN MODE: Storing raw HTML content without sanitization",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        # Create comment with raw content
        comment = TicketComment(
            ticket_id=ticket_id,
            user_id=user.id,
            content=raw_content  # No sanitization - vulnerable to stored XSS
        )
        
        g.db.add(comment)
        g.db.commit()
        comment_id = comment.id
        
        # Log successful creation
        audit_manager.log_action(
            user_id=user.id,
            action="create",
            entity_type="comment",
            entity_id=comment_id,
            details={"ticket_id": ticket_id},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        security_logger.info(
            f"VULN MODE: Comment added to ticket {ticket_id}: {comment_id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "message": "Comment added successfully",
            "comment_id": comment_id,
            "content": raw_content  # Return raw content - XSS vulnerability
        }), 201
        
    except SQLAlchemyError as e:
        security_logger.error(
            f"VULN MODE: Database error creating comment: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Database error creating comment"}), 500
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error creating comment: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Error creating comment"}), 500

@vuln_tickets_bp.route('/<int:ticket_id>/comments', methods=['GET'])
@auth_required
def get_comments(ticket_id):
    """Get comments for a specific ticket."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    
    try:
        # Verify ticket exists
        ticket = g.db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            security_logger.warning(
                f"VULN MODE: Ticket not found: {ticket_id}",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Ticket not found"}), 404
        
        # Get comments
        comments = g.db.query(TicketComment).filter(TicketComment.ticket_id == ticket_id).order_by(TicketComment.created_at).all()
        
        # Format response
        result = []
        for comment in comments:
            result.append({
                "id": comment.id,
                "user_id": comment.user_id,
                "content": comment.content,  # Potentially dangerous content is returned as is
                "created_at": comment.created_at.isoformat(),
                "updated_at": comment.updated_at.isoformat() if comment.updated_at else None
            })
        
        security_logger.info(
            f"VULN MODE: Fetched comments for ticket: {ticket_id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "ticket_id": ticket_id,
            "comments": result
        }), 200
        
    except Exception as e:
        security_logger.error(
            f"VULN MODE: Error fetching comments for ticket {ticket_id}: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": f"Error fetching comments: {str(e)}"}), 500

"""
Customer routes for secure CRUD operations.
"""
from flask import Blueprint, request, jsonify, g
from sqlalchemy.exc import SQLAlchemyError

from app.models.models import Customer, User
from ..logging.logger import security_logger
from ..utils.audit_manager import create_audit_manager
from ..auth.csrf import csrf_protect
from ..auth.decorators import auth_required

customers_bp = Blueprint('customers', __name__, url_prefix='/customers')

@customers_bp.route('', methods=['POST'])
@auth_required
@csrf_protect
def create_customer():
    """Create a new customer."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        data = request.get_json()
        
        if not data:
            security_logger.warning(
                "Invalid request data for customer creation",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Invalid request data"}), 400
            
        required_fields = ['first_name', 'last_name', 'phone_number']
        for field in required_fields:
            if field not in data:
                security_logger.warning(
                    f"Missing required field: {field}",
                    ip=request.remote_addr,
                    user=user.username,
                    request_id=request_id
                )
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Create new customer
        customer = Customer(
            user_id=user.id,
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone_number=data['phone_number'],
            address=data.get('address'),
            city=data.get('city'),
            postal_code=data.get('postal_code'),
            country=data.get('country')
        )
        
        g.db.add(customer)
        g.db.commit()
        
        # Log successful creation
        audit_manager.log_action(
            user_id=user.id,
            action="create",
            entity_type="customer",
            entity_id=customer.id,
            details={"first_name": data['first_name'], "last_name": data['last_name']},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        security_logger.info(
            f"Customer created: {customer.id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "message": "Customer created successfully",
            "customer_id": customer.id
        }), 201
        
    except SQLAlchemyError as e:
        g.db.rollback()
        security_logger.error(
            f"Database error creating customer: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Database error creating customer"}), 500
    except Exception as e:
        g.db.rollback()
        security_logger.error(
            f"Error creating customer: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Error creating customer"}), 500

@customers_bp.route('', methods=['GET'])
@auth_required
def get_customers():
    """Get list of customers."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)  # Limit to 100 per page
        offset = (page - 1) * per_page
        
        # Get customers
        customers = g.db.query(Customer).limit(per_page).offset(offset).all()
        
        # Log fetch action
        audit_manager.log_action(
            user_id=user.id,
            action="fetch",
            entity_type="customers",
            entity_id=None,
            details={"page": page, "per_page": per_page},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        # Format response
        result = []
        for customer in customers:
            result.append({
                "id": customer.id,
                "first_name": customer.first_name,
                "last_name": customer.last_name,
                "phone_number": customer.phone_number,
                "created_at": customer.created_at.isoformat(),
                "updated_at": customer.updated_at.isoformat()
            })
            
        security_logger.info(
            f"Fetched customers list: page {page}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify({
            "customers": result,
            "page": page,
            "per_page": per_page,
            "total": g.db.query(Customer).count()
        }), 200
        
    except ValueError as e:
        security_logger.warning(
            f"Invalid pagination parameters: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Invalid pagination parameters"}), 400
    except Exception as e:
        security_logger.error(
            f"Error fetching customers: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": "Error fetching customers"}), 500

@customers_bp.route('/<int:customer_id>', methods=['GET'])
@auth_required
def get_customer(customer_id):
    """Get a specific customer."""
    user = g.user
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)
    
    try:
        # Get customer
        customer = g.db.query(Customer).filter(Customer.id == customer_id).first()
        
        if not customer:
            security_logger.warning(
                f"Customer not found: {customer_id}",
                ip=request.remote_addr,
                user=user.username,
                request_id=request_id
            )
            return jsonify({"error": "Customer not found"}), 404
            
        # Log fetch action
        audit_manager.log_action(
            user_id=user.id,
            action="fetch",
            entity_type="customer",
            entity_id=customer.id,
            details={"customer_id": customer_id},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )
        
        # Format response
        result = {
            "id": customer.id,
            "first_name": customer.first_name,
            "last_name": customer.last_name,
            "phone_number": customer.phone_number,
            "address": customer.address,
            "city": customer.city,
            "postal_code": customer.postal_code,
            "country": customer.country,
            "created_at": customer.created_at.isoformat(),
            "updated_at": customer.updated_at.isoformat()
        }
        
        security_logger.info(
            f"Fetched customer: {customer_id}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        security_logger.error(
            f"Error fetching customer: {customer_id}: {str(e)}",
            ip=request.remote_addr,
            user=user.username,
            request_id=request_id
        )
        return jsonify({"error": f"Error fetching customer: {str(e)}"}), 500

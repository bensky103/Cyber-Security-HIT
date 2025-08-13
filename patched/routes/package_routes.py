"""
Package routes for public read operations.
"""
from flask import Blueprint, request, jsonify, g

from app.models.models import Package
from ..logging.logger import security_logger
from ..utils.audit_manager import create_audit_manager


packages_bp = Blueprint('packages', __name__, url_prefix='/packages')


@packages_bp.route('', methods=['GET'])
def get_packages():
    """Get list of packages (public endpoint)."""
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)

    try:
        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)  # Limit to 100 per page
        offset = (page - 1) * per_page

        # Get packages
        packages = g.db.query(Package).limit(per_page).offset(offset).all()

        # Log fetch action
        audit_manager.log_action(
            user_id=None,  # No user authentication required
            action="fetch",
            entity_type="packages",
            entity_id=None,
            details={"page": page, "per_page": per_page},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )

        # Format response
        result = []
        for package in packages:
            result.append({
                "id": package.id,
                "name": package.name,
                "description": package.description,
                "price": package.price,
                "features": package.features,
                "created_at": package.created_at.isoformat()
            })

        security_logger.info(
            f"Fetched packages list: page {page}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request_id
        )

        return jsonify({
            "packages": result,
            "page": page,
            "per_page": per_page,
            "total": g.db.query(Package).count()
        }), 200

    except ValueError as e:
        security_logger.warning(
            f"Invalid pagination parameters: {str(e)}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request_id
        )
        return jsonify({"error": "Invalid pagination parameters"}), 400
    except Exception as e:
        security_logger.error(
            f"Error fetching packages: {str(e)}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request_id
        )
        return jsonify({"error": "Error fetching packages"}), 500


@packages_bp.route('/<int:package_id>', methods=['GET'])
def get_package(package_id):
    """Get a specific package (public endpoint)."""
    request_id = request.headers.get('X-Request-ID', 'no-request-id')
    audit_manager = create_audit_manager(g.db)

    try:
        # Get package
        package = g.db.query(Package).filter(Package.id == package_id).first()

        if not package:
            security_logger.warning(
                f"Package not found: {package_id}",
                ip=request.remote_addr,
                user="anonymous",
                request_id=request_id
            )
            return jsonify({"error": "Package not found"}), 404

        # Log fetch action
        audit_manager.log_action(
            user_id=None,  # No user authentication required
            action="fetch",
            entity_type="package",
            entity_id=package.id,
            details={"package_id": package_id},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            request_id=request_id
        )

        # Format response
        result = {
            "id": package.id,
            "name": package.name,
            "description": package.description,
            "price": package.price,
            "features": package.features,
            "created_at": package.created_at.isoformat(),
            "updated_at": package.updated_at.isoformat()
        }

        security_logger.info(
            f"Fetched package: {package_id}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request_id
        )

        return jsonify(result), 200

    except Exception as e:
        security_logger.error(
            f"Error fetching package {package_id}: {str(e)}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request_id
        )
        return jsonify({"error": f"Error fetching package: {str(e)}"}), 500

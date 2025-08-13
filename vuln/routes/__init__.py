"""
Routes for the vulnerable version of the API.
This file imports and reuses the secure routes where no vulnerabilities are needed.
"""
from flask import Blueprint

# Import the vulnerable endpoints
from .ticket_routes import vuln_tickets_bp

# Import the secure endpoints to reuse them
from patched.routes.customer_routes import customers_bp
from patched.routes.package_routes import packages_bp

# Create the main blueprint
vuln_api_bp = Blueprint('vuln_api', __name__, url_prefix='/vuln')

# Register the vulnerable ticket routes
vuln_api_bp.register_blueprint(vuln_tickets_bp)

# Register the secure routes for other endpoints
vuln_api_bp.register_blueprint(customers_bp)
vuln_api_bp.register_blueprint(packages_bp)

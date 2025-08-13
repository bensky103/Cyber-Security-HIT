"""
Main application file for the vulnerable version of the API.
IMPORTANT: This application intentionally contains security vulnerabilities for demonstration purposes.
DO NOT USE THIS CODE IN PRODUCTION.
"""
from flask import Flask, g, request, jsonify, redirect, Response, send_file
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import os
import secrets

from app.models.models import Base
from patched.logging.logger import setup_logger, security_logger

# Import blueprints
from vuln.routes import vuln_api_bp
from vuln.auth.routes import auth_bp

def create_app():
    """Create and configure the Flask application."""
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    jwt_secret = os.environ.get('JWT_SECRET', secrets.token_hex(32))
    
    # Set up logging
    setup_logger()
    
    # Set up database connection
    engine = create_engine(database_url, pool_pre_ping=True)
    Session = scoped_session(sessionmaker(bind=engine))
    
    # Create tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Register before_request handler
    @app.before_request
    def before_request():
        g.db = Session()
        
        # Log when vulnerable endpoints are hit
        if request.path.startswith('/vuln'):
            security_logger.info(
                f"VULN MODE: Request to vulnerable endpoint: {request.path} [{request.method}]",
                ip=request.remote_addr,
                user="anonymous",
                request_id=request.headers.get('X-Request-ID', 'no-request-id')
            )
    
    # Register teardown handler
    @app.teardown_request
    def teardown_request(exception=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()
            
    # Register error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404
        
    @app.errorhandler(500)
    def internal_error(error):
        security_logger.error(
            f"VULN MODE: Internal server error: {str(error)}",
            ip=request.remote_addr,
            user="anonymous",
            request_id=request.headers.get('X-Request-ID', 'no-request-id')
        )
        return jsonify({"error": "Internal server error"}), 500
    
    # Register blueprints under both normal and cosmetic /vuln prefixes
    app.register_blueprint(vuln_api_bp)  # includes /tickets, /customers, /packages under /vuln
    app.register_blueprint(auth_bp, url_prefix='/vuln/auth')

    # Cosmetic non-prefixed aliases for vulnerable routes (so app works with or without /vuln)
    # Re-register core blueprints without the /vuln umbrella for convenience
    # Use redirects (307) to preserve method/body
    @app.route('/auth', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_auth_root():
        return redirect('/vuln/auth', code=307)

    @app.route('/auth/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_auth(subpath):
        return redirect(f'/vuln/auth/{subpath}', code=307)

    @app.route('/tickets', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_tickets_root():
        return redirect('/vuln/tickets', code=307)

    @app.route('/tickets/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_tickets(subpath):
        return redirect(f'/vuln/tickets/{subpath}', code=307)

    @app.route('/customers', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_customers_root():
        return redirect('/vuln/customers', code=307)

    @app.route('/customers/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_customers(subpath):
        return redirect(f'/vuln/customers/{subpath}', code=307)

    @app.route('/packages', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_packages_root():
        return redirect('/vuln/packages', code=307)

    @app.route('/packages/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_packages(subpath):
        return redirect(f'/vuln/packages/{subpath}', code=307)
    
    # Add a root route
    @app.route('/')
    def root():
        return jsonify({
            "message": "Vulnerable API - For demonstration purposes only",
            "version": "1.0.0",
            "warning": "This API intentionally contains security vulnerabilities. DO NOT USE IN PRODUCTION."
        })

    # Cosmetic alias root
    @app.route('/vuln')
    def root_alias():
        return jsonify({
            "message": "Vulnerable API (alias)",
            "version": "1.0.0",
            "alias": "/vuln"
        })
    
    # Optional CORS for local dev when frontend runs on a different origin
    origin = os.environ.get('CORS_ORIGIN')
    if origin:
        try:
            from flask_cors import CORS
            CORS(app, resources={r"/*": {"origins": origin}}, supports_credentials=True)
        except Exception:
            pass

    # Serve OpenAPI spec and Swagger UI without extra dependencies
    @app.route('/openapi.yaml', methods=['GET'])
    def openapi_spec():
        root_dir = os.path.dirname(os.path.dirname(__file__))
        spec_path = os.path.join(root_dir, 'api-contract', 'openapi.yaml')
        try:
            return send_file(spec_path, mimetype='application/yaml')
        except Exception:
            return Response('Spec not found', status=404)

    @app.route('/docs', methods=['GET'])
    def swagger_ui():
        html = (
            "<!doctype html><html><head><title>API Docs</title>"
            '<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">'
            "</head><body><div id=\"swagger-ui\"></div>"
            '<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>'
            "<script>window.onload=()=>{SwaggerUIBundle({url:'/openapi.yaml',dom_id:'#swagger-ui',presets:[SwaggerUIBundle.presets.apis],layout:'BaseLayout'});};</script>"
            "</body></html>"
        )
        return Response(html, mimetype='text/html')

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)

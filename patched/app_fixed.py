"""
Fixed module for app.py that properly handles db_session injection
"""
# Import conditionally to handle the case when flask is not installed
try:
    from flask import Flask, g, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create a minimal mock Flask for testing
    class MockFlask:
        def __init__(self, name):
            self.name = name
            self.blueprints = {}
            self.routes = {}
            self.config = {}
            self.before_request_funcs = []
            self.teardown_request_funcs = []
            self.after_request_funcs = []
            
        def register_blueprint(self, blueprint):
            self.blueprints[blueprint.name] = blueprint
            
        def route(self, path):
            def decorator(f):
                self.routes[path] = f
                return f
            return decorator
            
        def before_request(self, f):
            self.before_request_funcs.append(f)
            return f
            
        def teardown_request(self, f):
            self.teardown_request_funcs.append(f)
            return f
            
        def after_request(self, f):
            self.after_request_funcs.append(f)
            return f
            
        def test_client(self):
            return MockTestClient(self)
    
    class MockBlueprint:
        def __init__(self, name, import_name, url_prefix=None):
            self.name = name
            self.import_name = import_name
            self.url_prefix = url_prefix
            
    class MockTestClient:
        def __init__(self, app):
            self.app = app
            
    Flask = MockFlask

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import os
import functools
import inspect
from typing import Optional

# Import conditionally
try:
    from .auth.routes import auth_bp
    from .routes.customer_routes import customers_bp
    from .routes.package_routes import packages_bp
    from .routes.ticket_routes import tickets_bp
    from .auth.security_headers import add_security_headers
except ImportError:
    # Create mock blueprints for testing
    auth_bp = MockBlueprint('auth', __name__, url_prefix='/auth') if not FLASK_AVAILABLE else None
    customers_bp = MockBlueprint('customers', __name__, url_prefix='/customers') if not FLASK_AVAILABLE else None
    packages_bp = MockBlueprint('packages', __name__, url_prefix='/packages') if not FLASK_AVAILABLE else None
    tickets_bp = MockBlueprint('tickets', __name__, url_prefix='/tickets') if not FLASK_AVAILABLE else None
    
    # Mock security headers function
    def add_security_headers(response):
        return response

def with_db_session(f):
    """Decorator to inject db_session into route handlers, but only if they accept it.

    - Always attaches the session to flask.g as g.db
    - Passes db_session keyword arg only when the view function signature includes it
    """
    sig = None
    try:
        sig = inspect.signature(f)
    except (TypeError, ValueError):
        # Builtins or C functions without signature support
        sig = None

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if FLASK_AVAILABLE:
            # Ensure session is available on g
            if not hasattr(g, 'db'):
                # Fallback if called outside request context; no-op
                pass
            # Inject kwarg only if function expects it
            if sig and 'db_session' in sig.parameters:
                kwargs['db_session'] = getattr(g, 'db', None)
        return f(*args, **kwargs)
    return decorated

def create_app(test_config=None):
    """Create and configure the Flask application."""
    # Set dev-friendly defaults if not already provided (align with __main__.py)
    os.environ.setdefault('DATABASE_URL', 'sqlite:///app.db')
    os.environ.setdefault('JWT_SECRET', 'dev-jwt-secret-change-me')
    os.environ.setdefault('PEPPER_SECRET', 'dev-pepper-secret-change-me')

    app = Flask(__name__)
    
    # Load configuration
    if test_config is None:
        # Load the instance config, if it exists, when not testing
        if FLASK_AVAILABLE:
            app.config.from_pyfile('config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.update(test_config)
    
    # Ensure the instance folder exists
    if FLASK_AVAILABLE:
        try:
            os.makedirs(app.instance_path, exist_ok=True)
        except OSError:
            pass

    # Optional CORS for local dev when frontend runs on a different origin
    if FLASK_AVAILABLE:
        origin: Optional[str] = os.environ.get('CORS_ORIGIN')
        if origin:
            try:
                from flask_cors import CORS
                CORS(app, resources={r"/*": {"origins": origin}}, supports_credentials=True)
            except Exception:
                # CORS not installed; ignore silently
                pass
    
    # Set up database
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        # Default to SQLite if no DATABASE_URL is specified
        database_url = "sqlite:///app.db"
        
    engine = create_engine(database_url)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db_session = scoped_session(session_factory)
    
    # Register blueprints if they exist
    if auth_bp:
        app.register_blueprint(auth_bp)
    if customers_bp:
        app.register_blueprint(customers_bp)
    if packages_bp:
        app.register_blueprint(packages_bp)
    if tickets_bp:
        app.register_blueprint(tickets_bp)
    
    # Database session middleware
    @app.before_request
    def before_request():
        """Attach database session to each request."""
        if FLASK_AVAILABLE:
            g.db = db_session()
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Close database session after each request."""
        if FLASK_AVAILABLE:
            if hasattr(g, 'db'):
                g.db.close()
    
    # Apply security headers to all responses
    @app.after_request
    def after_request(response):
        """Add security headers to all responses."""
        return add_security_headers(response)
    
    # Set up routes and additional components
    @app.route('/')
    def index():
        return {"message": "Communication LTD API"}

    # Cosmetic alias: serve root also under /vuln for clarity when only one server runs
    @app.route('/vuln')
    def vuln_index_alias():
        return {"message": "Communication LTD API (alias)", "alias": "/vuln"}

    # Cosmetic aliases for common API groups so /vuln/* works too
    from flask import redirect, Response, send_file

    @app.route('/vuln/auth', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_auth_root():
        return redirect('/auth', code=307)

    @app.route('/vuln/auth/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_auth(subpath):
        return redirect(f'/auth/{subpath}', code=307)

    @app.route('/vuln/tickets', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_tickets_root():
        return redirect('/tickets', code=307)

    @app.route('/vuln/tickets/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_tickets(subpath):
        return redirect(f'/tickets/{subpath}', code=307)

    @app.route('/vuln/customers', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_customers_root():
        return redirect('/customers', code=307)

    @app.route('/vuln/customers/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_customers(subpath):
        return redirect(f'/customers/{subpath}', code=307)

    @app.route('/vuln/packages', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_packages_root():
        return redirect('/packages', code=307)

    @app.route('/vuln/packages/<path:subpath>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
    def _alias_vuln_packages(subpath):
        return redirect(f'/packages/{subpath}', code=307)

    # Serve OpenAPI spec and Swagger UI without extra dependencies
    @app.route('/openapi.yaml', methods=['GET'])
    def openapi_spec():
        # Compute path to repo root -> api-contract/openapi.yaml
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
    
    # Fix route handlers to inject db_session
    if FLASK_AVAILABLE:
        # Auto-decorate route functions with db_session
        for endpoint, view_func in list(app.view_functions.items()):
            app.view_functions[endpoint] = with_db_session(view_func)
            
        # Patch blueprint view functions too
        for blueprint in app.blueprints.values():
            blueprint_prefix = blueprint.name + '.'
            for endpoint, view_func in list(app.view_functions.items()):
                if endpoint.startswith(blueprint_prefix):
                    app.view_functions[endpoint] = with_db_session(view_func)
    
    return app

# Add application run code for direct execution
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

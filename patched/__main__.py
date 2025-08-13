"""
Main entry point for running the application with automatic setup for local dev.
"""
import os
from patched.app_fixed import create_app
from patched.bootstrap import bootstrap_all

# Minimal bootstrap: set dev-friendly defaults if not provided
os.environ.setdefault('DATABASE_URL', 'sqlite:///app.db')
os.environ.setdefault('JWT_SECRET', 'dev-jwt-secret-change-me')
os.environ.setdefault('PEPPER_SECRET', 'dev-pepper-secret-change-me')

def main():
    # Optional: allow HTTPS via Werkzeug adhoc cert if requested
    use_https = os.environ.get('USE_HTTPS', '').lower() in ['1', 'true', 'yes', 'on']
    # If running over plain HTTP locally, default to insecure cookie unless overridden
    if not use_https:
        os.environ.setdefault('COOKIE_SECURE', 'false')

    # Bootstrap DB (migrations, config, seed admin) but don't crash on errors in dev
    try:
        bootstrap_all()
    except Exception as e:
        print(f"[bootstrap] Skipped due to error: {e}")

    app = create_app()

    # Start app
    # Allow overriding port via PORT env to align single-run model
    port = int(os.environ.get('PORT', '5000'))
    if use_https:
        # Werkzeug supports adhoc SSL context for quick local TLS
        app.run(debug=True, host='0.0.0.0', port=port, ssl_context='adhoc')
    else:
        app.run(debug=True, host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()

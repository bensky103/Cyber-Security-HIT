"""
Unified launcher for running either the secure (patched) or vulnerable API on a single port.

Usage (PowerShell):
  $env:APP_MODE = "patched"; python run.py
  $env:APP_MODE = "vuln";    python run.py

Defaults:
  - APP_MODE=patched
  - PORT=5000
"""
import os


def main():
    mode = os.environ.get("APP_MODE", "patched").lower()
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("DEBUG", "true").lower() in ["1", "true", "yes", "on"]

    if mode == "vuln":
        from vuln.app import app as flask_app
        flask_app.run(host=host, port=port, debug=debug)
    else:
        # default to patched
        from patched.app_fixed import create_app
        flask_app = create_app()
        flask_app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()

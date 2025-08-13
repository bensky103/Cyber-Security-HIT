"""
Local development bootstrap utilities: run migrations if available, ensure config, and seed admin user.
"""
import os
from sqlalchemy import create_engine

def run_alembic_upgrade_head() -> bool:
    """Attempt to run Alembic upgrade head. Returns True on success, False otherwise."""
    try:
        # Prefer invoking programmatically via Alembic API if available
        from alembic import command
        from alembic.config import Config

        ini_path = os.path.join(os.getcwd(), 'alembic.ini')
        if not os.path.exists(ini_path):
            return False

        cfg = Config(ini_path)
        # Ensure env has correct database url
        if 'DATABASE_URL' in os.environ:
            cfg.set_main_option('sqlalchemy.url', os.environ['DATABASE_URL'])

        command.upgrade(cfg, 'head')
        print('[bootstrap] Alembic migration: upgrade head completed')
        return True
    except Exception as e:
        print(f"[bootstrap] Alembic upgrade failed or not available: {e}")
        return False


def ensure_config_and_seed_admin():
    """Ensure config table exists and seed admin if needed."""
    from sqlalchemy.orm import sessionmaker
    from patched.config.setup import create_config_table
    from app.models.models import User
    from patched.auth.password_hasher import PasswordHasher
    from patched.config.config import AppConfig
    from app.models import Base

    engine = create_engine(os.environ.get('DATABASE_URL', 'sqlite:///app.db'))

    # Ensure config and baseline tables exist
    create_config_table(engine)
    Base.metadata.create_all(engine)

    # Seed admin if not exists
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        admin = session.query(User).filter(User.username == 'admin').first()
        if not admin:
            print('[bootstrap] Seeding default admin user: admin / Admin!23456')
            hasher = PasswordHasher(AppConfig.get_pepper_secret())
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=hasher.hash('Admin!23456'),
                role='admin'
            )
            session.add(admin)
            session.commit()
    finally:
        session.close()


def bootstrap_all():
    """Run all bootstrap steps for local development."""
    migrated = run_alembic_upgrade_head()
    ensure_config_and_seed_admin()
    return migrated

import os
import pytest
import inspect
from sqlalchemy import create_engine, inspect as sa_inspect
from sqlalchemy.orm import Session
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from pathlib import Path
from sqlalchemy.exc import SQLAlchemyError


# Set DATABASE_URL for testing
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

# Import models to test
try:
    from app.models import (
        Base, User, UserRole, PasswordHistory, PasswordResetToken,
        Customer, Package, CustomerPackage, PackageStatus,
        Ticket, TicketStatus, TicketPriority, TicketCategory,
        TicketComment, ForbiddenWord, AuditLog
    )
    MODELS_IMPORTED = True
except ImportError:
    MODELS_IMPORTED = False


def test_models_importable():
    """Test that all models are importable"""
    assert MODELS_IMPORTED, "Failed to import models"


def test_model_attributes():
    """Test that models have the expected attributes"""
    # Test User model
    assert hasattr(User, '__tablename__'), "User model missing tablename"
    assert User.__tablename__ == 'users', "User tablename should be 'users'"
    assert hasattr(User, 'id'), "User model missing id column"
    assert hasattr(User, 'username'), "User model missing username column"
    assert hasattr(User, 'email'), "User model missing email column"
    assert hasattr(User, 'password_hash'), "User model missing password_hash column"
    assert hasattr(User, 'role'), "User model missing role column"

    # Test Customer model
    assert hasattr(Customer, '__tablename__'), "Customer model missing tablename"
    assert Customer.__tablename__ == 'customers', "Customer tablename should be 'customers'"
    assert hasattr(Customer, 'id'), "Customer model missing id column"
    assert hasattr(Customer, 'user_id'), "Customer model missing user_id column"
    assert hasattr(Customer, 'first_name'), "Customer model missing first_name column"
    assert hasattr(Customer, 'last_name'), "Customer model missing last_name column"
    assert hasattr(Customer, 'phone_number'), "Customer model missing phone_number column"

    # Test Package model
    assert hasattr(Package, '__tablename__'), "Package model missing tablename"
    assert Package.__tablename__ == 'packages', "Package tablename should be 'packages'"
    assert hasattr(Package, 'id'), "Package model missing id column"
    assert hasattr(Package, 'name'), "Package model missing name column"
    assert hasattr(Package, 'description'), "Package model missing description column"
    assert hasattr(Package, 'price'), "Package model missing price column"
    assert hasattr(Package, 'features'), "Package model missing features column"

    # Test Ticket model
    assert hasattr(Ticket, '__tablename__'), "Ticket model missing tablename"
    assert Ticket.__tablename__ == 'tickets', "Ticket tablename should be 'tickets'"
    assert hasattr(Ticket, 'id'), "Ticket model missing id column"
    assert hasattr(Ticket, 'customer_id'), "Ticket model missing customer_id column"
    assert hasattr(Ticket, 'assigned_to'), "Ticket model missing assigned_to column"
    assert hasattr(Ticket, 'subject'), "Ticket model missing subject column"
    assert hasattr(Ticket, 'status'), "Ticket model missing status column"
    assert hasattr(Ticket, 'priority'), "Ticket model missing priority column"


def test_model_relationships():
    """Test that models have the expected relationships"""
    # Test User model relationships
    assert hasattr(User, 'password_history'), "User model missing password_history relationship"
    assert hasattr(User, 'password_reset_tokens'), "User model missing password_reset_tokens relationship"
    assert hasattr(User, 'customer'), "User model missing customer relationship"
    assert hasattr(User, 'tickets_assigned'), "User model missing tickets_assigned relationship"
    assert hasattr(User, 'comments'), "User model missing comments relationship"

    # Test Customer model relationships
    assert hasattr(Customer, 'user'), "Customer model missing user relationship"
    assert hasattr(Customer, 'packages'), "Customer model missing packages relationship"
    assert hasattr(Customer, 'tickets'), "Customer model missing tickets relationship"

    # Test Package model relationships
    assert hasattr(Package, 'customer_packages'), "Package model missing customer_packages relationship"

    # Test Ticket model relationships
    assert hasattr(Ticket, 'customer'), "Ticket model missing customer relationship"
    assert hasattr(Ticket, 'assigned_user'), "Ticket model missing assigned_user relationship"
    assert hasattr(Ticket, 'comments'), "Ticket model missing comments relationship"


def test_enum_values():
    """Test that enum values are correctly defined"""
    # Test UserRole enum
    assert UserRole.admin.value == "admin"
    assert UserRole.support.value == "support"
    assert UserRole.customer.value == "customer"

    # Test TicketStatus enum
    assert TicketStatus.new.value == "new"
    assert TicketStatus.in_progress.value == "in_progress"
    assert TicketStatus.on_hold.value == "on_hold"
    assert TicketStatus.resolved.value == "resolved"
    assert TicketStatus.closed.value == "closed"

    # Test TicketPriority enum
    assert TicketPriority.low.value == "low"
    assert TicketPriority.medium.value == "medium"
    assert TicketPriority.high.value == "high"
    assert TicketPriority.urgent.value == "urgent"

    # Test TicketCategory enum
    assert TicketCategory.billing.value == "billing"
    assert TicketCategory.technical.value == "technical"
    assert TicketCategory.account.value == "account"
    assert TicketCategory.other.value == "other"

    # Test PackageStatus enum
    assert PackageStatus.active.value == "active"
    assert PackageStatus.expired.value == "expired"
    assert PackageStatus.cancelled.value == "cancelled"


def test_unique_constraints():
    """Test that unique constraints are defined correctly"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    
    inspector = sa_inspect(engine)
    
    # Check User model unique constraints
    user_indices = inspector.get_indexes('users')
    user_unique_columns = [idx['column_names'][0] for idx in user_indices if idx['unique']]
    assert 'username' in user_unique_columns, "Username should have a unique constraint"
    assert 'email' in user_unique_columns, "Email should have a unique constraint"
    
    # Check Package model unique constraints
    package_indices = inspector.get_indexes('packages')
    package_unique_columns = [idx['column_names'][0] for idx in package_indices if idx['unique']]
    assert 'name' in package_unique_columns, "Package name should have a unique constraint"
    
    # Check ForbiddenWord model unique constraints
    forbidden_indices = inspector.get_indexes('forbidden_words')
    forbidden_unique_columns = [idx['column_names'][0] for idx in forbidden_indices if idx['unique']]
    assert 'word' in forbidden_unique_columns, "Forbidden word should have a unique constraint"


def test_required_columns():
    """Test that required columns are correctly defined as non-nullable"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    
    inspector = sa_inspect(engine)
    
    # Check User model required columns
    user_columns = {col['name']: col for col in inspector.get_columns('users')}
    assert not user_columns['username']['nullable'], "Username should be required"
    assert not user_columns['email']['nullable'], "Email should be required"
    assert not user_columns['password_hash']['nullable'], "Password hash should be required"
    assert not user_columns['role']['nullable'], "Role should be required"
    
    # Check Customer model required columns
    customer_columns = {col['name']: col for col in inspector.get_columns('customers')}
    assert not customer_columns['user_id']['nullable'], "User ID should be required"
    assert not customer_columns['first_name']['nullable'], "First name should be required"
    assert not customer_columns['last_name']['nullable'], "Last name should be required"
    assert not customer_columns['phone_number']['nullable'], "Phone number should be required"
    
    # Check Ticket model required columns
    ticket_columns = {col['name']: col for col in inspector.get_columns('tickets')}
    assert not ticket_columns['customer_id']['nullable'], "Customer ID should be required"
    assert not ticket_columns['subject']['nullable'], "Subject should be required"
    assert not ticket_columns['description']['nullable'], "Description should be required"
    assert not ticket_columns['status']['nullable'], "Status should be required"
    assert not ticket_columns['priority']['nullable'], "Priority should be required"
    assert not ticket_columns['category']['nullable'], "Category should be required"


def test_alembic_migrations():
    """Test that alembic migrations are correctly configured and can run programmatically"""
    # Get the project root directory
    project_dir = Path(__file__).parent.parent
    
    # Set up alembic config
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", str(project_dir / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", os.environ.get("DATABASE_URL", "sqlite:///:memory:"))
    
    # Check that the versions directory exists and contains migration files
    versions_dir = project_dir / "migrations" / "versions"
    assert versions_dir.exists(), "Migrations versions directory should exist"
    
    migration_files = list(versions_dir.glob("*.py"))
    assert len(migration_files) > 0, "There should be at least one migration file"
    
    # Check that we can get migration script directory
    script = ScriptDirectory.from_config(alembic_cfg)
    assert script is not None
    
    # Check that we have a revision
    head = script.get_current_head()
    assert head is not None, "There should be a migration head revision"
    
    # Create an in-memory database and check if migration can be run
    # Note: For SQLite in-memory connection, we need to use a persistent connection
    # to keep the database active during the test
    engine = create_engine("sqlite:///:memory:")
    connection = engine.connect()
    
    try:
        # Update the config with our connection
        alembic_cfg.attributes['connection'] = connection
        
        # Create database tables from scratch using alembic
        command.upgrade(alembic_cfg, "head")        # Check that all expected tables are created
        inspector = sa_inspect(engine)
        tables = inspector.get_table_names()
        
        expected_tables = [
            'users',
            'password_history',
            'password_reset_tokens',
            'customers',
            'packages',
            'customer_packages',
            'tickets',
            'ticket_comments',
            'forbidden_words',
            'audit_log',
            'alembic_version'  # Alembic's own table
        ]
        
        for table in expected_tables:
            assert table in tables, f"Table {table} should be created by migrations"
            
    except SQLAlchemyError as e:
        pytest.fail(f"Failed to run alembic migrations: {str(e)}")


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])

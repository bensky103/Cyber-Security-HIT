from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Override config with environment variable for DATABASE_URL
config.set_main_option("sqlalchemy.url", os.environ.get("DATABASE_URL", "mysql+pymysql://user:pass@localhost/communication_ltd"))

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
from app.models import Base
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # Check if a connection is already provided (useful for testing)
    connection = config.attributes.get('connection', None)
    connectable = None
    
    if connection is None:
        connectable = engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        connection = connectable.connect()
        close_connection_at_end = True
    else:
        close_connection_at_end = False
    
    # Determine if we're using SQLite
    is_sqlite = connection.engine.dialect.name == 'sqlite'
    
    with connection:
        # Set up SQLite for foreign key support if needed
        if is_sqlite:
            # Enable foreign key support
            from sqlalchemy import text
            connection.execute(text("PRAGMA foreign_keys=ON"))
            
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            compare_type=True,
            # Use render_as_batch for SQLite to handle column/table alterations better
            render_as_batch=is_sqlite,
        )

        with context.begin_transaction():
            context.run_migrations()
            
    # Only close the connection if we created it
    if connectable is not None and close_connection_at_end:
        connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

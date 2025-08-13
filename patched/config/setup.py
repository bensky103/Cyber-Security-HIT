"""
Create or update SQL tables for storing configuration.
"""
from sqlalchemy import Table, Column, String, Text, MetaData
from sqlalchemy.sql import text

def create_config_table(engine):
    """
    Create the config table if it doesn't exist.
    
    Args:
        engine: SQLAlchemy engine
        
    Returns:
        True if successful, False otherwise
    """
    try:
        metadata = MetaData()
        
        # Define config table
        config_table = Table(
            'config',
            metadata,
            Column('name', String(100), primary_key=True),
            Column('value', Text, nullable=True),
        )
        
        # Create table if it doesn't exist
        metadata.create_all(engine, tables=[config_table])
        
        # Insert default password policy if not exists
        with engine.connect() as connection:
            result = connection.execute(text("SELECT COUNT(*) FROM config WHERE name = 'password_policy'"))
            if result.scalar() == 0:
                connection.execute(
                    text("INSERT INTO config (name, value) VALUES (:name, :value)"),
                    {
                        "name": "password_policy",
                        "value": '{"min_length": 10, "require_uppercase": true, "require_lowercase": true, "require_digit": true, "require_special": true, "history_count": 3}'
                    }
                )
                connection.commit()
        
        return True
        
    except Exception as e:
        print(f"Error creating config table: {e}")
        return False

"""
Utilities for working with the database and stored procedures.
"""
from sqlalchemy import text
from datetime import datetime
import json

class DatabaseUtils:
    """
    Utility functions for database operations.
    """
    
    @staticmethod
    def execute_stored_procedure(db_session, procedure_name, params=None):
        """
        Execute a stored procedure with parameterized input.
        
        Args:
            db_session: SQLAlchemy database session
            procedure_name: Name of the stored procedure to execute
            params: Dictionary of parameters to pass to the stored procedure
            
        Returns:
            Result of the stored procedure execution
        """
        if params is None:
            params = {}
            
        try:
            # Format the stored procedure call SQL
            sql = f"CALL {procedure_name}("
            placeholders = []
            param_values = {}
            
            # Add named parameters
            for i, (key, value) in enumerate(params.items()):
                param_name = f"p_{i}"
                placeholders.append(f":{param_name}")
                param_values[param_name] = value
                
            sql += ", ".join(placeholders) + ")"
            
            # Execute the stored procedure
            result = db_session.execute(text(sql), param_values)
            return result
        except Exception as e:
            db_session.rollback()
            raise e

    @staticmethod
    def create_ticket_procedure(db_session, customer_id, subject, description, priority, category, assigned_to=None):
        """
        Execute stored procedure for creating a ticket.
        
        Args:
            db_session: SQLAlchemy database session
            customer_id: ID of the customer creating the ticket
            subject: Subject of the ticket
            description: Description of the ticket
            priority: Priority level of the ticket
            category: Category of the ticket
            assigned_to: ID of the user the ticket is assigned to (optional)
            
        Returns:
            ID of the created ticket or None if creation failed
        """
        try:
            # Portable timestamp values set from application
            now = datetime.utcnow()
            sql = text(
                """
                INSERT INTO tickets (
                    customer_id, subject, description, status,
                    priority, category, assigned_to, created_at, updated_at
                )
                VALUES (
                    :customer_id, :subject, :description, 'new',
                    :priority, :category, :assigned_to, :created_at, :updated_at
                )
                """
            )

            result = db_session.execute(
                sql,
                {
                    'customer_id': customer_id,
                    'subject': subject,
                    'description': description,
                    'priority': priority,
                    'category': category,
                    'assigned_to': assigned_to,
                    'created_at': now,
                    'updated_at': now,
                }
            )

            db_session.commit()
            # SQLAlchemy 1.4: lastrowid may not be populated; fallback to SELECT last_insert_rowid() for SQLite
            ticket_id = getattr(result, 'lastrowid', None)
            if ticket_id is None:
                try:
                    rid = db_session.execute(text('SELECT last_insert_rowid()')).scalar()
                    ticket_id = rid
                except Exception:
                    pass
            return ticket_id
        except Exception as e:
            db_session.rollback()
            raise e
    
    @staticmethod
    def create_comment_procedure(db_session, ticket_id, user_id, content):
        """
        Execute stored procedure for creating a ticket comment.
        
        Args:
            db_session: SQLAlchemy database session
            ticket_id: ID of the ticket
            user_id: ID of the user creating the comment
            content: Content of the comment (sanitized)
            
        Returns:
            ID of the created comment or None if creation failed
        """
        try:
            now = datetime.utcnow()
            sql = text(
                """
                INSERT INTO ticket_comments (
                    ticket_id, user_id, content, created_at, updated_at
                )
                VALUES (
                    :ticket_id, :user_id, :content, :created_at, :updated_at
                )
                """
            )

            result = db_session.execute(
                sql,
                {
                    'ticket_id': ticket_id,
                    'user_id': user_id,
                    'content': content,
                    'created_at': now,
                    'updated_at': now,
                }
            )

            db_session.commit()
            comment_id = getattr(result, 'lastrowid', None)
            if comment_id is None:
                try:
                    rid = db_session.execute(text('SELECT last_insert_rowid()')).scalar()
                    comment_id = rid
                except Exception:
                    pass
            return comment_id
        except Exception as e:
            db_session.rollback()
            raise e

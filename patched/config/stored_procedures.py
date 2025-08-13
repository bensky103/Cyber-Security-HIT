"""
Create the SQL setup for MySQL stored procedures.
"""

# SQL script to create the stored procedures for secure authentication
SQL_STORED_PROCEDURES = """
-- Procedure to update login attempts atomically
DELIMITER //

CREATE PROCEDURE update_login_attempts(
    IN p_user_id BIGINT,
    IN p_success BOOLEAN,
    IN p_max_attempts INT,
    IN p_lockout_minutes INT,
    OUT p_account_locked BOOLEAN,
    OUT p_lockout_time DATETIME
)
BEGIN
    DECLARE v_current_attempts INT;
    DECLARE v_locked BOOLEAN;
    
    -- Start a transaction to ensure atomicity
    START TRANSACTION;
    
    -- Get current user state
    SELECT failed_login_attempts, account_locked 
    INTO v_current_attempts, v_locked
    FROM users 
    WHERE id = p_user_id 
    FOR UPDATE;
    
    -- Set default output values
    SET p_account_locked = FALSE;
    SET p_lockout_time = NULL;
    
    -- If login was successful
    IF p_success = TRUE THEN
        -- Reset failed attempts and unlock account on successful login
        UPDATE users
        SET failed_login_attempts = 0, 
            account_locked = FALSE, 
            last_login = NOW()
        WHERE id = p_user_id;
    ELSE
        -- If login failed
        IF v_locked = TRUE THEN
            -- Account is already locked, keep it locked
            SET p_account_locked = TRUE;
            SET p_lockout_time = DATE_ADD(NOW(), INTERVAL p_lockout_minutes MINUTE);
        ELSE
            -- Increment failed attempts
            SET v_current_attempts = v_current_attempts + 1;
            
            -- Check if we should lock the account
            IF v_current_attempts >= p_max_attempts THEN
                -- Lock account and set lockout time
                SET p_account_locked = TRUE;
                SET p_lockout_time = DATE_ADD(NOW(), INTERVAL p_lockout_minutes MINUTE);
                
                UPDATE users
                SET failed_login_attempts = v_current_attempts,
                    account_locked = TRUE,
                    lockout_until = p_lockout_time
                WHERE id = p_user_id;
            ELSE
                -- Just update failed attempts
                UPDATE users
                SET failed_login_attempts = v_current_attempts
                WHERE id = p_user_id;
            END IF;
        END IF;
    END IF;
    
    -- Commit the transaction
    COMMIT;
END //

-- Procedure to validate and consume a reset token
CREATE PROCEDURE validate_reset_token(
    IN p_token_hash VARCHAR(100),
    OUT p_valid BOOLEAN,
    OUT p_user_id BIGINT
)
BEGIN
    DECLARE v_token_exists INT;
    DECLARE v_token_expired BOOLEAN;
    DECLARE v_token_used BOOLEAN;
    
    -- Start transaction
    START TRANSACTION;
    
    -- Check if token exists, is not expired, and has not been used
    SELECT 
        COUNT(*), 
        MAX(user_id) as user_id,
        MAX(CASE WHEN expires_at < NOW() THEN TRUE ELSE FALSE END) as expired,
        MAX(used) as used
    INTO 
        v_token_exists, 
        p_user_id,
        v_token_expired,
        v_token_used
    FROM password_reset_tokens 
    WHERE token = p_token_hash
    FOR UPDATE;
    
    -- Default to invalid
    SET p_valid = FALSE;
    
    IF v_token_exists = 0 THEN
        -- Token doesn't exist
        SET p_valid = FALSE;
        SET p_user_id = NULL;
    ELSEIF v_token_expired = TRUE THEN
        -- Token is expired
        SET p_valid = FALSE;
    ELSEIF v_token_used = TRUE THEN
        -- Token has already been used
        SET p_valid = FALSE;
    ELSE
        -- Token is valid, mark it as used
        UPDATE password_reset_tokens
        SET used = TRUE
        WHERE token = p_token_hash;
        
        SET p_valid = TRUE;
    END IF;
    
    -- Commit the transaction
    COMMIT;
END //

DELIMITER ;
"""

def get_stored_procedures():
    """
    Return the SQL stored procedures as a string.
    """
    return SQL_STORED_PROCEDURES

def create_stored_procedures(connection):
    """
    Execute stored procedures creation on a database connection.
    
    Args:
        connection: A raw database connection (not SQLAlchemy session)
    
    Returns:
        True if successful, False otherwise
    """
    cursor = connection.cursor()
    
    # Split the procedures by DELIMITER marker
    procedures = SQL_STORED_PROCEDURES.split("DELIMITER //")[1:]
    
    try:
        # For each procedure between DELIMITER markers
        for proc in procedures:
            if not proc.strip():
                continue
                
            # Split by DELIMITER ; to get the procedure body
            body = proc.split("DELIMITER ;")[0].strip()
            
            # Execute the procedure creation
            cursor.execute(body)
            
        connection.commit()
        return True
    except Exception as e:
        print(f"Error creating stored procedures: {e}")
        connection.rollback()
        return False
    finally:
        cursor.close()

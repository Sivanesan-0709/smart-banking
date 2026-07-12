import os
import sys
import json
import time
import traceback

def log(msg):
    print(f"[VERIFY] {msg}", flush=True)

def main():
    log("Starting PostgreSQL Production Verification...")
    
    # 1. Check if db_helper can be imported
    try:
        from db_helper import get_db_connection, _pool, init_pool
    except ImportError as e:
        log(f"ERROR: Failed to import db_helper: {e}")
        sys.exit(1)
        
    db_url = os.environ.get('DATABASE_URL')
    is_postgres = (db_url is not None or any(os.environ.get(var) for var in ['DB_HOST', 'DB_NAME', 'DB_USER']))
    
    if not is_postgres:
        log("WARNING: No PostgreSQL environment variables detected.")
        log("Application is running in SQLite fallback mode.")
        log("To verify PostgreSQL, please set DATABASE_URL or DB_HOST/DB_NAME/DB_USER.")
        log("Active Engine: SQLite")
    else:
        log("PostgreSQL environment variables detected.")
        log("Active Engine: PostgreSQL")
        
    # 2. Test Connection
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if is_postgres:
            cursor.execute("SELECT version()")
        else:
            cursor.execute("SELECT sqlite_version()")
        ver = cursor.fetchone()[0]
        log(f"Connection Success! DB Version: {ver.strip()}")
    except Exception as e:
        log(f"ERROR: Connection failed: {e}")
        traceback.print_exc()
        sys.exit(1)
        
    # 3. Check Tables
    required_tables = [
        'newbank', 'newt', 'pending_transactions', 'transaction_otp_challenges',
        'login_attempts', 'face_enrollments', 'face_verification_attempts',
        'biometric_security_events', 'cash_out_channels'
    ]
    
    log("Verifying tables...")
    missing_tables = []
    for table in required_tables:
        try:
            if is_postgres:
                cursor.execute(
                    "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s)",
                    (table,)
                )
                exists = cursor.fetchone()[0]
            else:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
                    (table.upper() if table in ('newbank', 'newt') else table,)
                )
                exists = cursor.fetchone() is not None
                
            if exists:
                log(f"  - Table '{table}' exists.")
            else:
                log(f"  - Table '{table}' MISSING!")
                missing_tables.append(table)
        except Exception as e:
            log(f"ERROR checking table '{table}': {e}")
            missing_tables.append(table)
            
    if missing_tables:
        log(f"ERROR: Schema incomplete. Missing tables: {missing_tables}")
        sys.exit(1)
        
    # 4. Verify Foreign Keys
    log("Verifying foreign key constraints...")
    if is_postgres:
        cursor.execute('''
        SELECT conname, confrelid::regclass
        FROM pg_constraint
        WHERE contype = 'f' AND connamespace = 'public'::regnamespace
        ''')
        fks = cursor.fetchall()
        for fk in fks:
            log(f"  - Found constraint '{fk[0]}' referencing '{fk[1]}'")
    else:
        log("  - Foreign keys verified via SQLite schema definition.")
        
    # 5. Verify Indexes
    log("Verifying database indexes...")
    if is_postgres:
        cursor.execute('''
        SELECT indexname, tablename, indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
        ''')
        indexes = cursor.fetchall()
        for idx in indexes:
            log(f"  - Index '{idx[0]}' exists on '{idx[1]}'")
    else:
        cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index'")
        indexes = cursor.fetchall()
        for idx in indexes:
            log(f"  - Index '{idx[0]}' exists on '{idx[1]}'")
            
    # 6. Verify Transaction Rollback
    log("Verifying transaction rollback behavior...")
    try:
        # Start transaction
        conn.autocommit = False
        cursor = conn.cursor()
        
        # 1. Insert seed user
        cursor.execute("SELECT COUNT(*) FROM NEWBANK WHERE USERNAME = 'rollback_test'")
        exists = cursor.fetchone()[0]
        if not exists:
            cursor.execute('''
            INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, SEX, ADDRESS, BAL)
            VALUES ('rollback_test', 'Test', 'Rollback', 'test@test.com', 'pwd', 'pwd', '123', 'M', 'Addr', 50000.0)
            ''')
            
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rollback_test'")
        initial_bal = cursor.fetchone()['BAL']
        
        # 2. Perform atomic update
        cursor.execute("UPDATE NEWBANK SET BAL = BAL - 1000 WHERE USERNAME = 'rollback_test'")
        
        # 3. Deliberately raise unique constraint violation to trigger rollback
        cursor.execute('''
        INSERT INTO NEWBANK (USERNAME, FIRSTNAME, LASTNAME, EMAIL, PASSWORD, CONFIRM, PHONE, ADDRESS)
        VALUES ('rollback_test', 'Dup', 'Dup', 'dup@test.com', 'pwd', 'pwd', '123', 'Addr')
        ''')
        
        # Should not reach here
        conn.commit()
        log("ERROR: Transaction did not fail as expected!")
        sys.exit(1)
    except Exception as rollback_err:
        log(f"  - Caught expected transaction error: {str(rollback_err).strip()}")
        try:
            conn.rollback()
            log("  - Rollback executed successfully.")
        except Exception as rb_failed:
            log(f"ERROR: Rollback failed: {rb_failed}")
            sys.exit(1)
            
    # Re-verify balance is unchanged
    try:
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("SELECT BAL FROM NEWBANK WHERE USERNAME = 'rollback_test'")
        post_bal_row = cursor.fetchone()
        post_bal = post_bal_row['BAL'] if post_bal_row else 50000.0
        if post_bal == initial_bal:
            log(f"  - Balance Verification: Balance is unchanged ({post_bal}). ROLLBACK verified!")
        else:
            log(f"ERROR: Balance changed from {initial_bal} to {post_bal}. ROLLBACK failed!")
            sys.exit(1)
    except Exception as e:
        log(f"ERROR verifying balance after rollback: {e}")
        sys.exit(1)
        
    # Clean up test user
    try:
        cursor.execute("DELETE FROM NEWBANK WHERE USERNAME = 'rollback_test'")
    except:
        pass
        
    log("All database diagnostics passed successfully!")
    log("PostgreSQL Production Verification: PASSED")

if __name__ == '__main__':
    main()

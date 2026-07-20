import sqlite3
import os
import sys

DB_FILE = "BankNH.db"

def main():
    print("====================================================")
    print("Smart Banking Database Reset Utility")
    print("====================================================")
    
    if not os.path.exists(DB_FILE):
        print(f"ERROR: Database file '{DB_FILE}' not found in the current directory.")
        sys.exit(1)
        
    print(f"Target Database: {os.path.abspath(DB_FILE)}")
    
    # 1. Connect to database to count rows first
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
    except Exception as e:
        print(f"ERROR: Failed to connect to database: {e}")
        sys.exit(1)
        
    # Table definitions and classifications
    # Dynamic user-data tables (Child tables first, parent tables last)
    tables_to_clear = [
        ("transaction_otp_challenges", "OTP challenges linked to pending transactions"),
        ("pending_transactions", "Transactions awaiting MFA or Admin verification"),
        ("face_enrollments", "Biometric face registration records"),
        ("face_verification_attempts", "Biometric match/mismatch attempt logs"),
        ("biometric_security_events", "Security events and logs (wallet deposit/MFA/etc.)"),
        ("deposits", "Deposits and smart wallet top-up records"),
        ("beneficiaries", "Registered transaction recipient lists"),
        ("login_history", "Session, fingerprint, and login logs"),
        ("notifications", "In-app system and transaction alerts"),
        ("audit_logs", "Sensitive action tracking and logs"),
        ("trusted_devices", "Registered trusted device fingerprints"),
        ("face_samples", "Biometric face sample embeddings"),
        ("login_attempts", "Tracked failed login count records"),
        ("NEWT", "General ledger and transaction history logs")
    ]
    
    # NEWBANK is handled specially to preserve the 'admin' user
    parent_table = "NEWBANK"
    
    print("\n[INFO] Analyzing database tables...")
    
    table_counts = {}
    total_records = 0
    
    for table, desc in tables_to_clear:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            table_counts[table] = count
            total_records += count
            print(f" - {table:<28} | {count:>5} records | {desc}")
        except sqlite3.OperationalError:
            # Table might not exist yet if migrations haven't run
            table_counts[table] = 0
            print(f" - {table:<28} |  (Table does not exist in schema)")
            
    # Count NEWBANK users
    try:
        cursor.execute("SELECT COUNT(*) FROM NEWBANK")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM NEWBANK WHERE USERNAME = 'admin'")
        admin_exists = cursor.fetchone()[0] > 0
        test_users_count = total_users - (1 if admin_exists else 0)
        print(f" - {'NEWBANK (test/dummy users)':<28} | {test_users_count:>5} records | User accounts (excluding default 'admin')")
    except sqlite3.OperationalError:
        test_users_count = 0
        admin_exists = False
        print(f" - {'NEWBANK':<28} |  (Table does not exist in schema)")
        
    print("----------------------------------------------------")
    
    if total_records == 0 and test_users_count == 0:
        print("Database is already clean. No test or dummy data found to clear.")
        conn.close()
        sys.exit(0)
        
    print("\nWARNING: This script will delete ALL transaction history, ledger entries,")
    print("MFA challenges, device registrations, and user accounts except the 'admin' user.")
    print("Database tables, columns, indexes, and constraints will remain intact.")
    
    # Prompt user for confirmation
    confirm = input("\nAre you sure you want to proceed with the reset? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("\nReset cancelled by user. No data was deleted.")
        conn.close()
        sys.exit(0)
        
    print("\n[INFO] Starting database transaction...")
    
    try:
        # Turn on foreign keys to ensure constraints are checked
        cursor.execute("PRAGMA foreign_keys = ON;")
        
        # 1. Clear dynamic child and independent tables first
        for table, _ in tables_to_clear:
            if table_counts.get(table, 0) > 0:
                cursor.execute(f"DELETE FROM {table};")
                print(f"Deleted {table_counts[table]} records from {table}")
                
        # 2. Clear test/dummy users from NEWBANK
        if test_users_count > 0:
            cursor.execute("DELETE FROM NEWBANK WHERE USERNAME != 'admin';")
            print(f"Deleted {test_users_count} test/dummy users from NEWBANK (default 'admin' account preserved)")
            
        # Commit transaction
        conn.commit()
        print("\n[SUCCESS] Transaction committed. Database reset successfully completed!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] Deletion failed. Transaction rolled back. Details: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    main()

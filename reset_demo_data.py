"""
Safe Presentation Demo Data Reset Script
Smart Banking and Fraud Detection System

Usage:
  Dry Run (Default, Safe Inspection):
    python reset_demo_data.py

  Actual Execution (Requires Explicit Flag):
    python reset_demo_data.py --execute

Rules & Safety Features:
- Connects to configured PostgreSQL / SQLite database via db_helper.
- Dynamically discovers existing tables in database before query execution.
- Skips optional missing tables cleanly without failing the reset.
- Preserves system configuration tables (e.g. cash_out_channels).
- Preserves the default Administrator account ('admin').
- Never drops tables or alters schema.
- Executes within an atomic database transaction with automatic rollback on failure.
- Prints pre and post row counts.
- Never prints passwords, keys, or secrets.
"""

import sys
import os
import argparse

from db_helper import get_db_connection

# Candidate tables for demo reset in safe foreign-key dependency order
CANDIDATE_TABLES = [
    {"name": "face_verification_attempts", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "biometric_security_events", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "face_enrollments", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "transaction_otp_challenges", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "pending_transactions", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "notifications", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "fraud_feedback", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "beneficiaries", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "user_sessions", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "trusted_devices", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "login_attempts", "condition": None, "type": "SECURITY / AUDIT LOGS"},
    {"name": "deposits", "condition": None, "type": "USER TRANSACTIONAL DATA"},
    {"name": "NEWT", "condition": None, "type": "USER TRANSACTIONAL DATA (Ledger)"},
    {"name": "NEWBANK", "condition": "LOWER(USERNAME) != 'admin'", "type": "USER TRANSACTIONAL DATA (Preserving 'admin')"}
]

SYSTEM_TABLES_PRESERVED = [
    "cash_out_channels (SYSTEM/CONFIGURATION DATA - UNTOUCHED)"
]

def get_existing_tables(cursor, is_postgres):
    """Dynamically discover which tables exist in the connected database."""
    if is_postgres:
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        rows = cursor.fetchall()
        return {row[0].lower() for row in rows}
    else:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        rows = cursor.fetchall()
        return {row[0].lower() for row in rows}

def main():
    parser = argparse.ArgumentParser(description="Safe Presentation Demo Data Reset Tool")
    parser.add_argument("--execute", action="store_true", help="Execute actual deletion (default is DRY RUN)")
    args = parser.parse_args()

    is_dry_run = not args.execute

    print("==========================================================")
    print("      SAFE PRESENTATION DEMO DATA RESET TOOL              ")
    print("==========================================================")

    db_url = os.environ.get('DATABASE_URL')
    is_postgres = (db_url is not None or any(os.environ.get(v) for v in ['DB_HOST', 'DB_NAME', 'DB_USER']))

    target_engine = "PostgreSQL (Render Production)" if is_postgres else "SQLite (Local Development)"
    print(f"[INFO] Target Database Engine: {target_engine}")
    print(f"[INFO] Mode: {'[DRY RUN - INSPECTION ONLY]' if is_dry_run else '[ACTUAL EXECUTION - LIVE DELETE]'}")
    print("==========================================================")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Step 1: Discover existing tables
        existing_tables_lower = get_existing_tables(cursor, is_postgres)
        
        tables_to_process = []
        skipped_tables = []

        for item in CANDIDATE_TABLES:
            tbl_name = item["name"]
            if tbl_name.lower() in existing_tables_lower:
                tables_to_process.append(item)
            else:
                skipped_tables.append(tbl_name)

        print("\n--- DYNAMIC TABLE DISCOVERY ---")
        print(f"  • Existing Tables Detected ({len(tables_to_process)}): {[t['name'] for t in tables_to_process]}")
        if skipped_tables:
            print(f"  • Missing Tables Skipped ({len(skipped_tables)}): {skipped_tables}")
            for sk in skipped_tables:
                print(f"    [SKIPPED] {sk} - table does not exist in database")

        print("\n--- PRE-RESET ROW COUNTS ---")
        counts_before = {}
        normal_users_to_remove = 0

        for item in tables_to_process:
            tbl = item["name"]
            cond = item["condition"]
            sql = f"SELECT COUNT(*) FROM {tbl}"
            if cond:
                sql += f" WHERE {cond}"
            try:
                cursor.execute(sql)
                cnt = cursor.fetchone()[0]
                counts_before[tbl] = cnt
                if tbl.upper() == "NEWBANK":
                    normal_users_to_remove = cnt
                print(f"  • {tbl:<30}: {cnt:>5} rows ({item['type']})")
            except Exception as e:
                counts_before[tbl] = 0
                print(f"  • {tbl:<30}: Error checking count: {e}")

        # Verify admin presence in NEWBANK
        admin_exists = False
        if "newbank" in existing_tables_lower:
            cursor.execute("SELECT COUNT(*) FROM NEWBANK WHERE LOWER(USERNAME) = 'admin'")
            admin_cnt = cursor.fetchone()[0]
            admin_exists = (admin_cnt > 0)
            print(f"\n  • Admin Account ('admin'): {'EXISTS (Will be PRESERVED)' if admin_exists else 'NOT FOUND'}")
            print(f"  • Normal Users To Remove : {normal_users_to_remove}")

        print("\n--- PRESERVED SYSTEM TABLES ---")
        for sys_tbl in SYSTEM_TABLES_PRESERVED:
            print(f"  [PRESERVED] {sys_tbl}")

        if is_dry_run:
            print("\n==========================================================")
            print("[DRY RUN COMPLETE] No data was deleted or modified.")
            print("To execute actual demo data reset, run:")
            print("  python reset_demo_data.py --execute")
            print("==========================================================")
            return

        print("\n[EXECUTING] Deleting demo user data within transaction block...")
        deleted_counts = {}

        for item in tables_to_process:
            tbl = item["name"]
            cond = item["condition"]
            sql = f"DELETE FROM {tbl}"
            if cond:
                sql += f" WHERE {cond}"
            
            cursor.execute(sql)
            row_count = cursor.rowcount if hasattr(cursor, 'rowcount') and cursor.rowcount is not None and cursor.rowcount >= 0 else counts_before.get(tbl, 0)
            deleted_counts[tbl] = row_count
            print(f"  ✓ Deleted {row_count} rows from {tbl}")

        # Verify admin account still exists before committing
        if "newbank" in existing_tables_lower:
            cursor.execute("SELECT COUNT(*) FROM NEWBANK WHERE LOWER(USERNAME) = 'admin'")
            post_admin_cnt = cursor.fetchone()[0]
            if post_admin_cnt == 0:
                raise Exception("Safety Check Failed: Admin account was deleted! Rolling back transaction.")

        conn.commit()
        print("\n[SUCCESS] Transaction committed successfully.")

        print("\n--- POST-RESET VERIFICATION ROW COUNTS ---")
        for item in tables_to_process:
            tbl = item["name"]
            sql = f"SELECT COUNT(*) FROM {tbl}"
            try:
                cursor.execute(sql)
                cnt = cursor.fetchone()[0]
                print(f"  • {tbl:<30}: {cnt:>5} rows remaining")
            except Exception:
                pass

        print("\n==========================================================")
        print("[RESET SUCCESSFUL]")
        print("Demo/test data cleared.")
        print("Admin account preserved.")
        print("System/configuration data preserved.")
        print("Database is ready for a fresh presentation account.")
        print("==========================================================")

    except Exception as e:
        print(f"\n[ERROR] Reset failed: {e}")
        try:
            conn.rollback()
            print("\n==========================================================")
            print("[RESET FAILED]")
            print("Transaction rolled back.")
            print("No partial reset was committed.")
            print("==========================================================")
        except Exception:
            pass
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    main()

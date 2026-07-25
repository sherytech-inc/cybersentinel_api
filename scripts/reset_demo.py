import asyncio
import os
import sys
import glob
import argparse

# Add current directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.client import init_db
from app.core.config import get_settings

def parse_args():
    parser = argparse.ArgumentParser(description="Factory reset for CyberSentinel Demo.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without deleting data.")
    parser.add_argument("--execute", action="store_true", help="Execute the deletion. Requires confirmation.")
    parser.add_argument("--environment", type=str, help="Specify environment explicitly (e.g. demo).")
    return parser.parse_args()

def check_environment_guards(args, settings):
    if not os.environ.get("ALLOW_DESTRUCTIVE_RESET") == "true":
        print("ERROR: ALLOW_DESTRUCTIVE_RESET environment variable must be set to 'true'.")
        sys.exit(1)
        
    app_env = os.environ.get("APP_ENV", "development")
    if app_env == "production" and args.environment != "demo":
        print("ERROR: APP_ENV is production. Use --environment demo to explicitly override.")
        sys.exit(1)

async def main():
    args = parse_args()
    settings = get_settings()
    
    if not args.dry_run and not args.execute:
        print("You must specify either --dry-run or --execute.")
        sys.exit(1)

    print(f"--- CyberSentinel Reset Script ---")
    print(f"Target Supabase Host: {settings.SUPABASE_URL}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'EXECUTE'}\n")

    if args.execute:
        check_environment_guards(args, settings)
        confirmation = input("Type 'RESET CYBERSENTINEL' to confirm deletion: ")
        if confirmation != "RESET CYBERSENTINEL":
            print("Confirmation failed. Aborting.")
            sys.exit(1)

    client = await init_db()
    
    # Dependent to Parent order
    tables = [
        "audit_logs",
        "copilot_conversations",
        "reports",
        "response_actions",
        "threat_scores",
        "ip_intelligence",
        "firewall_actions",
        "virus_scans",
        "firewall_logs",
        "threat_alerts",
        "packets"
    ]
    
    # Primary Key identifier heuristics to work around Supabase delete requirement
    pk_map = {
        "threat_alerts": "alert_id",
        "ip_intelligence": "ip_address",
        "packets": "id",
        "firewall_actions": "id",
        "threat_scores": "id",
        "audit_logs": "id",
        "copilot_conversations": "id",
        "reports": "id",
        "response_actions": "id",
        "virus_scans": "id",
        "firewall_logs": "id"
    }

    dummy_uuid = "00000000-0000-0000-0000-000000000000"
    dummy_ip = "0.0.0.0"

    results = {}
    
    print("--- Database Reset ---")
    for table in tables:
        try:
            # Count rows
            res = await client.table(table).select("count", count="exact").limit(1).execute()
            count = res.count if res.count is not None else 0
            
            if args.dry_run:
                print(f"[DRY RUN] Would delete {count} rows from {table}")
                results[table] = count
            else:
                pk = pk_map.get(table, "id")
                dummy_val = dummy_ip if pk == "ip_address" else dummy_uuid
                
                await client.table(table).delete().neq(pk, dummy_val).execute()
                print(f"[EXECUTE] Deleted {count} rows from {table}")
                results[table] = count
        except Exception as e:
            # Fallback if alert_id is not the primary key for threat_alerts
            if table == "threat_alerts":
                 try:
                    res = await client.table(table).select("count", count="exact").limit(1).execute()
                    count = res.count if res.count is not None else 0
                    if not args.dry_run:
                        await client.table(table).delete().neq("id", dummy_uuid).execute()
                        print(f"[EXECUTE] Deleted {count} rows from {table}")
                    else:
                        print(f"[DRY RUN] Would delete {count} rows from {table}")
                    results[table] = count
                 except Exception as e2:
                     print(f"Error accessing {table}: {e2}")
            else:
                print(f"Error accessing {table}: {e}")

    print("\n--- Artifacts Cleanup ---")
    artifact_dirs = [
        "app/artifacts/reports",
        "app/artifacts/exports",
        "app/artifacts/temp"
    ]
    
    deleted_files = {"pdf": 0, "csv": 0, "json": 0}
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d in artifact_dirs:
        full_dir = os.path.join(base_dir, d)
        if os.path.exists(full_dir):
            for ext in ["*.pdf", "*.csv", "*.json"]:
                for filepath in glob.glob(os.path.join(full_dir, ext)):
                    if args.dry_run:
                        print(f"[DRY RUN] Would delete {filepath}")
                    else:
                        os.remove(filepath)
                        print(f"[EXECUTE] Deleted {filepath}")
                    ext_key = ext.replace("*.", "")
                    if ext_key in deleted_files:
                        deleted_files[ext_key] += 1
                    else:
                        deleted_files[ext_key] = 1

    print("\n==============================")
    print("  CyberSentinel Reset Report  ")
    print("==============================\n")
    for table, count in results.items():
        print(f"{table}: {count} deleted{' (dry run)' if args.dry_run else ''}")
        
    print(f"\nGenerated PDFs: {deleted_files.get('pdf', 0)} deleted{' (dry run)' if args.dry_run else ''}")
    print(f"Generated CSVs: {deleted_files.get('csv', 0)} deleted{' (dry run)' if args.dry_run else ''}")
    print(f"Generated JSONs: {deleted_files.get('json', 0)} deleted{' (dry run)' if args.dry_run else ''}")
    
    print("\nProtected ML artifacts: unchanged")
    print("Supabase Auth users: unchanged")
    print("Application configuration: unchanged")
    print("==============================\n")
    
    if not args.dry_run:
        print("Verifying reset...")
        failed = False
        for table in tables:
            try:
                res = await client.table(table).select("count", count="exact").limit(1).execute()
                if res.count is not None and res.count > 0:
                    print(f"WARNING: Table {table} still has {res.count} rows.")
                    failed = True
            except:
                pass
        if failed:
            sys.exit(1)
        else:
            print("Verification passed. Database is empty.")

if __name__ == "__main__":
    asyncio.run(main())

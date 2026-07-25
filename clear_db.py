import asyncio
import os
import sys

# Add current directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database.client import init_db

async def main():
    client = await init_db()
    
    # Use a dummy UUID
    dummy_uuid = "00000000-0000-0000-0000-000000000000"
    
    print("Clearing packets...")
    await client.table("packets").delete().neq("id", dummy_uuid).execute()
    
    print("Clearing threat_alerts...")
    try:
        await client.table("threat_alerts").delete().neq("alert_id", dummy_uuid).execute()
    except Exception as e:
        print(f"Error clearing threat_alerts: {e}")
        try:
            await client.table("threat_alerts").delete().neq("id", dummy_uuid).execute()
        except:
            pass
            
    print("Clearing threat_scores...")
    await client.table("threat_scores").delete().neq("id", dummy_uuid).execute()
    
    print("Clearing ip_intelligence...")
    await client.table("ip_intelligence").delete().neq("ip_address", "0.0.0.0").execute()
    
    print("Clearing firewall_actions...")
    await client.table("firewall_actions").delete().neq("id", dummy_uuid).execute()

    print("Database cleared!")

if __name__ == "__main__":
    asyncio.run(main())

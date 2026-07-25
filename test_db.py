import asyncio
import os
import sys

# Add current directory to path so we can import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database.client import init_db, get_db_client

async def main():
    try:
        await init_db()
        db = await get_db_client()
        result = await db.table("packets").select("id", count="exact").execute()
        print(f"Total packets in DB: {result.count}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())

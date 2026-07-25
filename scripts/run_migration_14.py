import asyncio
import asyncpg
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

async def main():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not found. Please set DATABASE_URL environment variable.")
        print("Example: export DATABASE_URL='postgres://postgres:password@db.jivareuzlvircwzthtrd.supabase.co:5432/postgres'")
        return

    sql_path = Path("scripts/migrate_phase14.sql")
    sql = sql_path.read_text()

    conn = await asyncpg.connect(db_url)
    try:
        await conn.execute(sql)
        print("Stage 14 Migration executed successfully.")
    except Exception as e:
        print(f"Error executing migration: {e}")
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(main())

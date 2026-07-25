import asyncio
import asyncpg
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

async def main():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not found")
        return

    sql_path = Path("scripts/migrate_phase11.sql")
    sql = sql_path.read_text()

    conn = await asyncpg.connect(db_url)
    try:
        await conn.execute(sql)
        print("Migration executed successfully.")
    except Exception as e:
        print(f"Error executing migration: {e}")
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(main())

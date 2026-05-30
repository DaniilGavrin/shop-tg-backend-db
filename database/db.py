# database/db.py
import asyncpg
import os

DATABASE_URL = os.getenv("DATABASE_URL")
print(f'DATABASE_URL: {DATABASE_URL}')

class Database:
    def __init__(self):
        self.pool = None

    async def connect(self):
        if not self.pool:
            self.pool = await asyncpg.create_pool(
                dsn=DATABASE_URL,
                min_size=1,
                max_size=10,
                ssl="require"
            )
            print("✅ PostgreSQL pool created")

    async def disconnect(self):
        if self.pool:
            await self.pool.close()
            print("🔌 PostgreSQL pool closed")

    async def execute(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def upsert_telegram_user(
        self,
        tg_id: int,
        first_name: str,
        username: str | None = None,
        last_name: str | None = None,
        phone: str | None = None
    ):
        """
        Вставляет нового пользователя или обновляет существующего.
        last_seen обновляется всегда. NULL-значения не затирают старые данные.
        """
        query = """
            INSERT INTO users (
                tg_id, first_name, username, last_name, phone, email
            ) VALUES ($1, $2, $3, $4, $5, '')
            ON CONFLICT (tg_id) DO UPDATE
            SET 
                last_seen = NOW(),
                username = COALESCE(EXCLUDED.username, users.username),
                last_name = COALESCE(EXCLUDED.last_name, users.last_name),
                phone = COALESCE(EXCLUDED.phone, users.phone)
        """
        await self.execute(
            query,
            tg_id, first_name, username, last_name, phone
        )

db = Database()
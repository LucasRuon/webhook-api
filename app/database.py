import aiosqlite
import json
import os

DB_PATH = os.getenv("DB_PATH", "data/webhooks.db")


async def get_db() -> aiosqlite.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                fields_schema TEXT DEFAULT '[]',
                secret TEXT DEFAULT '',
                target_url TEXT DEFAULT '',
                rabbit_queue TEXT DEFAULT '',
                rabbit_exchange TEXT DEFAULT '',
                rabbit_routing_key TEXT DEFAULT '',
                rabbit_enabled INTEGER DEFAULT 0,
                rabbit_filter TEXT DEFAULT '[]',
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS webhook_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('in', 'out')),
                headers TEXT DEFAULT '{}',
                payload TEXT DEFAULT '{}',
                extracted_fields TEXT DEFAULT '{}',
                response_status INTEGER,
                response_body TEXT,
                rabbit_published INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (channel_id) REFERENCES channels (id)
            );

            CREATE INDEX IF NOT EXISTS idx_logs_created ON webhook_logs(created_at);
        """)
        await db.commit()

        # Migração: adiciona novas colunas se tabela já existia
        migrations = [
            ("channels", "rabbit_queue", "TEXT DEFAULT ''"),
            ("channels", "rabbit_exchange", "TEXT DEFAULT ''"),
            ("channels", "rabbit_routing_key", "TEXT DEFAULT ''"),
            ("channels", "rabbit_enabled", "INTEGER DEFAULT 0"),
            ("channels", "rabbit_filter", "TEXT DEFAULT '[]'"),
            ("webhook_logs", "rabbit_published", "INTEGER DEFAULT 0")
        ]
        
        for table, col, spec in migrations:
            try:
                await db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {spec}")
                await db.commit()
            except Exception:
                pass

    finally:
        await db.close()

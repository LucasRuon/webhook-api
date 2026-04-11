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
                response_body TEXT DEFAULT '',
                rabbit_published INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (channel_id) REFERENCES channels(id)
            );

            CREATE INDEX IF NOT EXISTS idx_logs_channel ON webhook_logs(channel_id);
            CREATE INDEX IF NOT EXISTS idx_logs_created ON webhook_logs(created_at);
        """)
        await db.commit()

        # Migração: adiciona colunas rabbit se tabela já existia
        try:
            await db.execute("ALTER TABLE channels ADD COLUMN rabbit_queue TEXT DEFAULT ''")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE channels ADD COLUMN rabbit_exchange TEXT DEFAULT ''")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE channels ADD COLUMN rabbit_routing_key TEXT DEFAULT ''")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE channels ADD COLUMN rabbit_enabled INTEGER DEFAULT 0")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE webhook_logs ADD COLUMN rabbit_published INTEGER DEFAULT 0")
            await db.commit()
        except Exception:
            pass

    finally:
        await db.close()

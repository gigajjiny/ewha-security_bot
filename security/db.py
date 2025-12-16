# security/db.py

import aiosqlite
from datetime import datetime
from typing import Optional

async def init_db(db_path: str):
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                channel_id INTEGER,
                message_id INTEGER,
                user_id INTEGER,
                username TEXT,
                content TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                channel_id INTEGER,
                message_id INTEGER,
                user_id INTEGER,
                event_type TEXT,
                detail TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                channel_id INTEGER,
                message_id INTEGER,
                user_id INTEGER,
                target_type TEXT,   -- 'url' or 'file'
                target_value TEXT,  -- 'url' or 'file'
                is_malicious INTEGER,
                reason TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT UNIQUE,
                filename TEXT,
                reason TEXT,
                created_at TEXT
            );
            """
        )
        await db.commit()


# 호환성 패치 : int | None -> Optional[int]
async def log_message(db_path: str, guild_id: Optional[int], channel_id: int, message_id: int,
                      user_id: int, username: str, content: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO messages (guild_id, channel_id, message_id, user_id, username, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (guild_id, channel_id, message_id, user_id, username, content, datetime.utcnow().isoformat())
        )
        await db.commit()

async def log_event(db_path: str, guild_id: Optional[int], channel_id: int, message_id: int, user_id: int, event_type: str, detail: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO events (guild_id, channel_id, message_id, user_id, event_type, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (guild_id, channel_id, message_id, user_id, event_type, detail, datetime.utcnow().isoformat())
        )
        await db.commit()

async def log_scan_result(db_path: str, guild_id: Optional[int], channel_id: int, message_id: Optional[int],
                          user_id: Optional[int], target_type: str, target_value: str,
                          is_malicious: bool, reason: str):
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO scans (guild_id, channel_id, message_id, user_id, target_type, target_value, is_malicious, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (guild_id, channel_id, message_id, user_id, target_type, target_value, 1 if is_malicious else 0, reason, datetime.utcnow().isoformat())
        )
        await db.commit()

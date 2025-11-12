import sqlite3
from typing import Optional, Dict
import config

def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            mode TEXT NOT NULL,
            salt TEXT,
            hash TEXT,
            token TEXT,
            consent INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_state (
            k TEXT PRIMARY KEY,
            v TEXT
        )
    """)
    return conn

# ---------- Users ----------
def save_user_record(username: str, record: Dict[str, str]) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, mode, salt, hash, token) VALUES (?,?,?,?,?)",
            (
                username,
                record.get("mode"),
                record.get("salt"),
                record.get("hash"),
                record.get("token"),
            ),
        )

def get_user_record(username: str) -> Optional[Dict[str, str]]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT mode, salt, hash, token FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row:
        return None
    mode, salt, hash_, token = row
    rec = {"mode": mode}
    if mode == "HASH":
        rec["salt"] = salt
        rec["hash"] = hash_
    elif mode == "FERNET":
        rec["token"] = token
    return rec

def user_exists(username: str) -> bool:
    with _conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    return bool(row)

# ---------- App state (lembrar último utilizador) ----------
def set_last_user(username: str) -> None:
    with _conn() as conn:
        conn.execute("INSERT OR REPLACE INTO app_state (k, v) VALUES ('last_user', ?)", (username,))

def get_last_user() -> Optional[str]:
    with _conn() as conn:
        row = conn.execute("SELECT v FROM app_state WHERE k = 'last_user'").fetchone()
    return row[0] if row else None
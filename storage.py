import sqlite3
from typing import Optional, Dict
import config
import os, shutil, time
from datetime import datetime, timezone
import warnings, traceback

# Name of the fallback audit file (used when DB writes fail)
AUDIT_FALLBACK_FILENAME = 'audit_fallback.log'

def get_audit_fallback_path() -> str:
    """Return the path to the audit fallback file, ensuring the directory exists."""
    fallback_dir = config.BACKUP_DIR or '.'
    try:
        os.makedirs(fallback_dir, exist_ok=True)
    except Exception:
        # ignore directory creation errors; joining will still produce a path
        pass
    return os.path.join(fallback_dir, AUDIT_FALLBACK_FILENAME)

def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            mode TEXT NOT NULL,
            salt TEXT,
            hash TEXT,
            token TEXT,
            consent INTEGER DEFAULT 0,
            consent_ts TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_state (
            k TEXT PRIMARY KEY,
            v TEXT
        )
    """)
    # Audit logs for incidents and important events
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT,
            event_type TEXT NOT NULL,
            details TEXT
        )
    """)
    # Migration: ensure new columns exist for older DBs (ALTER TABLE is safe in sqlite)
    try:
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {row[1] for row in cur}
        # desired columns added in recent changes
        migrations = {
            "consent_ts": "TEXT",
            "failed_attempts": "INTEGER DEFAULT 0",
            "locked_until": "INTEGER",
        }
        for col, col_def in migrations.items():
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
    except Exception as e:
        # Record migration failure for observability. We avoid calling
        # add_audit_log() here because that uses _conn() and would recurse.
        tb = traceback.format_exc()
        try:
            # attempt to write directly into audit_logs table using this conn
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    datetime.now(timezone.utc).isoformat(), None, 'migration_failed', str(e)
                ))
            except Exception:
                # if inserting into audit_logs fails, write a fallback file
                fallback_dir = config.BACKUP_DIR or '.'
                os.makedirs(fallback_dir, exist_ok=True)
                fallback_path = os.path.join(fallback_dir, 'migration_fallback.log')
                with open(fallback_path, 'a', encoding='utf-8') as f:
                    f.write(f"{datetime.now(timezone.utc).isoformat()} | migration_failed | error={e} | tb={tb}\n")
        except Exception:
            # give up but emit a developer warning so issues are visible during testing
            warnings.warn(f"DB migration failed and fallback logging also failed: {e}")
    return conn


def _ensure_column(conn, col: str, col_def: str) -> None:
    """Ensure a single column exists in users table; add it if missing."""
    try:
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing = {row[1] for row in cur}
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
    except Exception:
        # don't raise here; caller will handle
        pass

# ---------- Users ----------
def save_user_record(username: str, record: Dict[str, str]) -> None:
    with _conn() as conn:
        # defensively ensure columns exist before modifying (fix older DBs missing new columns)
        _ensure_column(conn, "consent_ts", "TEXT")
        _ensure_column(conn, "failed_attempts", "INTEGER DEFAULT 0")
        _ensure_column(conn, "locked_until", "INTEGER")

        # read current schema
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {row[1] for row in cur}

        # normalize provided record keys and types
        provided = {}
        for k, v in record.items():
            if k not in existing_cols:
                continue
            if k == "consent":
                try:
                    provided[k] = int(v)
                except Exception:
                    provided[k] = 1 if v else 0
            elif k == "failed_attempts":
                try:
                    provided[k] = int(v)
                except Exception:
                    provided[k] = 0
            else:
                provided[k] = v

        # Always include mode when inserting a new user
        provided_for_insert = provided.copy()
        if "mode" not in provided_for_insert:
            provided_for_insert.setdefault("mode", record.get("mode"))

        # determine if user exists
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            # perform partial update: only update columns explicitly provided in 'record'
            if provided:
                set_cols = [f"{c} = ?" for c in provided.keys()]
                sql = f"UPDATE users SET {', '.join(set_cols)} WHERE username = ?"
                vals = list(provided.values()) + [username]
                conn.execute(sql, tuple(vals))
            # if nothing provided, do nothing (preserve existing row)
            return
        else:
            # insert new row: include username plus any provided columns (DB will use defaults for omitted ones)
            insert_cols = ["username"] + [c for c in provided_for_insert.keys() if c in existing_cols]
            insert_vals = [username] + [provided_for_insert[c] for c in provided_for_insert.keys() if c in existing_cols]
            placeholders = ",".join(["?" for _ in insert_cols])
            sql = f"INSERT INTO users ({','.join(insert_cols)}) VALUES ({placeholders})"
            conn.execute(sql, tuple(insert_vals))

def get_user_record(username: str) -> Optional[Dict[str, str]]:
    with _conn() as conn:
        # ensure possible columns exist to avoid 'no such column' errors
        _ensure_column(conn, "consent_ts", "TEXT")
        _ensure_column(conn, "failed_attempts", "INTEGER DEFAULT 0")
        _ensure_column(conn, "locked_until", "INTEGER")

        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {row[1] for row in cur}
        select_cols = [c for c in ["mode", "salt", "hash", "token", "consent", "consent_ts", "failed_attempts", "locked_until"] if c in existing_cols]
        if not select_cols:
            return None
        sql = f"SELECT {','.join(select_cols)} FROM users WHERE username = ?"
        row = conn.execute(sql, (username,)).fetchone()
        if not row:
            return None
        rec = {}
        for idx, col in enumerate(select_cols):
            rec[col] = row[idx]
    # normalize some fields and provide defaults
    rec.setdefault("mode", None)
    rec.setdefault("consent", 0)
    rec.setdefault("consent_ts", None)
    rec.setdefault("failed_attempts", 0)
    rec.setdefault("locked_until", None)
    # convert types
    try:
        rec["consent"] = bool(int(rec.get("consent") or 0))
    except Exception:
        rec["consent"] = bool(rec.get("consent"))
    try:
        rec["failed_attempts"] = int(rec.get("failed_attempts") or 0)
    except Exception:
        rec["failed_attempts"] = 0
    return rec


def is_admin(username: str) -> bool:
    # Demo/backdoor policy: only the configured BACKDOOR_ADMIN_USER is treated
    # as an admin. This ignores any admin flags stored in the DB to ensure the
    # environment has only a single admin account (useful for classroom demos).
    try:
        if username == config.BACKDOOR_ADMIN_USER:
            return True
    except Exception:
        pass
    # otherwise no admin privileges
    return False

def user_exists(username: str) -> bool:
    with _conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    return bool(row)

# ---------- GDPR / account management helpers ----------
def delete_user_record(username: str) -> None:
    with _conn() as conn:
        try:
            if config.SECURE_DELETE_OVERWRITE:
                # overwrite sensitive fields with random data before deletion
                try:
                    import os, base64
                    rand_salt = base64.b64encode(os.urandom(16)).decode('utf-8')
                    rand_hash = base64.b64encode(os.urandom(32)).decode('utf-8')
                    rand_token = base64.b64encode(os.urandom(32)).decode('utf-8')
                    conn.execute("UPDATE users SET salt = ?, hash = ?, token = ? WHERE username = ?", (rand_salt, rand_hash, rand_token, username))
                except Exception:
                    pass
            # delete the user row
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            # clear last_user if matches
            conn.execute("DELETE FROM app_state WHERE k = 'last_user' AND v = ?", (username,))
            # optional VACUUM to try to remove remnants (may be slow)
            try:
                if config.SECURE_DELETE_VACUUM:
                    conn.execute("VACUUM")
            except Exception:
                pass
            # log deletion
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'account_deleted', None
                ))
            except Exception:
                pass
        except Exception:
            # best-effort: attempt to log failure
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'account_delete_failed', None
                ))
            except Exception:
                pass

def export_user_record(username: str, include_secrets: bool = False) -> Optional[Dict[str, str]]:
    """Export a user's data for portability requests.

    By default `include_secrets` is False and credential material (salt/hash/token)
    is excluded from the export to avoid creating a sensitive artifact. If the
    caller explicitly requests `include_secrets=True` the stored credential
    material will be included (use with caution).
    """
    rec = get_user_record(username)
    if not rec:
        return None
    export = {"username": username, "mode": rec.get("mode"), "consent": rec.get("consent"), "consent_ts": rec.get("consent_ts")}
    if include_secrets:
        # include underlying credential material only when explicitly requested
        # This application stores only HASH-style credentials (salt/hash).
        export.update({"salt": rec.get("salt"), "hash": rec.get("hash")})
    return export


def set_consent(username: str, consent: bool) -> None:
    """Set the consent flag and timestamp for a user."""
    with _conn() as conn:
        try:
            _ensure_column(conn, "consent_ts", "TEXT")
            val = 1 if consent else 0
            ts = __now_iso() if consent else None
            # update only existing user
            conn.execute("UPDATE users SET consent = ?, consent_ts = ? WHERE username = ?", (val, ts, username))
            # log consent
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'consent_given' if consent else 'consent_revoked', None
                ))
            except Exception:
                pass
        except Exception:
            # best-effort
            pass


def __now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def add_audit_log(username: str, event_type: str, details: Optional[str] = None) -> bool:
    """Append an audit log entry to the audit_logs table.

    Returns True on success. On failure, the function writes a fallback log
    entry to a file in `config.BACKUP_DIR` named `audit_fallback.log` and
    returns False. This keeps audit information available for post-mortem
    if the database write fails.
    """
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                __now_iso(), username, event_type, details
            ))
        return True
    except Exception as e:
        # best-effort fallback: write a plain-text entry to a fallback file
        try:
            fallback_path = get_audit_fallback_path()
            with open(fallback_path, 'a', encoding='utf-8') as f:
                f.write(f"{__now_iso()} | {username or '-'} | {event_type} | {details or ''} | error={e}\n")
        except Exception:
            # if even fallback writing fails, give up but don't raise
            pass
        return False


def safe_add_audit_log(username: str, event_type: str, details: Optional[str] = None):
    """Wrapper around add_audit_log that returns a tuple (ok, fallback_path).

    - ok: bool indicating whether the DB write succeeded.
    - fallback_path: path to the fallback file if ok is False, otherwise None.
    """
    try:
        ok = add_audit_log(username, event_type, details)
        if ok:
            return True, None
        return False, get_audit_fallback_path()
    except Exception:
        # If add_audit_log itself raised, return False and a fallback path
        try:
            return False, get_audit_fallback_path()
        except Exception:
            return False, None


def db_integrity_check() -> str:
    """Run PRAGMA integrity_check and return the result (first row or joined rows)."""
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            cur = conn.execute("PRAGMA integrity_check;")
            rows = [r[0] for r in cur.fetchall()]
        if not rows:
            return "no-result"
        return "; ".join(rows)
    except Exception as e:
        return f"error: {e}"


def backup_database(dest_dir: Optional[str] = None) -> Optional[str]:
    """Create an online backup of the SQLite database. Returns path to backup file on success, None on failure."""
    dest_dir = dest_dir or config.BACKUP_DIR
    try:
        os.makedirs(dest_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = os.path.basename(config.DB_PATH)
        dest_path = os.path.join(dest_dir, f"{base}.{ts}.backup")

        # Prefer sqlite3 Online Backup API
        try:
            src_conn = sqlite3.connect(config.DB_PATH)
            dest_conn = sqlite3.connect(dest_path)
            with dest_conn:
                src_conn.backup(dest_conn)
            dest_conn.close()
            src_conn.close()
        except Exception:
            # fallback to file copy (best-effort)
            shutil.copy2(config.DB_PATH, dest_path)

        # cleanup old backups (keep last N)
        try:
            files = [os.path.join(dest_dir, f) for f in os.listdir(dest_dir) if f.startswith(base) and f.endswith('.backup')]
            files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            for old in files[config.BACKUP_RETENTION:]:
                try:
                    os.remove(old)
                except Exception:
                    pass
        except Exception:
            pass

        # audit log
        # Optional backup encryption using Fernet (cryptography). If
        # BACKUP_ENCRYPT is True we attempt to encrypt the created backup
        # file with the key at config.KEY_FILE. If encryption fails (missing
        # package, key error) we fall back to leaving the plain backup and
        # record an audit event.
        try:
            if getattr(config, 'BACKUP_ENCRYPT', False):
                try:
                    from cryptography.fernet import Fernet
                except Exception:
                    # cryptography not available; record and continue with plain backup
                    try:
                        safe_add_audit_log('', 'backup_encrypt_unavailable', 'cryptography package missing')
                    except Exception:
                        pass
                else:
                    # ensure key file exists; create with secure permissions if missing
                    try:
                        key_path = config.KEY_FILE
                        key_dir = os.path.dirname(key_path) or '.'
                        os.makedirs(key_dir, exist_ok=True)
                        if not os.path.exists(key_path):
                            k = Fernet.generate_key()
                            with open(key_path, 'wb') as kf:
                                kf.write(k)
                            try:
                                if os.name == 'posix':
                                    os.chmod(key_path, 0o600)
                            except Exception:
                                pass
                        with open(key_path, 'rb') as kf:
                            key = kf.read()
                        fernet = Fernet(key)
                        with open(dest_path, 'rb') as f:
                            data = f.read()
                        enc_path = dest_path + '.enc'
                        with open(enc_path, 'wb') as ef:
                            ef.write(fernet.encrypt(data))
                        # remove plain backup and use encrypted path
                        try:
                            os.remove(dest_path)
                        except Exception:
                            pass
                        dest_path = enc_path
                        try:
                            safe_add_audit_log('', 'backup_encrypted', f'path={dest_path}')
                        except Exception:
                            pass
                    except Exception as e:
                        # encryption failed; record and continue with plain backup
                        try:
                            safe_add_audit_log('', 'backup_encrypt_failed', f'error={e}')
                        except Exception:
                            pass

        except Exception:
            # be defensive: do not fail backup because of encryption path
            pass

        # try to restrict filesystem permissions on the created backup
        try:
            if config.BACKUP_RESTRICT_PERMISSIONS and dest_path:
                try:
                    import stat
                    if os.name == 'posix':
                        os.chmod(dest_path, 0o600)
                    else:
                        # on Windows set file as read-only as a minimal restriction
                        os.chmod(dest_path, stat.S_IREAD)
                except Exception:
                    pass

        except Exception:
            pass

        # audit log
        try:
            add_audit_log('', 'db_backup', f'path={dest_path}')
        except Exception:
            pass

        return dest_path
    except Exception:
        try:
            add_audit_log('', 'db_backup_failed', None)
        except Exception:
            pass
        return None


def restore_database(src_path: str) -> Optional[str]:
    """Restore the application database from the provided backup file.

    Behavior:
    - Validate the source DB by running PRAGMA integrity_check on it.
    - Create a pre-restore snapshot of the current DB inside BACKUP_DIR so we can roll back if needed.
    - Replace the live DB file with the provided file (file copy).
    - Return the path to the pre-restore snapshot on success, or raise an exception on failure.
    """
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Backup file not found: {src_path}")
    # validate source DB integrity before replacing
    # If the source is an encrypted backup (endswith .enc) and a key is
    # available, attempt to decrypt to a temporary file for validation.
    decrypted_tmp = None
    try:
        to_validate = src_path
        if src_path.endswith('.enc') and getattr(config, 'BACKUP_ENCRYPT', False):
            try:
                from cryptography.fernet import Fernet
                # try to read key and decrypt
                if os.path.exists(config.KEY_FILE):
                    with open(config.KEY_FILE, 'rb') as kf:
                        key = kf.read()
                    fernet = Fernet(key)
                    with open(src_path, 'rb') as f:
                        data = f.read()
                    plain = fernet.decrypt(data)
                    # write decrypted data to a temporary path for validation
                    import tempfile
                    fd, decrypted_tmp = tempfile.mkstemp(suffix='.backup')
                    os.write(fd, plain)
                    os.close(fd)
                    to_validate = decrypted_tmp
                else:
                    raise RuntimeError('Backup is encrypted but KEY_FILE not found')
            except Exception as e:
                # decryption failed or cryptography not available
                try:
                    safe_add_audit_log('', 'backup_decrypt_failed', f'file={src_path}; error={e}')
                except Exception:
                    pass
                raise

        tmp_conn = sqlite3.connect(to_validate)
        cur = tmp_conn.execute("PRAGMA integrity_check;")
        rows = [r[0] for r in cur.fetchall()]
        tmp_conn.close()
        ok = any('ok' in (r or '').lower() for r in rows)
        if not ok:
            raise RuntimeError(f"Source backup failed integrity check: {rows}")
    except sqlite3.DatabaseError as e:
        raise RuntimeError(f"Source file is not a valid sqlite database: {e}")

    # ensure backup dir exists
    dest_dir = config.BACKUP_DIR
    os.makedirs(dest_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(config.DB_PATH)
    pre_path = os.path.join(dest_dir, f"{base}.pre_restore.{ts}.backup")

    try:
        # snapshot current DB first
        try:
            shutil.copy2(config.DB_PATH, pre_path)
        except Exception:
            # if copying fails, still attempt to continue but record None
            pre_path = None

        # replace live DB with provided file
        shutil.copy2(src_path, config.DB_PATH)

        # post-restore integrity check
        try:
            post = db_integrity_check()
        except Exception:
            post = 'integrity-check-failed'

        add_audit_log('', 'db_restore', f'src={src_path}; pre_snapshot={pre_path}; post_integrity={post}')
        return pre_path
    except Exception as e:
        try:
            add_audit_log('', 'db_restore_failed', f'error={e}')
        except Exception:
            pass
        raise


def get_audit_logs(username: Optional[str] = None, limit: int = 200):
    with _conn() as conn:
        if username:
            rows = conn.execute("SELECT ts, username, event_type, details FROM audit_logs WHERE username = ? ORDER BY id DESC LIMIT ?", (username, limit)).fetchall()
        else:
            rows = conn.execute("SELECT ts, username, event_type, details FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(ts=r[0], username=r[1], event_type=r[2], details=r[3]) for r in rows]

# ---------- Login attempt / lockout helpers ----------
def increment_failed_attempts(username: str) -> int:
    with _conn() as conn:
        _ensure_column(conn, "failed_attempts", "INTEGER DEFAULT 0")
        row = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return 0
        try:
            failed = int(row[0] or 0) + 1
        except Exception:
            failed = 1
        conn.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (failed, username))
    return failed

def reset_failed_attempts(username: str) -> None:
    with _conn() as conn:
        _ensure_column(conn, "failed_attempts", "INTEGER DEFAULT 0")
        _ensure_column(conn, "locked_until", "INTEGER")
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))

def set_lockout(username: str, until_ts: int) -> None:
    with _conn() as conn:
        _ensure_column(conn, "locked_until", "INTEGER")
        conn.execute("UPDATE users SET locked_until = ? WHERE username = ?", (until_ts, username))

def get_locked_until(username: str):
    with _conn() as conn:
        _ensure_column(conn, "locked_until", "INTEGER")
        row = conn.execute("SELECT locked_until FROM users WHERE username = ?", (username,)).fetchone()
    return row[0] if row else None

def is_account_locked(username: str, now_ts: int) -> bool:
    lu = get_locked_until(username)
    if lu is None:
        return False
    try:
        return int(lu) > now_ts
    except Exception:
        return False

# ---------- App state (lembrar último utilizador) ----------
def set_last_user(username: str) -> None:
    with _conn() as conn:
        conn.execute("INSERT OR REPLACE INTO app_state (k, v) VALUES ('last_user', ?)", (username,))

def get_last_user() -> Optional[str]:
    with _conn() as conn:
        row = conn.execute("SELECT v FROM app_state WHERE k = 'last_user'").fetchone()
    return row[0] if row else None
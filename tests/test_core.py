import os
import sys
import time
import sqlite3
import pathlib
import pytest

# Make tests runnable both via `pytest` and `python tests/test_core.py` by
# ensuring the project root is on sys.path so imports like `import config`
# resolve when the current working directory is the tests folder.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config
import security
import storage


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Use a temporary DB and backup dir for each test to avoid touching real files."""
    db_path = tmp_path / "test_users.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    # patch config
    monkeypatch.setattr(config, 'DB_PATH', str(db_path))
    monkeypatch.setattr(config, 'BACKUP_DIR', str(backup_dir))
    # ensure backup encryption disabled for tests unless cryptography is available
    monkeypatch.setattr(config, 'BACKUP_ENCRYPT', False)
    # ensure a clean start
    if db_path.exists():
        db_path.unlink()
    yield
    # teardown: remove files if present
    try:
        if db_path.exists():
            db_path.unlink()
    except Exception:
        pass


def create_user(username: str, password: str):
    rec = security.secure_password(password)
    storage.save_user_record(username, rec)
    return rec


def test_hash_and_verify():
    rec = security.secure_password('Abcd1234')
    assert rec.get('mode') == 'HASH'
    assert security.verify_with_record('Abcd1234', rec) is True
    assert security.verify_with_record('wrongpass', rec) is False


def test_consent_export_delete():
    username = 'alice'
    password = 'Password1'
    rec = create_user(username, password)

    # set consent and verify
    storage.set_consent(username, True)
    user = storage.get_user_record(username)
    assert user is not None
    assert user.get('consent') is True
    assert user.get('consent_ts') is not None

    # export without secrets
    exported = storage.export_user_record(username, include_secrets=False)
    assert exported is not None
    assert 'salt' not in exported and 'hash' not in exported

    # export with secrets
    exported2 = storage.export_user_record(username, include_secrets=True)
    assert exported2 is not None
    assert 'salt' in exported2 and 'hash' in exported2

    # delete and ensure gone
    storage.delete_user_record(username)
    assert storage.get_user_record(username) is None


def test_lockout_and_attempts():
    username = 'bob'
    password = 'S3curePwd'
    create_user(username, password)

    # reset attempts
    storage.reset_failed_attempts(username)
    # increment attempts
    val = 0
    for i in range(3):
        val = storage.increment_failed_attempts(username)
    assert val >= 1

    # set lockout and check
    future = int(time.time()) + 60
    storage.set_lockout(username, future)
    assert storage.is_account_locked(username, int(time.time())) is True

    # reset
    storage.reset_failed_attempts(username)
    assert storage.get_locked_until(username) in (None, 0)


def test_audit_logs():
    ok = storage.add_audit_log('tester', 'unit_test', 'details')
    assert ok is True
    rows = storage.get_audit_logs(limit=20)
    assert any(r for r in rows if r.get('event_type') == 'unit_test')

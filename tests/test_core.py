import os
import sys
import time
import sqlite3
import pathlib
import pytest

# Tornar os testes executáveis tanto via `pytest` como `python tests/test_core.py`:
# garantir que a raiz do projeto está em sys.path para que importações como
# `import config` resolvam quando o diretório atual for a pasta dos testes.
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
    # ajustar (monkeypatch) as configurações para um ambiente de teste isolado
    monkeypatch.setattr(config, 'DB_PATH', str(db_path))
    monkeypatch.setattr(config, 'BACKUP_DIR', str(backup_dir))
    # garantir que a encriptação de backup está desativada para os testes
    monkeypatch.setattr(config, 'BACKUP_ENCRYPT', False)
    # garantir um arranque limpo
    if db_path.exists():
        db_path.unlink()
    yield
    # teardown: remover ficheiros se presentes
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

    # definir consentimento e verificar
    storage.set_consent(username, True)
    user = storage.get_user_record(username)
    assert user is not None
    assert user.get('consent') is True
    assert user.get('consent_ts') is not None

    # exportar sem segredos
    exported = storage.export_user_record(username, include_secrets=False)
    assert exported is not None
    assert 'salt' not in exported and 'hash' not in exported

    # exportar com segredos
    exported2 = storage.export_user_record(username, include_secrets=True)
    assert exported2 is not None
    assert 'salt' in exported2 and 'hash' in exported2

    # eliminar e garantir que os dados desapareceram
    storage.delete_user_record(username)
    assert storage.get_user_record(username) is None


def test_lockout_and_attempts():
    username = 'bob'
    password = 'S3curePwd'
    create_user(username, password)

    # reiniciar contador de tentativas
    storage.reset_failed_attempts(username)
    # incrementar tentativas
    val = 0
    for i in range(3):
        val = storage.increment_failed_attempts(username)
    assert val >= 1

    # definir bloqueio e verificar
    future = int(time.time()) + 60
    storage.set_lockout(username, future)
    assert storage.is_account_locked(username, int(time.time())) is True

    # reiniciar
    storage.reset_failed_attempts(username)
    assert storage.get_locked_until(username) in (None, 0)


def test_audit_logs():
    ok = storage.add_audit_log('tester', 'unit_test', 'details')
    assert ok is True
    rows = storage.get_audit_logs(limit=20)
    assert any(r for r in rows if r.get('event_type') == 'unit_test')

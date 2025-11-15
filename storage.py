import sqlite3
from typing import Optional, Dict
import config
import os, shutil, time
from datetime import datetime, timezone
import warnings, traceback

# Nome do ficheiro de fallback para auditoria (quando gravações na BD falham)
AUDIT_FALLBACK_FILENAME = 'audit_fallback.log'

def get_audit_fallback_path() -> str:
    """Devolve o caminho para o ficheiro de fallback de auditoria, garantindo
    que a diretoria existe (melhor-esforço).
    """
    fallback_dir = config.BACKUP_DIR or '.'
    try:
        os.makedirs(fallback_dir, exist_ok=True)
    except Exception:
        # Melhor-esforço: se a criação da diretoria falhar, ainda devolvemos um
        # caminho válido (pode falhar mais tarde ao escrever).
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
    # Tabela de auditoria para incidentes e eventos importantes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT,
            event_type TEXT NOT NULL,
            details TEXT
        )
    """)
    # Migração: garantir que colunas novas existem em BD antigas (ALTER TABLE é
    # seguro no SQLite). Isto permite evoluir o esquema sem quebrar versões.
    try:
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {row[1] for row in cur}
        # Colunas desejadas adicionadas em alterações recentes
        migrations = {
            "consent_ts": "TEXT",
            "failed_attempts": "INTEGER DEFAULT 0",
            "locked_until": "INTEGER",
        }
        for col, col_def in migrations.items():
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
    except Exception as e:
        # Registar falha de migração para observabilidade. Evitamos chamar
        # add_audit_log() aqui porque usa _conn() e provocaria recursão.
        tb = traceback.format_exc()
        try:
            # tentar escrever diretamente na tabela audit_logs usando esta ligação
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    datetime.now(timezone.utc).isoformat(), None, 'migration_failed', str(e)
                ))
            except Exception:
                # se a inserção em audit_logs falhar, escrever num ficheiro de fallback
                fallback_dir = config.BACKUP_DIR or '.'
                os.makedirs(fallback_dir, exist_ok=True)
                fallback_path = os.path.join(fallback_dir, 'migration_fallback.log')
                with open(fallback_path, 'a', encoding='utf-8') as f:
                    f.write(f"{datetime.now(timezone.utc).isoformat()} | migration_failed | error={e} | tb={tb}\n")
        except Exception:
            # desistir e emitir um aviso de desenvolvimento para que o problema
            # seja visível durante os testes
            warnings.warn(f"DB migration failed and fallback logging also failed: {e}")
    return conn


def _ensure_column(conn, col: str, col_def: str) -> None:
    """Assegura que uma coluna existe na tabela `users`; adiciona-a se faltar.

    Função de melhor-esforço: em caso de falha não gera exceção para não
    interromper os fluxos que dependem desta verificação.
    """
    try:
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing = {row[1] for row in cur}
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")
    except Exception:
        # Não propagar erro; o chamador lida com falhas de escrita.
        pass

# ---------- Users ----------
def save_user_record(username: str, record: Dict[str, str]) -> None:
    with _conn() as conn:
        # Garantir que as colunas necessárias existem para BD antigas
        _ensure_column(conn, "consent_ts", "TEXT")
        _ensure_column(conn, "failed_attempts", "INTEGER DEFAULT 0")
        _ensure_column(conn, "locked_until", "INTEGER")

        # Obter esquema atual da tabela para normalizar colunas fornecidas
        cur = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {row[1] for row in cur}

        # Normalizar as chaves/valores recebidos no record conforme o esquema
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

        # Incluir sempre o campo 'mode' ao inserir um novo utilizador
        provided_for_insert = provided.copy()
        if "mode" not in provided_for_insert:
            provided_for_insert.setdefault("mode", record.get("mode"))
        # Determinar se o utilizador já existe
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            # Atualização parcial: atualizar apenas as colunas explicitamente fornecidas
            if provided:
                set_cols = [f"{c} = ?" for c in provided.keys()]
                sql = f"UPDATE users SET {', '.join(set_cols)} WHERE username = ?"
                vals = list(provided.values()) + [username]
                conn.execute(sql, tuple(vals))
            # se nada for fornecido, não alterar (preservar a linha existente)
            return
        else:
            # Inserir nova linha: incluir username e as colunas fornecidas
            # (a BD usa valores por omissão para as que faltam)
            insert_cols = ["username"] + [c for c in provided_for_insert.keys() if c in existing_cols]
            insert_vals = [username] + [provided_for_insert[c] for c in provided_for_insert.keys() if c in existing_cols]
            placeholders = ",".join(["?" for _ in insert_cols])
            sql = f"INSERT INTO users ({','.join(insert_cols)}) VALUES ({placeholders})"
            conn.execute(sql, tuple(insert_vals))

def get_user_record(username: str) -> Optional[Dict[str, str]]:
    with _conn() as conn:
        # Garantir colunas para evitar erros 'no such column' em BDs antigas
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
    # Normalizar campos e fornecer defaults
    # Normalizar campos e fornecer valores por omissão
    rec.setdefault("mode", None)
    rec.setdefault("consent", 0)
    rec.setdefault("consent_ts", None)
    rec.setdefault("failed_attempts", 0)
    rec.setdefault("locked_until", None)
    # Conversões de tipo defensivas
    # Conversões de tipo defensivas
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
    # Política demo/backdoor: apenas o BACKDOOR_ADMIN_USER configurado é tratado
    # como administrador. Ignora flags de admin na BD para garantir apenas uma
    # conta administrativa (útil em demonstrações/classes).
    # Política demo/backdoor: apenas o BACKDOOR_ADMIN_USER configurado é
    # tratado como administrador. Ignora flags de admin na BD para garantir uma
    # única conta administrativa (útil em demonstrações/classes).
    try:
        if username == config.BACKDOOR_ADMIN_USER:
            return True
    except Exception:
        pass
    # caso contrário sem privilégios de administrador
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
                # Sobrepor campos sensíveis com dados aleatórios antes de apagar
                # Sobrepor campos sensíveis com dados aleatórios antes de apagar
                try:
                    import os, base64
                    rand_salt = base64.b64encode(os.urandom(16)).decode('utf-8')
                    rand_hash = base64.b64encode(os.urandom(32)).decode('utf-8')
                    rand_token = base64.b64encode(os.urandom(32)).decode('utf-8')
                    conn.execute("UPDATE users SET salt = ?, hash = ?, token = ? WHERE username = ?", (rand_salt, rand_hash, rand_token, username))
                except Exception:
                    pass
                # Apagar a linha do utilizador
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            # Limpar last_user se coincidir
            conn.execute("DELETE FROM app_state WHERE k = 'last_user' AND v = ?", (username,))
            # VACUUM opcional para tentar remover vestígios (pode ser lento)
            try:
                if config.SECURE_DELETE_VACUUM:
                    conn.execute("VACUUM")
            except Exception:
                pass
            # Registar eliminação
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'account_deleted', None
                ))
            except Exception:
                pass
        except Exception:
            # tentar em melhor-esforço registar a falha
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'account_delete_failed', None
                ))
            except Exception:
                pass

def export_user_record(username: str, include_secrets: bool = False) -> Optional[Dict[str, str]]:
    """Exportar os dados de um utilizador para pedidos de portabilidade.

    Por defeito `include_secrets` é False e o material credencial (salt/hash/token)
    é excluído do export para evitar criar artefactos sensíveis. Se o chamador
    pedir explicitamente `include_secrets=True`, o material das credenciais será
    incluído (usar com cautela).
    """
    rec = get_user_record(username)
    if not rec:
        return None
    export = {"username": username, "mode": rec.get("mode"), "consent": rec.get("consent"), "consent_ts": rec.get("consent_ts")}
    if include_secrets:
        # Incluir material de credenciais apenas quando explicitamente pedido.
        # Esta aplicação armazena apenas credenciais no formato HASH (salt/hash).
        export.update({"salt": rec.get("salt"), "hash": rec.get("hash")})
    return export


def set_consent(username: str, consent: bool) -> None:
    """Definir o indicador de consentimento e o timestamp para um utilizador."""
    with _conn() as conn:
        try:
            _ensure_column(conn, "consent_ts", "TEXT")
            val = 1 if consent else 0
            ts = __now_iso() if consent else None
            # Atualizar apenas utilizador existente
            conn.execute("UPDATE users SET consent = ?, consent_ts = ? WHERE username = ?", (val, ts, username))
            # Registar consentimento
            try:
                conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                    __now_iso(), username, 'consent_given' if consent else 'consent_revoked', None
                ))
            except Exception:
                pass
        except Exception:
            # melhor-esforço
            pass


def __now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def add_audit_log(username: str, event_type: str, details: Optional[str] = None) -> bool:
    """Acrescenta uma entrada de auditoria na tabela `audit_logs`.

    Retorna True em caso de sucesso. Em falha, escreve uma entrada de fallback
    num ficheiro em `config.BACKUP_DIR` chamado `audit_fallback.log` e retorna
    False. Isto mantém informação de auditoria disponível para análise posterior
    caso a gravação na BD falhe.
    """
    try:
        with _conn() as conn:
            conn.execute("INSERT INTO audit_logs (ts, username, event_type, details) VALUES (?,?,?,?)", (
                __now_iso(), username, event_type, details
            ))
        return True
    except Exception as e:
        # Fallback em melhor-esforço: escrever uma entrada em texto simples num ficheiro
        try:
            fallback_path = get_audit_fallback_path()
            with open(fallback_path, 'a', encoding='utf-8') as f:
                f.write(f"{__now_iso()} | {username or '-'} | {event_type} | {details or ''} | error={e}\n")
        except Exception:
            # se mesmo o fallback falhar, desistir sem lançar
            pass
        return False


def safe_add_audit_log(username: str, event_type: str, details: Optional[str] = None):
    """Envoltorio para add_audit_log que devolve (ok, fallback_path).

    - ok: bool indicando se a escrita na BD teve sucesso.
    - fallback_path: caminho para o ficheiro de fallback caso ok seja False,
      caso contrário None.
    """
    try:
        ok = add_audit_log(username, event_type, details)
        if ok:
            return True, None
        return False, get_audit_fallback_path()
    except Exception:
        # Se add_audit_log lançou, devolver False e o caminho de fallback
        try:
            return False, get_audit_fallback_path()
        except Exception:
            return False, None


def db_integrity_check() -> str:
    """Executa PRAGMA integrity_check e devolve o resultado (linha(s) retornada(s))."""
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
    """Criar um backup online da base de dados SQLite.

    Retorna o caminho para o ficheiro de backup em caso de sucesso, ou None em
    caso de falha.
    """
    dest_dir = dest_dir or config.BACKUP_DIR
    try:
        os.makedirs(dest_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = os.path.basename(config.DB_PATH)
        dest_path = os.path.join(dest_dir, f"{base}.{ts}.backup")

    # Preferir a API de Backup Online do sqlite3
    # Preferir a API de Backup Online do sqlite3
        try:
            src_conn = sqlite3.connect(config.DB_PATH)
            dest_conn = sqlite3.connect(dest_path)
            with dest_conn:
                src_conn.backup(dest_conn)
            dest_conn.close()
            src_conn.close()
        except Exception:
            # Recuo: copiar ficheiro como fallback (melhor-esforço)
            shutil.copy2(config.DB_PATH, dest_path)

    # limpeza de backups antigos (manter os últimos N)
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

        # Auditoria: encriptação opcional do backup usando Fernet (cryptography).
        # Se BACKUP_ENCRYPT for True, tentamos encriptar o ficheiro de backup
        # com a chave em config.KEY_FILE. Em falha regressamos ao backup não
        # encriptado e registamos o evento.
        try:
            if getattr(config, 'BACKUP_ENCRYPT', False):
                try:
                    from cryptography.fernet import Fernet
                except Exception:
                    # Se o pacote cryptography não estiver disponível, registar e
                    # continuar com o backup sem encriptação
                    try:
                        safe_add_audit_log('', 'backup_encrypt_unavailable', 'cryptography package missing')
                    except Exception:
                        pass
                else:
                    # garantir que o ficheiro de chave existe; criar com permissões
                    # restritas se faltar
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
                        # remover o backup em claro e usar o caminho encriptado
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
                        # Encriptação falhou; registar e continuar com backup em claro
                        try:
                            safe_add_audit_log('', 'backup_encrypt_failed', f'error={e}')
                        except Exception:
                            pass

        except Exception:
            # Ser defensivo: não falhar o backup por causa da etapa de encriptação
            pass
            pass

        # Tentar restringir permissões do ficheiro de backup (melhor-esforço)
        # Tentar restringir permissões do ficheiro de backup (melhor-esforço)
        try:
            if config.BACKUP_RESTRICT_PERMISSIONS and dest_path:
                try:
                    import stat
                    if os.name == 'posix':
                        os.chmod(dest_path, 0o600)
                    else:
                        # No Windows marcar o ficheiro como somente-leitura como
                        # restrição mínima
                        # No Windows marcar o ficheiro como somente-leitura como
                        # restrição mínima
                        os.chmod(dest_path, stat.S_IREAD)
                except Exception:
                    pass

        except Exception:
            pass

    # Registo de auditoria
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
    """Restaurar a base de dados a partir do ficheiro de backup indicado.

    Valida a fonte (PRAGMA integrity_check), faz um snapshot pré-restauro e
    substitui o ficheiro ativo. Em caso de backup encriptado (.enc) tenta
    desencriptar usando a chave em config.KEY_FILE para validar.
    """
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Backup file not found: {src_path}")

    # Preparar ficheiro para validação (desencriptar se necessário)
    decrypted_tmp = None
    to_validate = src_path
    try:
        if src_path.endswith('.enc') and getattr(config, 'BACKUP_ENCRYPT', False):
            try:
                from cryptography.fernet import Fernet
                if os.path.exists(config.KEY_FILE):
                    with open(config.KEY_FILE, 'rb') as kf:
                        key = kf.read()
                    fernet = Fernet(key)
                    with open(src_path, 'rb') as f:
                        data = f.read()
                    plain = fernet.decrypt(data)
                    # escrever ficheiro temporário para validação
                    import tempfile
                    fd, decrypted_tmp = tempfile.mkstemp(suffix='.backup')
                    os.write(fd, plain)
                    os.close(fd)
                    to_validate = decrypted_tmp
                else:
                    raise RuntimeError('Backup is encrypted but KEY_FILE not found')
            except Exception as e:
                try:
                    safe_add_audit_log('', 'backup_decrypt_failed', f'file={src_path}; error={e}')
                except Exception:
                    pass
                raise

        # Validar integridade do ficheiro a restaurar
        tmp_conn = sqlite3.connect(to_validate)
        cur = tmp_conn.execute("PRAGMA integrity_check;")
        rows = [r[0] for r in cur.fetchall()]
        tmp_conn.close()
        ok = any('ok' in (r or '').lower() for r in rows)
        if not ok:
            raise RuntimeError(f"Source backup failed integrity check: {rows}")
    except sqlite3.DatabaseError as e:
        raise RuntimeError(f"Source file is not a valid sqlite database: {e}")
    finally:
        # garantir remoção do temporário se criado
        if decrypted_tmp and os.path.exists(decrypted_tmp):
            try:
                os.remove(decrypted_tmp)
            except Exception:
                pass

    # Snapshot pré-restauro e substituição do ficheiro
    dest_dir = config.BACKUP_DIR
    os.makedirs(dest_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(config.DB_PATH)
    pre_path = os.path.join(dest_dir, f"{base}.pre_restore.{ts}.backup")

    try:
        try:
            shutil.copy2(config.DB_PATH, pre_path)
        except Exception:
            pre_path = None

        shutil.copy2(src_path, config.DB_PATH)

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

# ---------- Tentativa de login / lockout helpers ----------
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
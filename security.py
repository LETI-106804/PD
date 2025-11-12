import os, base64, hmac
from hashlib import pbkdf2_hmac
from typing import Dict
import config

# ---------- HASH (PBKDF2-HMAC-SHA256) ----------
def _hash_password(password: str):
    salt = os.urandom(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()

def _verify_hash(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(dk, expected)

# ---------- FERNET (encrypt/decrypt) ----------
def _load_or_create_key() -> bytes:
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise RuntimeError("Para usar FERNET instala: pip install cryptography")
    if not os.path.exists(config.KEY_FILE):
        with open(config.KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(config.KEY_FILE, "rb") as f:
        return f.read()

def _get_fernet():
    from cryptography.fernet import Fernet
    return Fernet(_load_or_create_key())

# ---------- API usada pelo GUI ----------
def secure_password(password: str) -> Dict[str, str]:
    """
    Recebe a password em texto simples e devolve um registo seguro:
    - HASH   -> {"mode":"HASH","salt":<b64>,"hash":<b64>}
    - FERNET -> {"mode":"FERNET","token":<b64>}
    """
    if config.SECURITY_MODE == "HASH":
        salt_b64, hash_b64 = _hash_password(password)
        return {"mode": "HASH", "salt": salt_b64, "hash": hash_b64}
    elif config.SECURITY_MODE == "FERNET":
        token = _get_fernet().encrypt(password.encode("utf-8"))
        return {"mode": "FERNET", "token": base64.b64encode(token).decode()}
    else:
        raise ValueError("SECURITY_MODE inválido (usa 'HASH' ou 'FERNET').")

def verify_with_record(password: str, record: Dict[str, str]) -> bool:
    """
    Verifica uma password contra um registo devolvido por secure_password().
    """
    mode = record.get("mode")
    if mode == "HASH":
        return _verify_hash(password, record["salt"], record["hash"])
    if mode == "FERNET":
        from cryptography.fernet import InvalidToken
        try:
            token = base64.b64decode(record["token"])
            clear = _get_fernet().decrypt(token).decode("utf-8")
            return hmac.compare_digest(clear, password)
        except (InvalidToken, KeyError, ValueError):
            return False
    return False
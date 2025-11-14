import os, base64, hmac, json
from hashlib import pbkdf2_hmac
from typing import Dict
import config
from datetime import datetime

# small password strength check to help GDPR/NIS2 compliance (reasonable minimums)
def password_strength_check(password: str) -> None:
    # simple rules: min length 8, mix of letters and numbers
    if len(password) < 8:
        raise RuntimeError("Password too short (min 8 characters).")
    has_digit = any(c.isdigit() for c in password)
    has_alpha = any(c.isalpha() for c in password)
    if not (has_digit and has_alpha):
        raise RuntimeError("Password must contain letters and digits.")

# ---------- HASH (PBKDF2-HMAC-SHA256) ----------
def _hash_password(password: str):
    salt = os.urandom(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, config.PBKDF2_ITER)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()

def _verify_hash(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    # Use the configured PBKDF2 iteration count so verification remains
    # correct if the constant in config.py is changed.
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, config.PBKDF2_ITER)
    return hmac.compare_digest(dk, expected)

# Note: Fernet/encryption support has been removed. This module only supports
# HASH mode (PBKDF2-HMAC-SHA256). If you need encryption later, add a well-
# scoped implementation with explicit key management.

# ---------- API usada pelo GUI ----------
def secure_password(password: str) -> Dict[str, str]:
    """
    Recebe a password em texto simples e devolve um registo seguro:
    - HASH   -> {"mode":"HASH","salt":<b64>,"hash":<b64>}
    - FERNET -> {"mode":"FERNET","token":<b64>}
    """
    # perform a strength check before creating credentials
    password_strength_check(password)

    # Always create a HASH-style credential record.
    salt_b64, hash_b64 = _hash_password(password)
    return {"mode": "HASH", "salt": salt_b64, "hash": hash_b64}

def verify_with_record(password: str, record: Dict[str, str]) -> bool:
    """
    Verifica uma password contra um registo devolvido por secure_password().
    """
    # Only HASH records are supported. If the record does not contain the
    # expected fields, verification fails.
    try:
        return _verify_hash(password, record["salt"], record["hash"])
    except Exception:
        return False
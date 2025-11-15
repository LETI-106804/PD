import os, base64, hmac, json
from hashlib import pbkdf2_hmac
from typing import Dict
import config
from datetime import datetime

# Verificação simples da força da password para apoiar conformidade GDPR/NIS2
def password_strength_check(password: str) -> None:
    # Regras simples: comprimento mínimo 8, mistura de letras e dígitos
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
    # Usar o número de iterações configurado para PBKDF2 para que a
    # verificação permaneça correta caso o valor em config.py mude.
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, config.PBKDF2_ITER)
    return hmac.compare_digest(dk, expected)

# Nota: O suporte a Fernet/encriptação foi removido deste módulo. Aqui
# apenas é suportado o modo HASH (PBKDF2-HMAC-SHA256). Se for necessária
# encriptação no futuro, implementar de forma bem delimitada e com gestão
# explícita de chaves.

# ---------- API usada pelo GUI ----------
def secure_password(password: str) -> Dict[str, str]:
    """
    Recebe a password em texto simples e devolve um registo seguro:
    - HASH   -> {"mode":"HASH","salt":<b64>,"hash":<b64>}
    - FERNET -> {"mode":"FERNET","token":<b64>}
    """
    # Executar verificação de força antes de criar as credenciais
    password_strength_check(password)

    # Criar sempre um registo de credencial no formato HASH.
    salt_b64, hash_b64 = _hash_password(password)
    return {"mode": "HASH", "salt": salt_b64, "hash": hash_b64}

def verify_with_record(password: str, record: Dict[str, str]) -> bool:
    """
    Verifica uma password contra um registo devolvido por secure_password().
    """
    # Apenas registos no formato HASH são suportados. Se o registo não contiver
    # os campos esperados, a verificação falha.
    try:
        return _verify_hash(password, record["salt"], record["hash"])
    except Exception:
        return False
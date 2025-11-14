# Only HASH (PBKDF2) is supported in this simplified codebase.
SECURITY_MODE = "HASH"

# Base de dados SQLite
DB_PATH = "users.db"

# PBKDF2 iterations (HASH mode)
PBKDF2_ITER = 200_000

# Backdoor/admin exception for demo: single admin account
# WARNING: This stores a plaintext backdoor password in code. Only use for
# demonstration/testing in a trusted environment (teacher demo). Remove before
# production.
BACKDOOR_ADMIN_USER = "admin"
BACKDOOR_ADMIN_PASSWORD = "1Q2W3E4R"

# Security / account lockout policy (NIS2 / GDPR helpful hardening)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60  # 5 minutes

# Export directory for data export (default: current working dir)
DATA_EXPORT_DIR = "."
 
# Backup / integrity settings
BACKUP_DIR = "."
BACKUP_RETENTION = 7  # keep last N backups
ENABLE_AUTOMATIC_BACKUP = False

# Backup hardening
# Backup encryption: when True backups will be encrypted with Fernet (AES-128
# in the cryptography library). This requires the `cryptography` package and
# a key file at `KEY_FILE`. Backups are encrypted *after* creation. If
# encryption is enabled but fails (missing package or key issues) the code
# will fall back to an unencrypted backup and append an audit entry.
BACKUP_ENCRYPT = True
# Path to Fernet key used for backup encryption. If the file does not exist
# it will be created automatically on first backup (use secure storage in
# production and rotate keys as needed).
KEY_FILE = "secret.key"

# Try to make backup files permission-restricted (POSIX: 0o600, Windows: read-only)
BACKUP_RESTRICT_PERMISSIONS = True

# run an integrity check on startup (best-effort)
RUN_INTEGRITY_CHECK_ON_START = False
 
# Secure deletion settings
SECURE_DELETE_OVERWRITE = True  # overwrite sensitive fields before delete
SECURE_DELETE_VACUUM = False    # run VACUUM after delete to reduce remnants (may be expensive)
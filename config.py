# Apenas HASH (PBKDF2) é suportado nesta base de código simplificada.
SECURITY_MODE = "HASH"

# Base de dados SQLite
DB_PATH = "users.db"

# PBKDF2 iterations (HASH mode)
PBKDF2_ITER = 200_000

# Backdoor/admin para demonstração: conta única de administrador.
# AVISO: Isto guarda uma password em texto claro no código. Usar apenas para
# demonstração/testes em ambiente confiável (ex.: demonstração docente). Remover
# antes de produção.
BACKDOOR_ADMIN_USER = "admin"
BACKDOOR_ADMIN_PASSWORD = "1Q2W3E4R"

# Política de segurança / bloqueio de conta (endurecimento útil para NIS2/GDPR)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60  # 5 minutes

# Diretoria para exportação de dados (por defeito: diretoria atual)
DATA_EXPORT_DIR = "."
 
# Configurações de backup / integridade
BACKUP_DIR = "."
BACKUP_RETENTION = 7  # keep last N backups
ENABLE_AUTOMATIC_BACKUP = False

# Endurecimento de backups
# Encriptação de backups: se True os backups serão encriptados com Fernet
# (biblioteca cryptography). Requer o pacote `cryptography` e um ficheiro de
# chave em `KEY_FILE`. Os backups são encriptados após a sua criação. Se a
# encriptação estiver ativa mas falhar (pacote ausente ou problemas de chave)
# o código regressa a um backup não encriptado e regista o evento de auditoria.
BACKUP_ENCRYPT = True
# Caminho para a chave Fernet usada na encriptação de backups. Se o ficheiro
# não existir, será criado automaticamente no primeiro backup (usar armazenamento
# seguro em produção e rotacionar chaves conforme necessário).
KEY_FILE = "secret.key"

# Tentar restringir permissões dos ficheiros de backup (POSIX: 0o600,
# Windows: read-only) - melhor-esforço
BACKUP_RESTRICT_PERMISSIONS = True

# Executar uma verificação de integridade ao arranque (melhor-esforço)
RUN_INTEGRITY_CHECK_ON_START = False
 
# Definições para eliminação segura
# Sobrepor campos sensíveis antes de apagar
SECURE_DELETE_OVERWRITE = True
# Executar VACUUM após eliminação para reduzir vestígios (pode ser caro)
SECURE_DELETE_VACUUM = False
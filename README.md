# 📘 Sistema de Autenticação com Privacy by Design

---

## 🤝 Autores
- Número: **106804, 111342, 122635**
- Aluno: **Carlos Correia, Pedro Correia, Rui Andrez**
- Este projeto pode ser acessado no repositório GitHub 'https://github.com/LETI-106804/PD.git'

---

## 📌 Descrição do Projeto
Este projeto implementa um sistema de autenticação desenvolvido com **Tkinter**, **SQLite** e **Python**, seguindo os princípios de **Privacy by Design**, bem como boas práticas alinhadas com requisitos de **NIS2**, **GDPR** e segurança moderna.

Inclui:
- Registo e login seguro  
- Armazenamento seguro de palavras-passe com PBKDF2-HMAC + salt  
- Controlo de consentimento do utilizador  
- Auditoria de eventos de segurança  
- Proteção contra brute-force (lockout automático)  
- Exportação e eliminação segura dos dados do utilizador  
- Backup e verificação de integridade da base de dados  
- Funções administrativas protegidas  

---

## 🛠️ Tecnologias Utilizadas
- Python 3.10+
- SQLite3
- Tkinter
- Hashing PBKDF2-HMAC-SHA256
- JSON

---

## 🔐 Funcionalidades Principais

### ✔ 1. Autenticação Segura
- Passwords nunca são armazenadas em texto simples.
- Hashing forte com PBKDF2 (iterações configuráveis).
- Armazenamento separado de `salt` e `hash`.

### ✔ 2. Consentimento do Utilizador
- O utilizador só pode usar a aplicação após aceitar os Termos e Condições.
- Consentimento e timestamp são guardados na base de dados.
- O utilizador pode revogar ou apagar os seus dados a qualquer momento.

### ✔ 3. Auditoria / Logging
Eventos registados:
- Login com sucesso  
- Tentativas falhadas  
- Bloqueios  
- Alterações de password  
- Exportação / eliminação da conta  
- Backups, restauros e integridade  

Logs são guardados na base de dados e acessíveis **apenas por administradores**.

### ✔ 4. Proteção contra Ataques
- Contador de tentativas falhadas.
- Bloqueio automático após várias falhas.
- Duração de bloqueio configurável.

### ✔ 5. Exportação e Eliminação dos Dados (GDPR)
O utilizador pode:
- Exportar os seus dados em JSON (sem incluir hashes por defeito).
- Eliminar a conta com:
  - Sobrescrita de dados sensíveis
  - Possível operação VACUUM para limpeza profunda

### ✔ 6. Backups e Integridade
Admin pode:
- Fazer backups da BD
- Restaurar versões anteriores
- Executar `PRAGMA integrity_check`

---

## 👮 Privacidade e Segurança (Privacy by Design)

O sistema cumpre os 7 princípios:
1. Proativo, não reativo  
2. Privacidade por defeito  
3. Privacidade incorporada na arquitetura  
4. Funcionalidade total  
5. Proteção de ponta a ponta  
6. Visibilidade e transparência  
7. Foco no utilizador  

---

## 👤 Administração
O administrador pode:
- Ver logs
- Fazer backups
- Restaurar BD
- Verificar integridade

O admin é definido em `config.py`.

---

## 📁 Estrutura de Ficheiros

├── gui_login.py # Interface gráfica
├── storage.py # Base de dados, auditoria, backup, eliminação
├── security.py # Hashing PBKDF2, verificação e regras
├── config.py # Configurações globais
├── users.db # Base de dados (gerada automaticamente)
└── README.md # Este ficheiro

---

## 📦 Exportação dos Dados
Dados exportados:
- Username
- Consentimento
- Timestamp
- (Hash/salt só se solicitado explicitamente)

Formato: **JSON**

---

## 🧽 Eliminação Segura
- Sobrescrita dos campos sensíveis antes de apagar.
- Opcionalmente executado `VACUUM`.

---

## ⚠️ Avisos Importantes
- Este sistema é um **protótipo académico**, não é para produção.  
- Backups devem ser protegidos.  
- A base de dados não é encriptada.

---

## 📚 Termos e Condições (Resumo)
- Recolha mínima de dados.  
- Direito à exportação e eliminação.  
- Consentimento obrigatório.  
- Usado apenas para fins académicos.

(O texto completo está no código em `TERMS_AND_CONDITIONS`.)

---

## ✔️ Estado do Projeto
**Totalmente funcional**, incluindo:
- Hashing PBKDF2  
- Consentimento  
- Auditoria  
- Lockout  
- Exportação e eliminação  
- Backups e integridade  
- UI consistente  

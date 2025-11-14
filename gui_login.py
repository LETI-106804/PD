from tkinter import *
from tkinter import messagebox, filedialog
import security, config, storage
from datetime import datetime, timezone
import time, json, threading, os

TERMS_AND_CONDITIONS = """
TERMOS E CONDIÇÕES DE UTILIZAÇÃO

1. Finalidade da Aplicação
Esta aplicação destina-se exclusivamente a fins académicos, para demonstração de
práticas de Privacidade desde a Conceção (Privacy by Design) e requisitos de
cibersegurança associados a NIS2.

2. Dados Recolhidos
A aplicação recolhe e armazena apenas:
– Nome de utilizador
– Palavra-passe (armazenada de forma irreversível através de hash seguro)
– Estado de consentimento
– Registos técnicos necessários para segurança (tentativas de login, bloqueios, 
  e eventos de auditoria)

Nenhuma outra informação pessoal é solicitada ou recolhida.

3. Tratamento e Armazenamento dos Dados
Os dados são armazenados localmente num ficheiro de base de dados SQLite.
São aplicadas medidas de segurança, incluindo:
– Hash seguro das palavras-passe com salt e PBKDF2
– Registo de eventos de segurança (auditoria)
– Políticas de bloqueio após múltiplas tentativas falhadas
– Minimização de dados e mecanismos de eliminação seguros

4. Utilização dos Dados
Os dados recolhidos são utilizados apenas para:
– Autenticação do utilizador
– Controlo de acessos
– Finalidades de segurança (auditoria, prevenção de abuso)
– Cumprimento dos requisitos do projeto académico

Os dados não são partilhados, transmitidos, vendidos ou utilizados para qualquer 
outra finalidade.

5. Direitos do Utilizador
O utilizador pode, a qualquer momento:
– Consultar os dados que lhe dizem respeito (exportação)
– Eliminar a sua conta, incluindo a remoção segura de dados sensíveis
– Retirar o consentimento (impedindo uso continuado da aplicação)

6. Conservação dos Dados
Os dados são mantidos apenas enquanto a conta existir ou enquanto forem necessários
para garantir a segurança da aplicação. Após eliminação da conta, os dados são
apagados ou sobrescritos de forma segura.

7. Responsabilidade
Esta aplicação é fornecida “tal como está”, sem garantias e apenas para fins de
demonstração académica. Não deve ser utilizada em ambiente real ou para fins
profissionais.

8. Aceitação dos Termos
Ao selecionar “Aceito”, o utilizador confirma:
– Que leu e compreendeu estes Termos
– Que consente o tratamento descrito acima
– Que compreende que a aplicação é um protótipo académico

Se não concordar com estes Termos, deverá selecionar “Recusar” e abandonar a
aplicação.
"""


# ===== Lógica de registo e login (persistente) =====
def register_user(username: str, password: str) -> bool:
    if not username or not password:
        messagebox.showwarning("Registo", "Preencha username e password.")
        return False
    if storage.user_exists(username):
        messagebox.showwarning("Registo", "Username já existe.")
        return False
    try:
        record = security.secure_password(password)  # proteção feita no ficheiro de segurança
    except RuntimeError:
        # password_strength_check may raise RuntimeError with internal details;
        # present a clearer, non-technical message to the user.
        messagebox.showerror("Registo", "Password inválida. A password deve ter pelo menos 8 caracteres e incluir letras e números.")
        return False
    # save credentials first, then centralize consent handling via storage API
    storage.save_user_record(username, record)
    try:
        storage.set_consent(username, True)
    except Exception:
        # best-effort: don't fail registration if consent recording fails
        pass
    return True

def check_login(username: str, password: str) -> bool:
    # Backdoor admin: allow the configured BACKDOOR_ADMIN_USER to authenticate
    # with the BACKDOOR_ADMIN_PASSWORD regardless of DB state (demo only).
    try:
        if username == config.BACKDOOR_ADMIN_USER and password == config.BACKDOOR_ADMIN_PASSWORD:
            return True
    except Exception:
        pass
    rec = storage.get_user_record(username)
    if not rec:
        return False
    return security.verify_with_record(password, rec)

# ===== Navegação =====
def show_login(main_frame, consent_frame):
    consent_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)

def show_consent(consent_frame):
    # set consent for the current username (if present)
    uname = username_var.get().strip()
    if uname:
        try:
            storage.set_consent(uname, True)
            try:
                # best-effort audit; use safe wrapper to centralize fallback path
                try:
                    storage.safe_add_audit_log(uname, "consent_given", None)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("Consentimento", f"Erro ao registar consentimento: {e}")
            return
    consent_frame.pack_forget()
    messagebox.showinfo("Consentimento", "Você aceitou os termos!")

# ===== GUI =====
root = Tk()
root.title("Formulário de Login")
root.geometry("320x380")

# Frames
main_frame = Frame(root)
consent_frame = Frame(root)
dashboard_frame = Frame(root)

# ---------- CONSENTIMENTO ----------
Label(consent_frame, text="Consentimento de Uso", width="300", bg="orange", fg="white").pack()
Label(consent_frame, text="Por favor, aceite os termos para continuar.", width="300").pack(pady=20)
Button(consent_frame, text="Termos de Uso", width=15, height=1, bg="lightgray",
       command=lambda: messagebox.showinfo("Termos de Uso", "Aqui você pode inserir os termos de uso...")).pack(pady=5)
Button(consent_frame, text="Aceitar", width=15, height=1, bg="green",
       command=lambda: show_consent(consent_frame)).pack()
Button(consent_frame, text="Voltar", width=15, height=1, bg="red",
       command=lambda: show_login(main_frame, consent_frame)).pack(pady=10)

# ---------- LOGIN ----------
Label(main_frame, text="Entre com seus dados", width="300", bg="orange", fg="white").pack()
Label(main_frame, text=f"Modo de segurança: {config.SECURITY_MODE}", fg="gray").pack(pady=(4, 6))

Label(main_frame, text="Username *").place(x=20, y=60)
username_var = StringVar()
Entry(main_frame, textvariable=username_var).place(x=110, y=62)

Label(main_frame, text="Password *").place(x=20, y=100)
password_var = StringVar()
Entry(main_frame, textvariable=password_var, show='*').place(x=110, y=102)

remember_var = BooleanVar(value=True)
Checkbutton(main_frame, text="Lembrar utilizador", variable=remember_var).place(x=110, y=132)

def do_login():
    user = username_var.get().strip()
    pwd = password_var.get()
    if not user or not pwd:
        messagebox.showwarning("Login", "Preencha ambos os campos.")
        return
    # wrap whole login flow to catch unexpected exceptions and show popup
    try:
        # check lockout
        now_ts = int(time.time())
        try:
            locked = storage.is_account_locked(user, now_ts)
        except Exception as e:
            messagebox.showerror("Login", f"Erro ao verificar estado da conta: {e}")
            return

        if locked:
            try:
                lu = storage.get_locked_until(user)
            except Exception:
                lu = None
            remaining = None
            if lu is not None:
                try:
                    remaining = int(lu) - now_ts
                except Exception:
                    remaining = None
            msg = "Conta bloqueada temporariamente."
            if remaining:
                msg += f" Tente novamente em {remaining} segundos."
            messagebox.showerror("Login", msg)
            return

        # attempt login in a background thread to avoid blocking the GUI (PBKDF2 is CPU-intensive)
        def handle_login_result(ok, exc=None):
            if exc:
                messagebox.showerror("Login", f"Erro ao verificar credenciais: {exc}")
                return
            if ok:
                try:
                    storage.reset_failed_attempts(user)
                except Exception as e:
                    # non-fatal: show a warning but continue login
                    messagebox.showwarning("Login", f"Não foi possível resetar as tentativas falhadas: {e}")
                try:
                    ok, fb = storage.safe_add_audit_log(user, "login_success", None)
                    if not ok:
                        messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
                except Exception:
                    pass
                if remember_var.get():
                    try:
                        storage.set_last_user(user)
                    except Exception as e:
                        messagebox.showwarning("Login", f"Não foi possível guardar utilizador lembrado: {e}")
                messagebox.showinfo("Login", f"Bem-vindo, {user}!")
                main_frame.pack_forget()
                # if user already gave consent, show dashboard; otherwise show consent screen
                try:
                    rec = storage.get_user_record(user)
                except Exception:
                    rec = None
                if rec and rec.get("consent"):
                    try:
                        # best-effort write; don't block the UI if it fails
                        storage.safe_add_audit_log(user, "register_success", None)
                    except Exception:
                        pass
                    dashboard_frame.pack(fill="both", expand=True)
                    update_dashboard_buttons()
                else:
                    consent_frame.pack(fill="both", expand=True)
            else:
                # increment failed attempts and possibly lock
                try:
                    failed = storage.increment_failed_attempts(user)
                except Exception as e:
                    messagebox.showwarning("Login", f"Erro ao registar tentativa falhada: {e}")
                    failed = None

                try:
                    storage.safe_add_audit_log(user, "login_failed", f"attempts={failed}")
                except Exception:
                    pass

                if failed is not None and failed >= config.MAX_FAILED_ATTEMPTS:
                    until = None
                    try:
                        until = int(time.time()) + config.LOCKOUT_SECONDS
                        storage.set_lockout(user, until)
                    except Exception as e:
                        messagebox.showwarning("Login", f"Erro ao aplicar bloqueio de conta: {e}")
                    try:
                        storage.safe_add_audit_log(user, "account_locked", f"until={until}")
                    except Exception:
                        pass
                    messagebox.showerror("Login", f"Muitas tentativas falhadas. Conta bloqueada por {config.LOCKOUT_SECONDS} segundos.")
                else:
                    remaining = config.MAX_FAILED_ATTEMPTS - (failed or 1)
                    messagebox.showerror("Login", f"Utilizador não existe ou password inválida. Tentativas restantes: {remaining}")

        def login_worker():
            try:
                ok = check_login(user, pwd)
                root.after(0, lambda: handle_login_result(ok, None))
            except Exception as e:
                root.after(0, lambda: handle_login_result(False, e))

        threading.Thread(target=login_worker, daemon=True).start()
    except Exception as e:
        # catch-all to ensure GUI feedback
        messagebox.showerror("Login", f"Erro inesperado durante o login: {e}")

def open_consent_for_register():
    # Cria janela de consentimento específica para o registo
    win = Toplevel(root)
    win.title("Consentimento")
    win.geometry("280x220")

    Label(win, text="Consentimento de Uso", bg="orange", fg="white").pack(fill="x")
    Label(win, text="Aceite os termos para criar conta.").pack(pady=20)

    Button(win, text="Termos de Uso", width=15, height=1, bg="lightgray",
           command=lambda: messagebox.showinfo("Termos de Uso", TERMS_AND_CONDITIONS)).pack(pady=5)

    def accept():
        win.destroy()
        open_register()

    Button(win, text="Aceitar", bg="green", width=12, command=accept).pack()
    Button(win, text="Recusar", bg="red", width=12, command=win.destroy).pack(pady=8)

def open_register():
    win = Toplevel(root)
    win.title("Registo")
    win.geometry("280x210")
    Label(win, text="Criar conta", bg="orange", fg="white").pack(fill="x")

    u = StringVar(); p = StringVar(); c = StringVar()
    frm = Frame(win); frm.pack(padx=12, pady=10, fill="x")

    Label(frm, text="Username").grid(row=0, column=0, sticky="w")
    Entry(frm, textvariable=u).grid(row=0, column=1)

    Label(frm, text="Password").grid(row=1, column=0, sticky="w", pady=(6,0))
    Entry(frm, textvariable=p, show="*").grid(row=1, column=1, pady=(6,0))

    Label(frm, text="Confirmar").grid(row=2, column=0, sticky="w", pady=(6,0))
    Entry(frm, textvariable=c, show="*").grid(row=2, column=1, pady=(6,0))

    def do_register():
        user = u.get().strip()
        pwd  = p.get()
        cf   = c.get()
        if not user or not pwd:
            messagebox.showwarning("Registo", "Preencha username e password.")
            return
        if pwd != cf:
            messagebox.showwarning("Registo", "As passwords não coincidem.")
            return
        # perform registration (hashing + save) in background to avoid blocking UI
        def on_register_done(success, err=None):
            if success:
                try:
                    storage.set_last_user(user)  # lembrar recém-registado
                except Exception:
                    pass
                # ensure the main login fields reflect the newly created user
                try:
                    username_var.set(user)
                    password_var.set('')
                except Exception:
                    pass
                messagebox.showinfo("Registo", "Conta criada com sucesso!")
                win.destroy()
                main_frame.pack_forget()
                # newly-registered users already have consent recorded at registration;
                # show dashboard instead of repeating consent
                try:
                    rec = storage.get_user_record(user)
                except Exception:
                    rec = None
                if rec and rec.get("consent"):
                    dashboard_frame.pack(fill="both", expand=True)
                    update_dashboard_buttons()
                else:
                    consent_frame.pack(fill="both", expand=True)
            else:
                # If the failure is due to password strength, show a friendly message
                if isinstance(err, RuntimeError):
                    messagebox.showerror("Registo", "Password inválida. A password deve ter pelo menos 8 caracteres e incluir letras e números.")
                else:
                    messagebox.showerror("Registo", f"Falha no registo: {err}")

        def register_worker():
            try:
                # compute secure record (PBKDF2) - CPU-intensive
                record = security.secure_password(pwd)
                # save credentials first
                storage.save_user_record(user, record)
                try:
                    # centralize consent handling so timestamp is set by storage
                    storage.set_consent(user, True)
                except Exception:
                    pass
                try:
                    ok, fb = storage.safe_add_audit_log(user, "register_created", None)
                    if not ok:
                        root.after(0, lambda: messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}"))
                except Exception:
                    pass
                root.after(0, lambda: on_register_done(True, None))
            except Exception as e:
                root.after(0, lambda: on_register_done(False, e))

        threading.Thread(target=register_worker, daemon=True).start()

    Button(win, text="Criar", bg="orange", command=do_register).pack(pady=8)
    Button(win, text="Fechar", command=win.destroy).pack()

Button(main_frame, text="Login", width=10, height=1, bg="orange",
       command=do_login).place(x=110, y=170)

Button(main_frame, text="Registar", width=10, height=1,
       command=lambda: open_consent_for_register()).place(x=110, y=205)

# Export and Delete account actions (GDPR support)
def export_account_data():
    user = username_var.get().strip()
    if not user:
        messagebox.showwarning("Exportar", "Indique o username para exportar os dados.")
        return
    try:
        rec = storage.export_user_record(user)
    except Exception as e:
        messagebox.showerror("Exportar", f"Erro ao obter dados do utilizador: {e}")
        return
    if not rec:
        messagebox.showerror("Exportar", "Utilizador não encontrado.")
        return
    # ask where to save
    path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')], initialfile=f"{user}_data.json")
    if not path:
        return
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        try:
            ok, fb = storage.safe_add_audit_log(user, "data_export", f"path={path}")
            if not ok:
                messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
        except Exception:
            pass
        messagebox.showinfo("Exportar", f"Dados exportados para {path}")
    except Exception as e:
        messagebox.showerror("Exportar", f"Erro ao exportar dados: {e}")

def delete_account():
    user = username_var.get().strip()
    if not user:
        messagebox.showwarning("Apagar", "Indique o username para apagar a conta.")
        return
    if not storage.user_exists(user):
        messagebox.showerror("Apagar", "Utilizador não encontrado.")
        return
    if messagebox.askyesno("Apagar Conta", f"Tem a certeza que deseja apagar a conta '{user}'? Esta ação é irreversível."):
        try:
            storage.delete_user_record(user)
            # clear if remembered
            last = storage.get_last_user()
            if last == user:
                storage.set_last_user('')
            messagebox.showinfo("Apagar", "Conta apagada com sucesso.")
        except Exception as e:
            messagebox.showerror("Apagar", f"Erro ao apagar conta: {e}")
            try:
                ok, fb = storage.safe_add_audit_log(user, "delete_failed", f"error={e}")
                if not ok:
                    messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
            except Exception:
                pass

# Audit log viewer intentionally removed from the GUI to prevent exposing
# audit records to non-admin users. Audit logs remain recorded in the
# `audit_logs` table and can be accessed by admin tools or direct DB queries.


def do_integrity_check():
    try:
        res = storage.db_integrity_check()
    except Exception as e:
        messagebox.showerror("Integridade DB", f"Erro ao verificar integridade: {e}")
        success, fb = storage.safe_add_audit_log('', 'db_integrity_check_failed', f'error={e}')
        if not success:
            messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
        return
    messagebox.showinfo("Integridade DB", f"Resultado: {res}")
    success, fb = storage.safe_add_audit_log('', 'db_integrity_check', f'result={res}')
    if not success:
        messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")


def do_backup():
    try:
        path = storage.backup_database()
    except Exception as e:
        messagebox.showerror("Backup", f"Erro ao criar backup: {e}")
        success, fb = storage.safe_add_audit_log('', 'db_backup_failed', f'error={e}')
        if not success:
            messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
        return
    if not path:
        messagebox.showerror("Backup", "Backup falhou (sem path retornado).")
        return
    messagebox.showinfo("Backup", f"Backup criado: {path}")
    success, fb = storage.safe_add_audit_log('', 'db_backup_manual', f'path={path}')
    if not success:
        messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")

# Dashboard (shows after login if consent already given)
Label(dashboard_frame, text="Área Principal", width="300", bg="orange", fg="white").pack()
Label(dashboard_frame, textvariable=username_var, fg="gray").pack(pady=(4,6))
Button(dashboard_frame, text="Exportar dados", width=12, command=export_account_data).pack(pady=6)
Button(dashboard_frame, text="Apagar conta", width=12, bg='red', fg='white', command=delete_account).pack(pady=6)
backup_btn = Button(dashboard_frame, text="Backup DB", width=12, command=do_backup)
backup_btn.pack(pady=6)
integrity_btn = Button(dashboard_frame, text="Verificar integridade", width=16, command=do_integrity_check)
integrity_btn.pack(pady=6)
restore_btn = Button(dashboard_frame, text="Restaurar Backup", width=16)
restore_btn.pack(pady=6)

def open_change_password():
    win = Toplevel(root)
    win.title("Alterar Password")
    win.geometry("320x220")
    Label(win, text="Alterar Password", bg="orange", fg="white").pack(fill="x")
    frm = Frame(win); frm.pack(padx=12, pady=10)
    cur_var = StringVar(); new_var = StringVar(); cf_var = StringVar()
    Label(frm, text="Password atual").grid(row=0, column=0, sticky="w")
    Entry(frm, textvariable=cur_var, show='*').grid(row=0, column=1)
    Label(frm, text="Nova password").grid(row=1, column=0, sticky="w", pady=(6,0))
    Entry(frm, textvariable=new_var, show='*').grid(row=1, column=1, pady=(6,0))
    Label(frm, text="Confirmar").grid(row=2, column=0, sticky="w", pady=(6,0))
    Entry(frm, textvariable=cf_var, show='*').grid(row=2, column=1, pady=(6,0))

    def do_change():
        user = username_var.get().strip()
        cur = cur_var.get()
        new = new_var.get()
        cf = cf_var.get()
        if not user:
            messagebox.showwarning("Alterar Password", "Username não preenchido.")
            return
        if not cur or not new:
            messagebox.showwarning("Alterar Password", "Preencha ambas as passwords.")
            return
        if new != cf:
            messagebox.showwarning("Alterar Password", "As passwords não coincidem.")
            return
        # verify current password
        try:
            ok = check_login(user, cur)
        except Exception as e:
            messagebox.showerror("Alterar Password", f"Erro ao verificar password atual: {e}")
            return
        if not ok:
            messagebox.showerror("Alterar Password", "Password atual incorreta.")
            try:
                storage.safe_add_audit_log(user, 'password_change_failed', 'incorrect_current')
            except Exception:
                pass
            return
        # create secure record for new password
        try:
            new_record = security.secure_password(new)
        except RuntimeError:
            # clearer message for password strength failures
            messagebox.showerror("Alterar Password", "Password inválida. A password deve ter pelo menos 8 caracteres e incluir letras e números.")
            return
        except Exception as e:
            messagebox.showerror("Alterar Password", f"Erro ao gerar credenciais: {e}")
            return
        # save only the credential fields (partial update)
        try:
            storage.save_user_record(user, new_record)
            try:
                storage.safe_add_audit_log(user, 'password_changed', None)
            except Exception:
                pass
            messagebox.showinfo("Alterar Password", "Password alterada com sucesso.")
            win.destroy()
        except Exception as e:
            messagebox.showerror("Alterar Password", f"Erro ao guardar nova password: {e}")

    Button(win, text="Alterar", bg="orange", command=do_change).pack(pady=8)
    Button(win, text="Fechar", command=win.destroy).pack()

Button(dashboard_frame, text="Alterar Password", width=16, command=open_change_password).pack(pady=6)
Button(dashboard_frame, text="Logout", width=10, command=lambda: (dashboard_frame.pack_forget(), main_frame.pack(fill="both", expand=True), username_var.set(''), password_var.set(''))).pack(pady=8)


def do_restore():
    # ask user to choose a backup file to restore from
    path = filedialog.askopenfilename(title='Selecione backup para restaurar', filetypes=[('Backup','*.backup;*.db;*.sqlite;*.sqlite3'), ('All','*.*')])
    if not path:
        return
    if not messagebox.askyesno('Restaurar Backup', f'Tem a certeza que deseja restaurar o ficheiro {path}? O ficheiro de dados atual será substituído.'):
        return
    try:
        pre = storage.restore_database(path)
    except Exception as e:
        messagebox.showerror('Restaurar', f'Erro ao restaurar backup: {e}')
        try:
            ok, fb = storage.safe_add_audit_log('', 'db_restore_failed', f'error={e}; src={path}')
            if not ok:
                messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")
        except Exception:
            pass
        return
    messagebox.showinfo('Restaurar', f'Restore concluído. Pre-snapshot: {pre or "(não criado)"}. Reinicie a aplicação para garantir consistência.')
    ok, fb = storage.safe_add_audit_log('', 'db_restore_manual', f'src={path}; pre_snapshot={pre}')
    if not ok:
        messagebox.showwarning("Aviso (dev)", f"Falha ao gravar registo de auditoria. Verifique: {fb}")

# bind restore button to handler (button was created earlier)
try:
    restore_btn.config(command=do_restore)
except Exception:
    pass

def update_dashboard_buttons():
    """Ensure dashboard buttons are enabled (visible) for all users.

    Previously these were admin-gated; this function keeps them enabled so
    the GUI shows the Backup and Integrity actions again.
    """
    # Gate backup/integrity/restore to admin users only. Regular users can
    # still export/delete their own data but system-level operations are
    # restricted.
    user = username_var.get().strip()
    try:
        is_admin = storage.is_admin(user)
    except Exception:
        is_admin = False

    state = "normal" if is_admin else "disabled"
    try:
        backup_btn.config(state=state)
    except Exception:
        pass
    try:
        integrity_btn.config(state=state)
    except Exception:
        pass
    try:
        restore_btn.config(state=state)
    except Exception:
        pass

# Pré-preencher com o último utilizador lembrado
last = storage.get_last_user()
if last:
    username_var.set(last)

main_frame.pack(fill="both", expand=True)
root.mainloop()
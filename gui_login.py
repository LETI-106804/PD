from tkinter import *
from tkinter import messagebox
import security, config, storage

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
    except RuntimeError as e:
        messagebox.showerror("Registo", str(e))
        return False
    storage.save_user_record(username, record)
    return True

def check_login(username: str, password: str) -> bool:
    rec = storage.get_user_record(username)
    if not rec:
        return False
    return security.verify_with_record(password, rec)

# ===== Navegação =====
def show_login(main_frame, consent_frame):
    consent_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)

def show_consent(consent_frame):
    consent_frame.pack_forget()
    messagebox.showinfo("Consentimento", "Você aceitou os termos!")

# ===== GUI =====
root = Tk()
root.title("Formulário de Login")
root.geometry("320x380")

# Frames
main_frame = Frame(root)
consent_frame = Frame(root)

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
    if check_login(user, pwd):
        if remember_var.get():
            storage.set_last_user(user)
        messagebox.showinfo("Login", f"Bem-vindo, {user}!")
        main_frame.pack_forget()
        consent_frame.pack(fill="both", expand=True)
    else:
        messagebox.showerror("Login", "Utilizador não existe ou password inválida.")

def open_consent_for_register():
    # Cria janela de consentimento específica para o registo
    win = Toplevel(root)
    win.title("Consentimento")
    win.geometry("280x220")

    Label(win, text="Consentimento de Uso", bg="orange", fg="white").pack(fill="x")
    Label(win, text="Aceite os termos para criar conta.").pack(pady=20)

    Button(win, text="Termos de Uso", width=15, height=1, bg="lightgray",
           command=lambda: messagebox.showinfo("Termos de Uso", "Aqui você pode inserir os termos de uso...")).pack(pady=5)

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
        if register_user(user, pwd):
            storage.set_last_user(user)  # lembrar recém-registado
            messagebox.showinfo("Registo", "Conta criada com sucesso!")
            win.destroy()
            main_frame.pack_forget()
            consent_frame.pack(fill="both", expand=True)

    Button(win, text="Criar", bg="orange", command=do_register).pack(pady=8)
    Button(win, text="Fechar", command=win.destroy).pack()

Button(main_frame, text="Login", width=10, height=1, bg="orange",
       command=do_login).place(x=110, y=170)

Button(main_frame, text="Registar", width=10, height=1,
       command=lambda: open_consent_for_register()).place(x=110, y=205)

# Pré-preencher com o último utilizador lembrado
last = storage.get_last_user()
if last:
    username_var.set(last)

main_frame.pack(fill="both", expand=True)
root.mainloop()
from tkinter import *
from tkinter import messagebox
from functools import partial


# Função para mostrar a página de consentimento após o login
def user_credential(username, password, main_frame, consent_frame):
    user = username.get()
    pwd = password.get()

    if user and pwd:
        print("Username entered:", user)
        print("Password entered:", pwd)
        # Exemplo de uma verificação de login bem-sucedido
        messagebox.showinfo("Login", "Login bem-sucedido!")
        
        # Esconde a página principal e mostra a página de consentimento
        main_frame.pack_forget()  # Esconde a página de login
        consent_frame.pack(fill="both", expand=True)  # Mostra a página de consentimento
    else:
        messagebox.showwarning("Aviso", "Por favor, preencha ambos os campos!")


# Função para mostrar a página de consentimento (simples)
def show_consent(consent_frame):
    consent_frame.pack_forget()  # Esconde a página de consentimento
    messagebox.showinfo("Consentimento", "Você aceitou os termos!")

# Função para voltar à página de login
def show_login(main_frame, consent_frame):
    consent_frame.pack_forget()  # Esconde a página de consentimento
    main_frame.pack(fill="both", expand=True)  # Mostra a página de login


# Janela principal
root = Tk()
root.title("Formulário de Login")
root.geometry("300x300")

# Frame de consentimento (após login)
consent_frame = Frame(root)

# Título da tela de consentimento
Label(consent_frame, text="Consentimento de Uso", width="300", bg="orange", fg="white").pack()

# Texto do consentimento
Label(consent_frame, text="Por favor, aceite os termos para continuar.", width="300").pack(pady=20)

# Botão de aceitação
accept_button = Button(consent_frame, text="Aceitar", width=15, height=1, bg="green", command=lambda: show_consent(consent_frame))
accept_button.pack()

# Botão de voltar à página de login
back_button = Button(consent_frame, text="Voltar", width=15, height=1, bg="red", command=lambda: show_login(main_frame, consent_frame))
back_button.pack(pady=10)

# Frame principal (Login)
main_frame = Frame(root)

# Título
Label(main_frame, text="Entre com seus dados", width="300", bg="orange", fg="white").pack()

# Campo de username
Label(main_frame, text="Username *").place(x=20, y=40)
username = StringVar()
Entry(main_frame, textvariable=username).place(x=90, y=42)

# Campo de senha
Label(main_frame, text="Password *").place(x=20, y=80)
password = StringVar()
Entry(main_frame, textvariable=password, show='*').place(x=90, y=82)

# Botão de login
login_button = Button(main_frame, text="Login", width=10, height=1, bg="orange", command=partial(user_credential, username, password, main_frame, consent_frame))
login_button.place(x=105, y=130)

# Botão de termos de uso (simula um popup)
terms_button = Button(main_frame, text="Termos de Uso", width=10, height=1, bg="lightgray", command=lambda: messagebox.showinfo("Termos de Uso", "Aqui você pode inserir os termos de uso..."))
terms_button.place(x=105, y=160)

# Exibe a página de login inicialmente
main_frame.pack(fill="both", expand=True)

root.mainloop()
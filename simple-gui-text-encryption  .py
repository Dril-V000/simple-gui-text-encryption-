import os
import base64
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_key_from_password(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


def encrypt(text, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    token = cipher.encrypt(text.encode()).decode()
    salt_b64 = base64.urlsafe_b64encode(salt).decode()
    return f"{salt_b64}:{token}"


def decrypt(prefixed, password):
    try:
        salt_b64, token = prefixed.split(":", 1)
    except ValueError:
        raise ValueError("Invalid format! Must be salt:token")
    salt = base64.urlsafe_b64decode(salt_b64.encode())
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    return cipher.decrypt(token.encode()).decode()


def create_gui():
    root = tk.Tk()
    root.title("🔒 Simple Cipher GUI")
    root.geometry("700x600")
    root.resizable(0,0)
    root.configure(bg="#0d0d0d")

    title = tk.Label(root, text="🔐 Simple Password-based Cipher",
                     font=("Consolas", 16, "bold"),
                     fg="#00FF00", bg="#0d0d0d")
    title.pack(pady=10)

    tk.Label(root, text="Password:", font=("Consolas", 12), fg="#00FF00", bg="#0d0d0d").pack()
    password_entry = tk.Entry(root, show="*", width=40, font=("Consolas", 12), bg="#1a1a1a", fg="#00FF00", insertbackground="#00FF00")
    password_entry.pack(pady=5)

    tk.Label(root, text="Text / Encrypted Data:", font=("Consolas", 12), fg="#00FF00", bg="#0d0d0d").pack()
    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=10,
                                          font=("Consolas", 11), bg="#1a1a1a", fg="#00FF00", insertbackground="#00FF00")
    text_area.pack(pady=5)

    tk.Label(root, text="Output:", font=("Consolas", 12), fg="#00FF00", bg="#0d0d0d").pack()
    output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=10,
                                            font=("Consolas", 11), bg="#1a1a1a", fg="#00FF00", insertbackground="#00FF00")
    output_area.pack(pady=5)

    def do_encrypt():
        password = password_entry.get().strip()
        text = text_area.get("1.0", tk.END).strip()
        if not password or not text:
            messagebox.showwarning("⚠️ Warning", "Please enter password and text.")
            return
        try:
            encrypted = encrypt(text, password)
            output_area.delete("1.0", tk.END)
            output_area.insert(tk.END, encrypted)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt():
        password = password_entry.get().strip()
        text = text_area.get("1.0", tk.END).strip()
        if not password or not text:
            messagebox.showwarning("⚠️ Warning", "Please enter password and encrypted data.")
            return
        try:
            decrypted = decrypt(text, password)
            output_area.delete("1.0", tk.END)
            output_area.insert(tk.END, decrypted)
        except Exception:
            messagebox.showerror("Error", "Wrong password or invalid encrypted text!")


    button_frame = tk.Frame(root, bg="#0d0d0d")
    button_frame.pack(pady=10)

    encrypt_btn = tk.Button(button_frame, text="🔒 Encrypt", font=("Consolas", 12, "bold"),
                            bg="#003300", fg="#00FF00", width=15, command=do_encrypt)
    encrypt_btn.grid(row=0, column=0, padx=10)

    decrypt_btn = tk.Button(button_frame, text="🔓 Decrypt", font=("Consolas", 12, "bold"),
                            bg="#330000", fg="#FF5555", width=15, command=do_decrypt)
    decrypt_btn.grid(row=0, column=1, padx=10)

    exit_btn = tk.Button(button_frame, text="❌ Exit", font=("Consolas", 12, "bold"),
                         bg="#1a1a1a", fg="#FF0000", width=15, command=root.destroy)
    exit_btn.grid(row=0, column=2, padx=10)

    root.mainloop()


if __name__ == "__main__":
    try:
        create_gui()
    except KeyboardInterrupt:
        sys.exit(0)

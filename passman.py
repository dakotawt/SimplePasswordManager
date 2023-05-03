import bcrypt
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os

#cryptography documentation: https://cryptography.io/en/latest/fernet/
#NetworkChuck cryptography: https://www.youtube.com/watch?v=UtMMjXOlRQc
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

PASSWORD_FILE = 'passwords.json'
MASTER_PASSWORD_FILE = 'master_password'

def master_password_exists():
    return os.path.exists(MASTER_PASSWORD_FILE)

def set_master_password():
    master_password = simpledialog.askstring("Set Master Password", "Enter a master password:", show='*')

    if not master_password:
        messagebox.showerror("Error", "Master password is required")
        return

    hashed_master_password = bcrypt.hashpw(master_password.encode('utf-8'), bcrypt.gensalt(10))

    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(hashed_master_password)

    return master_password

def verify_master_password(master_password):
    if not master_password:
        return False

    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        stored_hash = f.read()

    return bcrypt.checkpw(master_password.encode('utf-8'), stored_hash)

def create_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
    return key

#encryption
def encrypt(plaintext, key):
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(plaintext.encode('utf-8'))
    return ciphertext.decode('utf-8')

#decryption
def decrypt(ciphertext, key):
    fernet = Fernet(key)
    plaintext = fernet.decrypt(ciphertext.encode('utf-8'))
    return plaintext.decode('utf-8')

def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as f:
            return json.load(f)
    return []

def save_passwords(passwords):
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(passwords, f)
        
#add credentials; check to see if all fields were entered; encrypt password; save;
def add_password():
    salt = os.urandom(16)
    key = create_key(master_password, salt)

    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not website or not username or not password:
        messagebox.showerror("Error", "All fields are required")
        return

    encrypted_password = encrypt(password, key)

    passwords = load_passwords()
    passwords.append({"website": website, "username": username, "password": encrypted_password, "salt": base64.urlsafe_b64encode(salt).decode('utf-8')})
    save_passwords(passwords)

    messagebox.showinfo("Success", "Password added successfully")

#decrypt pass; show credential
def show_passwords():
    passwords_window = tk.Toplevel(root)
    passwords_window.title("Stored Passwords")

    passwords = load_passwords()

    for index, entry in enumerate(passwords):
        salt = base64.urlsafe_b64decode(entry['salt'].encode('utf-8'))
        key = create_key(master_password, salt)
        try:
            decrypted_password = decrypt(entry['password'], key)
        except:
            decrypted_password = 'Incorrect master password'
            
        website_label = tk.Label(passwords_window, text=entry['website'])
        website_label.grid(row=index, column=0, sticky=tk.W, padx=10, pady=5)

        username_label = tk.Label(passwords_window, text=entry['username'])
        username_label.grid(row=index, column=1, sticky=tk.W, padx=10, pady=5)

        password_label = tk.Label(passwords_window, text=decrypted_password)
        password_label.grid(row=index, column=2, sticky=tk.W, padx=10, pady=5)

#remove cred based on input website        
def remove_cred():
    website_to_remove = simpledialog.askstring("Remove Credential", "Enter the website of the credential you want to remove:")

    if not website_to_remove:
        messagebox.showerror("Error", "Website is required")
        return

    passwords = load_passwords()

    for index, entry in enumerate(passwords):
        if entry['website'] == website_to_remove:
            del passwords[index]
            save_passwords(passwords)
            messagebox.showinfo("Success", "Credential removed successfully")
            return

    messagebox.showerror("Error", "No password found for the given website")
#assign a master password if one doesnt exist; if one does ask for input.
if not master_password_exists():
    master_password = set_master_password()
    if not master_password:
        messagebox.showerror("Error", "Master password is required to use the password manager")
        sys.exit(1)
else:
    master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
    if not verify_master_password(master_password):
        messagebox.showerror("Error", "Incorrect master password")
        sys.exit(1)

#GUI implementation

root = tk.Tk()
root.geometry("450x300")
root.title("Password Manager")

website_label = tk.Label(root, text="Website:")
website_label.grid(row=0, column=0, sticky=tk.W, padx=20, pady=20)

website_entry = tk.Entry(root)
website_entry.grid(row=0, column=1, padx=20, pady=20)

username_label = tk.Label(root, text="Username:")
username_label.grid(row=1, column=0, sticky=tk.W, padx=20, pady=20)

username_entry = tk.Entry(root)
username_entry.grid(row=1, column=1, padx=20, pady=20)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=2, column=0, sticky=tk.W, padx=20, pady=20)

password_entry = tk.Entry(root)
password_entry.grid(row=2, column=1, padx=20, pady=20)

add_button = tk.Button(root, text="Add Password", command=add_password)
add_button.grid(row=3, column=0, pady=20)

show_passwords_button = tk.Button(root, text="Show Passwords", command=show_passwords)
show_passwords_button.grid(row=3, column=1, pady=20)

remove_button = tk.Button(root, text="Remove Credential", command=remove_cred)
remove_button.grid(row=3, column=2, pady=20)

root.mainloop()

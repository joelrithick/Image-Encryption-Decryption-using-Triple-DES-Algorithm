import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hashlib
import os
import base64
import binascii  # Add this import statement

# Encryption mode constants
ECB_MODE = 'ECB'
CBC_MODE = 'CBC'
CTR_MODE = 'CTR'

# Function to pad data
def pad(data):
    pad_len = DES3.block_size - (len(data) % DES3.block_size)
    return data + bytes([pad_len] * pad_len)

# Function to unpad data
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Function to derive key
def derive_key(password):
    hash_obj = SHA256.new()
    hash_obj.update(password.encode('utf-8'))
    return hash_obj.digest()[:24]

# Function to encrypt a file
def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        padded_data = pad(file_bytes)
        new_file_bytes = cipher.encrypt(padded_data)

    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)

# Function to decrypt a file
def decrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        decrypted_data = cipher.decrypt(file_bytes)
        unpadded_data = unpad(decrypted_data)

    with open(file_path, 'wb') as output_file:
        output_file.write(unpadded_data)

# Function to encrypt a folder
def encrypt_folder(folder_path, cipher, progress_bar):
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    progress = 0
    progress_bar["maximum"] = total_files
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, cipher)
            progress += 1
            progress_bar["value"] = progress
            progress_bar.update()

# Function to decrypt a folder
def decrypt_folder(folder_path, cipher, progress_bar):
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    progress = 0
    progress_bar["maximum"] = total_files
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_file(file_path, cipher)
            progress += 1
            progress_bar["value"] = progress
            progress_bar.update()

# Function to calculate hash of a file
def calculate_hash(file_path):
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

# Function to generate digital signature
def generate_signature(folder_path, private_key, status_label, progress_bar):
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    progress = 0
    progress_bar["maximum"] = total_files
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            hash_value = calculate_hash(file_path)
            signature = base64.b64encode(hash_value.encode('utf-8'))
            signature_file_path = file_path + ".sig"
            with open(signature_file_path, 'wb') as sig_file:
                sig_file.write(signature)
            progress += 1
            progress_bar["value"] = progress
            progress_bar.update()
    status_label.config(text="Digital signature generated.")

# Function to verify digital signature
def verify_signature(folder_path, public_key):
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith(".sig"):
                signature_file_path = os.path.join(root, file_name)
                with open(signature_file_path, 'rb') as sig_file:
                    signature = sig_file.read()
                try:
                    signature = base64.b64decode(signature)
                except binascii.Error:
                    return False  # Incorrect padding or invalid signature format
                original_file_path = os.path.join(root, file_name[:-4])
                original_hash = calculate_hash(original_file_path)
                if signature != original_hash.encode('utf-8'):
                    return False
    return True


# Function to check key strength
def check_key_strength(key):
    min_key_length = 16
    key_length = len(key.encode('ascii'))
    return key_length >= min_key_length

# Function to get encryption cipher
def get_cipher(key, mode):
    key = derive_key(key)
    if mode == ECB_MODE:
        return DES3.new(key, DES3.MODE_ECB)
    elif mode == CBC_MODE:
        iv = get_random_bytes(DES3.block_size)
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif mode == CTR_MODE:
        nonce = get_random_bytes(DES3.block_size // 2)
        return DES3.new(key, DES3.MODE_CTR, nonce=nonce)

# Function to browse for folder
def browse_folder(entry_widget):
    folder_path = filedialog.askdirectory()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, folder_path)

# Function to validate inputs and start encryption/decryption process
def validate_and_process(operation_var, folder_var, key_var, mode_var, signature_var, status_label, progress_bar):
    operation = operation_var.get()
    folder_path = folder_var.get()
    key = key_var.get()
    mode = mode_var.get()
    signature = signature_var.get()

    if not os.path.exists(folder_path):
        messagebox.showerror("Error", "Folder path does not exist.")
        return

    if not check_key_strength(key):
        messagebox.showerror("Error", "The key is too weak. Please choose a stronger key (minimum length: 16 characters).")
        return

    cipher = get_cipher(key, mode)

    if operation == 'Encrypt':
        status_label.config(text="Encrypting files...")
        encrypt_folder(folder_path, cipher, progress_bar)
        if signature == 'Generate':
            status_label.config(text="Generating digital signature...")
            generate_signature(folder_path, key, status_label, progress_bar)
        messagebox.showinfo("Encryption Complete", "Files encrypted successfully!")
    elif operation == 'Decrypt':
        status_label.config(text="Decrypting files...")
        decrypt_folder(folder_path, cipher, progress_bar)
        status_label.config(text="Verifying digital signature...")
        if verify_signature(folder_path, key):
            status_label.config(text="Digital signature verified.")
            messagebox.showinfo("Decryption Complete", "Files decrypted successfully and integrity verified!")
        else:
            status_label.config(text="Digital signature verification failed.")
            messagebox.showerror("Decryption Failed", "Files decrypted successfully and integrity verified")

# Function to create the main application window
def create_main_window():
    # Create GUI
    root = tk.Tk()
    root.title("Image Encryption & Decryption")

    operation_label = tk.Label(root, text="Operation:")
    operation_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    operation_var = tk.StringVar(root)
    operation_var.set("Encrypt")
    operation_option = tk.OptionMenu(root, operation_var, "Encrypt", "Decrypt")
    operation_option.grid(row=0, column=1, padx=10, pady=5)

    folder_label = tk.Label(root, text="Folder Path:")
    folder_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

    folder_var = tk.StringVar(root)
    folder_entry = tk.Entry(root, textvariable=folder_var, width=40)
    folder_entry.grid(row=1, column=1, padx=10, pady=5)

    browse_button = tk.Button(root, text="Browse", command=lambda: browse_folder(folder_entry))
    browse_button.grid(row=1, column=2, padx=5, pady=5)

    key_label = tk.Label(root, text="Encryption Key:")
    key_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

    key_var = tk.StringVar(root)
    key_entry = tk.Entry(root, textvariable=key_var, show="*", width=40)
    key_entry.grid(row=2, column=1, padx=10, pady=5)

    mode_label = tk.Label(root, text="Encryption Mode:")
    mode_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

    mode_var = tk.StringVar(root)
    mode_var.set(ECB_MODE)
    mode_option = tk.OptionMenu(root, mode_var, ECB_MODE, CBC_MODE, CTR_MODE)
    mode_option.grid(row=3, column=1, padx=10, pady=5)

    signature_label = tk.Label(root, text="Digital Signature:")
    signature_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

    signature_var = tk.StringVar(root)
    signature_var.set("None")
    signature_option = tk.OptionMenu(root, signature_var, "None", "Generate")
    signature_option.grid(row=4, column=1, padx=10, pady=5)

    execute_button = tk.Button(root, text="Execute", command=lambda: validate_and_process(operation_var, folder_var, key_var, mode_var, signature_var, status_label, progress_bar))
    execute_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

    progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")
    progress_bar.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

    status_label = tk.Label(root, text="", fg="green")
    status_label.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    root.mainloop()

# Function to validate login credentials
def validate_login(username, password):
    if username == "admin" and password == "admin123":
        create_main_window()
    else:
        messagebox.showerror("Invalid Credentials", "Invalid username or password.")

# Function to create the login window
def create_login_window():
    login_window = tk.Tk()
    login_window.title("Login")

    username_label = tk.Label(login_window, text="Username:")
    username_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    username_var = tk.StringVar(login_window)
    username_entry = tk.Entry(login_window, textvariable=username_var)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    password_label = tk.Label(login_window, text="Password:")
    password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

    password_var = tk.StringVar(login_window)
    password_entry = tk.Entry(login_window, textvariable=password_var, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    login_button = tk.Button(login_window, text="Login", command=lambda: validate_login(username_entry.get(), password_entry.get()))
    login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    login_window.mainloop()

# Create login window
create_login_window()

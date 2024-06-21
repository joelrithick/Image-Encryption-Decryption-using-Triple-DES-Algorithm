import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from ttkthemes import ThemedStyle
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hashlib
import os
import base64

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
def encrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, cipher)

# Function to decrypt a folder
def decrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_file(file_path, cipher)

# Function to calculate hash of a file
def calculate_hash(file_path):
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

# Function to generate digital signature
def generate_signature(folder_path, private_key, status_label):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            hash_value = calculate_hash(file_path)
            signature = base64.b64encode(hash_value.encode('utf-8'))
            signature_file_path = file_path + ".sig"
            with open(signature_file_path, 'wb') as sig_file:
                sig_file.write(signature)
    status_label.config(text="Digital signature generated.")

# Function to verify digital signature
def verify_signature(folder_path, public_key):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith(".sig"):
                signature_file_path = os.path.join(root, file_name)
                with open(signature_file_path, 'rb') as sig_file:
                    signature = sig_file.read()
                signature = base64.b64decode(signature)
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
def validate_and_process(operation_var, folder_var, key_var, mode_var, signature_var, status_label):
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

    # Perform file integrity check before encryption/decryption
    initial_hashes = {}
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            initial_hashes[file_path] = calculate_hash(file_path)

    if operation == 'Encrypt':
        status_label.config(text="Encrypting files...")
        encrypt_folder(folder_path, cipher)
        if signature == 'Generate':
            status_label.config(text="Generating digital signature...")
            generate_signature(folder_path, key, status_label)
        messagebox.showinfo("Encryption Complete", "Files encrypted successfully!")
    elif operation == 'Decrypt':
        status_label.config(text="Decrypting files...")
        decrypt_folder(folder_path, cipher)
        status_label.config(text="Verifying digital signature...")
        if verify_signature(folder_path, key):
            status_label.config(text="Digital signature verified.")
            messagebox.showinfo("Decryption Complete", "Files decrypted successfully and integrity verified!")
        else:
            status_label.config(text="Digital signature verification failed.")
            messagebox.showerror("Decryption Failed", "Files decrypted successfully but integrity verification failed!")

    # Perform file integrity check after encryption/decryption
    final_hashes = {}
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            final_hashes[file_path] = calculate_hash(file_path)

    for file_path, initial_hash in initial_hashes.items():
        final_hash = final_hashes.get(file_path)
        if final_hash != initial_hash:
            messagebox.showerror("Integrity Check Failed", f"Integrity check failed for file: {file_path}")

# Create GUI
root = tk.Tk()
root.title("Image Encryption & Decryption")

# Customizable Themes
style = ThemedStyle(root)
style.set_theme("arc")  # Set your preferred theme

operation_label = ttk.Label(root, text="Operation:")
operation_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

operation_var = tk.StringVar(root)
operation_var.set("Encrypt")
operation_option = ttk.OptionMenu(root, operation_var, "Encrypt", "Decrypt")
operation_option.grid(row=0, column=1, padx=10, pady=5)

folder_label = ttk.Label(root, text="Folder Path:")
folder_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

folder_var = tk.StringVar(root)
folder_entry = ttk.Entry(root, textvariable=folder_var, width=40)
folder_entry.grid(row=1, column=1, padx=10, pady=5)

browse_button = ttk.Button(root, text="Browse", command=lambda: browse_folder(folder_entry))
browse_button.grid(row=1, column=2, padx=5, pady=5)

key_label = ttk.Label(root, text="Encryption Key:")
key_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

key_var = tk.StringVar(root)
key_entry = ttk.Entry(root, textvariable=key_var, show="*", width=40)
key_entry.grid(row=2, column=1, padx=10, pady=5)

mode_label = ttk.Label(root, text="Encryption Mode:")
mode_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

mode_var = tk.StringVar(root)
mode_var.set(ECB_MODE)
mode_option = ttk.OptionMenu(root, mode_var, ECB_MODE, CBC_MODE, CTR_MODE)
mode_option.grid(row=3, column=1, padx=10, pady=5)

signature_label = ttk.Label(root, text="Digital Signature:")
signature_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

signature_var = tk.StringVar(root)
signature_var.set("None")
signature_option = ttk.OptionMenu(root, signature_var, "None", "Generate")
signature_option.grid(row=4, column=1, padx=10, pady=5)

execute_button = ttk.Button(root, text="Execute", command=lambda: validate_and_process(operation_var, folder_var, key_var, mode_var, signature_var, status_label))
execute_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

status_label = ttk.Label(root, text="", foreground="green")
status_label.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

root.mainloop()

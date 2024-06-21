import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# Encryption mode constants
ECB_MODE = 'ECB'
CBC_MODE = 'CBC'
CTR_MODE = 'CTR'

def pad(data):
    pad_len = DES3.block_size - (len(data) % DES3.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password):
    hash_obj = SHA256.new()
    hash_obj.update(password.encode('utf-8'))
    return hash_obj.digest()[:24]

def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        padded_data = pad(file_bytes)
        new_file_bytes = cipher.encrypt(padded_data)

    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)

def decrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        decrypted_data = cipher.decrypt(file_bytes)
        unpadded_data = unpad(decrypted_data)

    with open(file_path, 'wb') as output_file:
        output_file.write(unpadded_data)

def encrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, cipher)

def decrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_file(file_path, cipher)

def check_key_strength(key):
    min_key_length = 16
    key_length = len(key.encode('ascii'))
    return key_length >= min_key_length

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

def encrypt_decrypt_files(operation, folder_path, key, mode):
    cipher = get_cipher(key, mode)
    if operation == 'Encrypt':
        encrypt_folder(folder_path, cipher)
        messagebox.showinfo("Encryption Complete", "Files encrypted successfully!")
    elif operation == 'Decrypt':
        decrypt_folder(folder_path, cipher)
        messagebox.showinfo("Decryption Complete", "Files decrypted successfully!")

def browse_folder(entry_widget):
    folder_path = filedialog.askdirectory()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, folder_path)

def validate_and_process(root, operation_var, folder_var, key_var, mode_var):
    operation = operation_var.get()
    folder_path = folder_var.get()
    key = key_var.get()
    mode = mode_var.get()

    if not os.path.exists(folder_path):
        messagebox.showerror("Error", "Folder path does not exist.")
        return

    if not check_key_strength(key):
        messagebox.showerror("Error", "The key is too weak. Please choose a stronger key (minimum length: 16 characters).")
        return

    encrypt_decrypt_files(operation, folder_path, key, mode)
    root.destroy()

def create_gui():
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
    key_entry = tk.Entry(root, textvariable=key_var, width=40, show="*")
    key_entry.grid(row=2, column=1, padx=10, pady=5)

    mode_label = tk.Label(root, text="Encryption Mode:")
    mode_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

    mode_var = tk.StringVar(root)
    mode_var.set(ECB_MODE)
    mode_option = tk.OptionMenu(root, mode_var, ECB_MODE, CBC_MODE, CTR_MODE)
    mode_option.grid(row=3, column=1, padx=10, pady=5)

    execute_button = tk.Button(root, text="Execute", command=lambda: validate_and_process(root, operation_var, folder_var, key_var, mode_var))
    execute_button.grid(row=4, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

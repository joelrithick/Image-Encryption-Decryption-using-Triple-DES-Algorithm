import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES3
import zlib

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

def calculate_checksum(file_path):
    with open(file_path, 'rb') as file:
        checksum = zlib.adler32(file.read())
    return checksum

def encrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, cipher)
            checksum = calculate_checksum(file_path)
            with open(file_path + '.checksum', 'w') as checksum_file:
                checksum_file.write(str(checksum))

def decrypt_folder(folder_path, cipher):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_file(file_path, cipher)

def validate_and_process(root, operation_var, folder_var, key_var, mode_var, status_label):
    operation = operation_var.get()
    folder_path = folder_var.get()
    key = key_var.get()
    mode = mode_var.get()

    if not os.path.exists(folder_path):
        messagebox.showerror("Error", "Folder path does not exist.")
        return

    key = key.encode('utf-8')  # Ensure key is encoded as bytes

    cipher = DES3.new(key, DES3.MODE_ECB)

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
    key_entry = tk.Entry(root, textvariable=key_var, show="*")
    key_entry.grid(row=2, column=1, padx=10, pady=5)

    mode_label = tk.Label(root, text="Encryption Mode:")
    mode_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

    mode_var = tk.StringVar(root)
    mode_var.set(ECB_MODE)
    mode_option = tk.OptionMenu(root, mode_var, ECB_MODE, CBC_MODE, CTR_MODE)
    mode_option.grid(row=3, column=1, padx=10, pady=5)

    execute_button = tk.Button(root, text="Execute", command=lambda: validate_and_process(root, operation_var, folder_var, key_var, mode_var, status_label))
    execute_button.grid(row=4, column=0, columnspan=2, pady=10)

    status_label = tk.Label(root, text="")
    status_label.grid(row=5, column=0, columnspan=2)

    root.mainloop()

create_gui()

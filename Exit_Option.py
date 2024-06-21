import os
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# Encryption mode constants
ECB_MODE = 'ECB'
CBC_MODE = 'CBC'
CTR_MODE = 'CTR'


# PKCS#7 padding functions
def pad(data):
    pad_len = DES3.block_size - (len(data) % DES3.block_size)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def derive_key(password):
    # Use SHA-256 for key derivation
    hash_obj = SHA256.new()
    hash_obj.update(password.encode('utf-8'))
    return hash_obj.digest()[:24]  # Trim to 24 bytes (192 bits) for DES3 key


def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        padded_data = pad(file_bytes)
        new_file_bytes = cipher.encrypt(padded_data)

        # Generate hash for integrity verification
        hash_obj = SHA256.new()
        hash_obj.update(file_bytes)
        integrity_hash = hash_obj.digest()

    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)

    # Save integrity hash to a separate file
    integrity_file_path = file_path + ".integrity"
    with open(integrity_file_path, "wb") as integrity_file:
        integrity_file.write(integrity_hash)


def decrypt_file(file_path, cipher):
    integrity_file_path = file_path + ".integrity"
    with open(integrity_file_path, "rb") as integrity_file:
        integrity_hash = integrity_file.read()

    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        decrypted_data = cipher.decrypt(file_bytes)
        unpadded_data = unpad(decrypted_data)

        # Verify integrity using stored hash
        hash_obj = SHA256.new()
        hash_obj.update(unpadded_data)
        decrypted_hash = hash_obj.digest()

        if decrypted_hash != integrity_hash:
            raise ValueError("Integrity check failed. Data may have been tampered with.")

    with open(file_path, 'wb') as output_file:
        output_file.write(unpadded_data)


def encrypt_folder(folder_path, cipher):
    print("Encrypting files...")
    for root, dirs, files in os.walk(folder_path):
        total_files = len(files)
        for index, file_name in enumerate(files, start=1):
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, cipher)
            print(f"Progress: {index}/{total_files} files encrypted", end="\r")
    print("\nEncryption complete.")


def decrypt_folder(folder_path, cipher):
    print("Decrypting files...")
    for root, dirs, files in os.walk(folder_path):
        total_files = len(files)
        for index, file_name in enumerate(files, start=1):
            if file_name.endswith(".integrity"):
                continue
            file_path = os.path.join(root, file_name)
            decrypt_file(file_path, cipher)
            os.remove(file_path + ".integrity")
            print(f"Progress: {index}/{total_files} files decrypted", end="\r")
    print("\nDecryption complete.")


def check_key_strength(key):
    min_key_length = 16
    key_length = len(key.encode('ascii'))
    return key_length >= min_key_length


def get_cipher(key, mode):
    key = derive_key(key)  # Derive key using SHA-256
    if mode == ECB_MODE:
        return DES3.new(key, DES3.MODE_ECB)
    elif mode == CBC_MODE:
        iv = get_random_bytes(DES3.block_size)
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif mode == CTR_MODE:
        nonce = get_random_bytes(DES3.block_size // 2)
        return DES3.new(key, DES3.MODE_CTR, nonce=nonce)


def main():
    print("Welcome to Image Encryption & Decryption!")
    while True:
        print("\nSelect the operation to be done:")
        print("\t1- Encryption")
        print("\t2- Decryption")
        print("\t3- Exit")
        operation = input("Select your choice: ")
        if operation not in ['1', '2', '3']:
            print("Invalid choice. Please try again.")
            continue
        if operation == '3':
            print("Exiting the program.")
            break

        folder_path = input("Enter folder path: ")
        if not os.path.exists(folder_path):
            print("Folder does not exist. Please provide a valid folder path.")
            continue

        key = input("Enter TDES key: ")
        while not check_key_strength(key):
            print("The key is too weak. Please choose a stronger key (minimum length: 16 characters).")
            key = input("Enter TDES key: ")

        print("Select encryption mode:")
        print("\t1- ECB (Electronic Codebook)")
        print("\t2- CBC (Cipher Block Chaining)")
        print("\t3- CTR (Counter)")
        mode_choice = input("Select your choice: ")

        if mode_choice == '1':
            mode = ECB_MODE
        elif mode_choice == '2':
            mode = CBC_MODE
        elif mode_choice == '3':
            mode = CTR_MODE
        else:
            print("Invalid choice. Defaulting to ECB mode.")
            mode = ECB_MODE

        cipher = get_cipher(key, mode)

        if operation == '1':
            encrypt_folder(folder_path, cipher)
        else:
            try:
                decrypt_folder(folder_path, cipher)
            except ValueError as e:
                print(f"Decryption failed: {e}")


if __name__ == "__main__":
    main()

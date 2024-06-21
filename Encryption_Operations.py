import os
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from hashlib import md5

# Encryption mode constants
ECB_MODE = 'ECB'
CBC_MODE = 'CBC'
CTR_MODE = 'CTR'


def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        new_file_bytes = cipher.encrypt(file_bytes)
    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


def decrypt_file(file_path, cipher):
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
        new_file_bytes = cipher.decrypt(file_bytes)
    with open(file_path, 'wb') as output_file:
        output_file.write(new_file_bytes)


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
    key_hash = md5(key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)

    if mode == ECB_MODE:
        return DES3.new(tdes_key, DES3.MODE_ECB)
    elif mode == CBC_MODE:
        iv = get_random_bytes(DES3.block_size)
        return DES3.new(tdes_key, DES3.MODE_CBC, iv=iv)
    elif mode == CTR_MODE:
        nonce = get_random_bytes(DES3.block_size // 2)
        return DES3.new(tdes_key, DES3.MODE_CTR, nonce=nonce)


def main():
    while True:
        print('Select the operation to be done:')
        print('\t1- Encryption')
        print('\t2- Decryption')
        operation = input('Select your choice: ')
        if operation not in ['1', '2']:
            break

        folder_path = input('Enter folder path: ')
        key = input('TDES key: ')

        while not check_key_strength(key):
            print("The key is too weak. Please choose a stronger key (minimum length: 16 characters).")
            key = input('TDES key: ')

        print('Select encryption mode:')
        print('\t1- ECB (Electronic Codebook)')
        print('\t2- CBC (Cipher Block Chaining)')
        print('\t3- CTR (Counter)')
        mode_choice = input('Select your choice: ')

        if mode_choice == '1':
            mode = ECB_MODE
        elif mode_choice == '2':
            mode = CBC_MODE
        elif mode_choice == '3':
            mode = CTR_MODE
        else:
            print('Invalid choice. Defaulting to ECB mode.')
            mode = ECB_MODE

        cipher = get_cipher(key, mode)

        if operation == '1':
            encrypt_folder(folder_path, cipher)
        else:
            decrypt_folder(folder_path, cipher)

        print('Successfully done!')


if __name__ == "__main__":
    main()

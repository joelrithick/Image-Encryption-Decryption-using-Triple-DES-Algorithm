import os
from Crypto.Cipher import DES3
from hashlib import md5

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

        key_hash = md5(key.encode('ascii')).digest()
        tdes_key = DES3.adjust_key_parity(key_hash)
        cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

        if operation == '1':
            encrypt_folder(folder_path, cipher)
        else:
            decrypt_folder(folder_path, cipher)

        print('Successfully done!')

if __name__ == "__main__":
    main()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from os import urandom
import os

# Funkcja do generowania klucza z hasła
def generate_key(password: str, salt: bytes, iterations: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str, output_path: str, enhanced_protection: bool):
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    salt = urandom(32) if enhanced_protection else urandom(16)  # Zwiększony salt w przypadku ochrony
    iterations = 500000 if enhanced_protection else 100000  # Więcej iteracji dla ochrony
    key = generate_key(password, salt, iterations)
    iv = urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Dodanie paddingu PKCS7
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    with open(output_path, 'wb') as output_file:
        output_file.write(salt + iv + ciphertext)

def decrypt_file(file_path: str, password: str, output_path: str, enhanced_protection: bool):
    with open(file_path, 'rb') as file:
        decoded_data = file.read()

    salt_length = 32 if enhanced_protection else 16
    salt = decoded_data[:salt_length]
    iv = decoded_data[salt_length:salt_length + 16]
    encrypted_data = decoded_data[salt_length + 16:]
    iterations = 500000 if enhanced_protection else 100000
    key = generate_key(password, salt, iterations)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_text = decryptor.update(encrypted_data) + decryptor.finalize()

  
    unpadder = PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    with open(output_path, 'wb') as output_file:
        output_file.write(decrypted_text)


file_for_encryption = r'C:\Users\Adrian\Desktop\file_for_python.txt'
encrypted_file = r'C:\Users\Adrian\Desktop\encrypted_file.txt'
decrypted_file = r'C:\Users\Adrian\Desktop\decrypted_file.txt'

# Dodanie ochrony
user_input = input("Czy chcesz dodać ochronę przed brute force? (tak/nie): ")
enhanced_protection = user_input.lower() == 'tak'


encrypt_file(file_for_encryption, 'ad', encrypted_file, enhanced_protection)


decrypt_file(encrypted_file, 'ad', decrypted_file, enhanced_protection)

# Funkcja do usuwania plików
def remove_files(file_paths):
    for path in file_paths:
        if os.path.exists(path):
            os.remove(path)
            print(f"Plik {path} został usunięty.")
        else:
            print(f"Plik {path} nie istnieje.")

# Usunięcie plików
user_input = input("Czy chcesz zakończyć program i usunąć pliki? (tak/nie): ")

if user_input.lower() == 'tak':
    remove_files([encrypted_file, decrypted_file])
    print("Program zakończony.")
else:
    print("Pliki pozostaną na pulpicie.")
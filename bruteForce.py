import itertools
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7

# Funkcja generująca klucz z hasła
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Funkcja deszyfrująca plik
def decrypt_file(salt, iv, encrypted_data, password: str):
    key = generate_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    
    decrypted_padded_text = decryptor.update(encrypted_data) + decryptor.finalize()

    
    unpadder = PKCS7(128).unpadder()
    try:
        decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
        return decrypted_text
    except Exception:
        return None  

# Funkcja brute force
def brute_force_attack(file_path: str, max_length: int):
    with open(file_path, 'rb') as file:
        decoded_data = file.read()

    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    encrypted_data = decoded_data[32:]

    characters = string.ascii_lowercase + string.digits  
    for password_length in range(1, max_length + 1):
        for password in itertools.product(characters, repeat=password_length):
            password_str = ''.join(password)
            print(f"Próba hasła: {password_str}")
            decrypted_text = decrypt_file(salt, iv, encrypted_data, password_str)
            
            if decrypted_text is not None:
                try:
                    decrypted_str = decrypted_text.decode('utf-8')
                    
                    print(f'Hasło znalezione: {password_str}')
                    with open('decrypted_file.txt', 'wb') as output_file:
                        output_file.write(decrypted_text)
                    return
                except (UnicodeDecodeError, TypeError):
                    pass  
    print('Nie udało się znaleźć hasła.')

# Atak brute force
brute_force_attack(r'C:\Users\Adrian\Desktop\encrypted_file.txt', max_length=2)  


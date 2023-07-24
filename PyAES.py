import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

def encrypt_text(password, plaintext):
    salt = b'\xdd\xe4\xe6-\x9c\x8b\xb3\x8d\x05\xd5\xb8\x0f\xea\xa7~'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)[:32]

    iv = os.urandom(16)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext  # Include the IV in the returned ciphertext

def decrypt_text(password, ciphertext):
    salt = b'\xdd\xe4\xe6-\x9c\x8b\xb3\x8d\x05\xd5\xb8\x0f\xea\xa7~'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)[:32]

    iv = ciphertext[:16]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return unpadded_plaintext

def start_menu():
    print("Start Menu:")
    print("1. PyEncrypt")
    print("2. PyDecrypt")
    choice = input("Enter your choice (1/2): ")
    if choice == '1':
        py_encrypt()
    elif choice == '2':
        py_decrypt()
    else:
        print("Invalid choice. Please choose a valid option (1 or 2).")

def py_encrypt():
    user_input = input("Enter the text to encrypt: ")
    password = input("Enter the encryption password: ")

    encrypted_data = encrypt_text(password.encode(), user_input.encode())

    print("Encrypted text:", base64.urlsafe_b64encode(encrypted_data).decode())

def py_decrypt():
    encrypted_text = input("Enter the encrypted text: ")
    password = input("Enter the decryption password: ")

    encrypted_data = base64.urlsafe_b64decode(encrypted_text.encode())

    decrypted_data = decrypt_text(password.encode(), encrypted_data)

    print("Decrypted text:", decrypted_data.decode())

if __name__ == "__main__":
    print("Welcome to PyEncrypt/PyDecrypt!")
    start_menu()
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import os

def encrypt_folder(folder, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet = Fernet(key)
    for root, dirs, files in os.walk(folder):
        for filename in files:
            file_path = os.path.join(root, filename)
            with open(file_path, "rb") as file:
                data = file.read()
            encrypted_data = fernet.encrypt(data)
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
    with open("salt.bin", "wb") as f:
        f.write(salt)

def decrypt_folder(folder, password):
    try:
        with open("salt.bin", "rb") as f:
            salt = f.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            iterations=100000,
            salt=salt,
            length=32,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        fernet = Fernet(key)

        for root, dirs, files in os.walk(folder):
            for filename in files:
                file_path = os.path.join(root, filename)
                with open(file_path, "rb") as file:
                    data = file.read()
                decrypted_data = fernet.decrypt(data)
                with open(file_path, "wb") as file:
                    file.write(decrypted_data)

    except InvalidToken:
        print("Error: Invalid password")
    else:
        print("Decryption complete!")



print("Welcome to the folder encryption/decryption program!")
print("1. Encrypt folder")
print("2. Decrypt folder")

choice = input("Enter your choice: ")

if choice == "1":
    folder = input("Enter the folder path: ")
    password = input("Enter the password: ").encode()
    encrypt_folder(folder, password)
    print("Encryption complete!")

elif choice == "2":
    folder = input("Enter the folder path: ")
    password = input("Enter the password: ").encode()
    decrypt_folder(folder, password)


else:
    print("Invalid choice!")



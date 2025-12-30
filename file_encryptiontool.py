import os
import base64
import getpass
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

logging.basicConfig(
    filename="encryption.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename: str):
    password = getpass.getpass("Enter encryption password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filename, "rb") as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    with open(filename + ".enc", "wb") as enc_file:
        enc_file.write(salt + encrypted_data)

    logging.info(f"File encrypted: {filename}")
    print(" File encrypted successfully!")

def decrypt_file(filename: str):
    password = getpass.getpass("Enter decryption password: ")

    with open(filename, "rb") as file:
        file_data = file.read()

    salt = file_data[:16]
    encrypted_data = file_data[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        print("Incorrect password or corrupted file!")
        logging.warning(f"Failed decryption attempt: {filename}")
        return

    output_file = filename.replace(".enc", ".dec")
    with open(output_file, "wb") as dec_file:
        dec_file.write(decrypted_data)

    logging.info(f"File decrypted: {filename}")
    print("File decrypted successfully!")

def main():
    print("\nSecure File Encryption Tool")
    print("1. Encrypt File")
    print("2. Decrypt File")

    choice = input("Choose an option (1/2): ")

    if choice == "1":
        filename = input("Enter filename to encrypt: ")
        if os.path.exists(filename):
            encrypt_file(filename)
        else:
            print("File not found.")

    elif choice == "2":
        filename = input("Enter filename to decrypt (.enc): ")
        if os.path.exists(filename):
            decrypt_file(filename)
        else:
            print(" File not found.")
    else:
        print(" Invalid choice.")

if __name__ == "__main__":
    main()

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class AES256Tool:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt_file(self, input_file: str, output_file: str):
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(salt)
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        file_hash = hashlib.sha256(plaintext).digest()
        with open(output_file, 'wb') as f:
            f.write(salt + iv + file_hash + ciphertext)
        print(f"[+] Encrypted: {output_file}")

    def decrypt_file(self, input_file: str, output_file: str):
        with open(input_file, 'rb') as f:
            data = f.read()
        salt, iv, stored_hash, ciphertext = data[:16], data[16:32], data[32:64], data[64:]
        key = self._derive_key(salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        if hashlib.sha256(plaintext).digest() != stored_hash:
            raise ValueError("Integrity check failed!")
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"[+] Decrypted: {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python encryptor.py [encrypt/decrypt] [password] [file_path]")
    else:
        action, pwd, path = sys.argv[1], sys.argv[2], sys.argv[3]
        tool = AES256Tool(pwd)
        try:
            if action == "encrypt": tool.encrypt_file(path, path + ".enc")
            elif action == "decrypt": tool.decrypt_file(path, path.replace(".enc", "_decrypted.txt"))
        except Exception as e:
            print(f"[-] Error: {e}")

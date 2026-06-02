import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class Symmetric:
    """Модуль для работы с алгоритмом SEED."""

    def __init__(self, block_size_bits: int = 128):
        self.block_size_bytes = block_size_bits // 8

    def generate_key(self, key_size_bytes: int = 16) -> bytes:
        """Генерирует случайный ключ для SEED."""
        return os.urandom(key_size_bytes)

    def encrypt_data(self, plaintext: bytes, key: bytes) -> bytes:
        """Шифрует данные алгоритмом SEED в режиме CBC."""
        iv = os.urandom(self.block_size_bytes)
        
        padder = padding.PKCS7(self.block_size_bytes * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def decrypt_data(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает данные алгоритмом SEED в режиме CBC."""
        if len(ciphertext) < self.block_size_bytes:
            raise ValueError("Некорректная длина шифротекста для извлечения IV.")

        iv = ciphertext[:self.block_size_bytes]
        actual_ciphertext = ciphertext[self.block_size_bytes:]

        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(self.block_size_bytes * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
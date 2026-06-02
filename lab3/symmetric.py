import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class Symmetric:
    """Модуль для работы с алгоритмом SEED."""

    def __init__(self, block_size_bits: int = 128):
        #block_size_bits: Размер блока шифра в битах (для SEED всегда 128).
        self.block_size_bytes = block_size_bits // 8

    def generate_key(self, key_size_bytes: int = 16) -> bytes:
        """Генерирует случайный ключ для SEED."""
        #key_size_bytes: Длина ключа в байтах (по умолчанию 16 для 128 бит).
        #return: Случайная последовательность байтов
        return os.urandom(key_size_bytes)

    def encrypt_data(self, plaintext: bytes, key: bytes) -> bytes:
        """Шифрует данные алгоритмом SEED в режиме CBC."""
        #plaintext: Исходные данные для шифрования.
        #key: Симметричный ключ (16 байт).
        
        if len(key) != 16:
            raise ValueError("Некорректная длина ключа SEED.")
        try:
            iv = os.urandom(self.block_size_bytes)
            # Настройка паддинга PKCS7
            padder = padding.PKCS7(self.block_size_bytes * 8).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            # Создание шифра
            cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            #return: Вектор инициализации (IV) + зашифрованные данные.
            return iv + ciphertext
        
        except Exception as e:
            raise RuntimeError(f"Ошибка процесса симметричного шифрования: {e}")

    def decrypt_data(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает данные алгоритмом SEED в режиме CBC."""
        #ciphertext: Данные формата [IV (16 байт) + Шифротекст].
        #key: Симметричный ключ (16 байт).
        
        if len(key) != 16:
            raise ValueError("Некорректная длина ключа SEED.")
        
        if len(ciphertext) < self.block_size_bytes:
            raise ValueError("Некорректная длина шифротекста для извлечения IV.")

        iv = ciphertext[:self.block_size_bytes]
        actual_ciphertext = ciphertext[self.block_size_bytes:]

        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(self.block_size_bytes * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        #return: Расшифрованные исходные данные.
        return plaintext
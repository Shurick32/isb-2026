import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK_SIZE_BITS = 128  # Размер SEED

def encrypt_file(plaintext_path: str, sym_key: bytes, ciphertext_path: str):
    print(" Чтение исходного файла и шифрование алгоритмом SEED-CBC...")
    with open(plaintext_path, 'rb') as f:
        plaintext = f.read()

    # Выравнивание данных по размеру блока
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Вектор инициализации 
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(sym_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Сохраняем IV + шифротекст
    with open(ciphertext_path, 'wb') as f:
        f.write(iv + ciphertext)

    print("[+] Шифрование успешно завершено.\n")

def decrypt_file(ciphertext_path: str, sym_key: bytes, decrypted_path: str):
    print(" Чтение шифротекста и дешифрование алгоритмом SEED-CBC...")
    with open(ciphertext_path, 'rb') as f:
        raw_data = f.read()

    if len(raw_data) < 16:
        raise ValueError("Файл шифротекста поврежден или слишком мал для извлечения IV.")

    iv = raw_data[:16]
    ciphertext = raw_data[16:]

    cipher = Cipher(algorithms.SEED(sym_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Удаление паддинга
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    print("[+] Дешифрование успешно завершено.\n")
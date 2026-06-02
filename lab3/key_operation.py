import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys(enc_sym_key_path: str, pub_key_path: str, priv_key_path: str):
    print(" Генерация симметричного ключа (SEED, 128 бит)...")
    sym_key = os.urandom(16)  # 128 бит = 16 байт

    print(" Генерация пары ключей RSA (2048 бит)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    print(" Сериализация асимметричных ключей...")
    with open(pub_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(priv_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(" Шифрование симметричного ключа открытым RSA-ключом и сохранение...")
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(enc_sym_key_path, 'wb') as f:
        f.write(encrypted_sym_key)

    print("[+] Генерация ключей успешно завершена.\n")

def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_symmetric_key(enc_sym_key_path: str, private_key):
    with open(enc_sym_key_path, 'rb') as f:
        encrypted_sym_key = f.read()
    return private_key.decrypt(
        encrypted_sym_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
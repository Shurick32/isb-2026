from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class Asymmetric:
    """Модуль для работы с алгоритмом RSA."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        """Генерирует пару ключей RSA."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.public_key, self.private_key

    def serialize_public_key(self, public_key) -> bytes:
        """Сериализует открытый ключ в формат PEM."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self, private_key) -> bytes:
        """Сериализует закрытый ключ в формат PEM."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def load_private_key(self, pem_data: bytes):
        """Десериализует закрытый ключ из PEM."""
        return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

    def encrypt_with_public(self, data: bytes, public_key) -> bytes:
        """Шифрует данные открытым ключом (используется для симметричного ключа)."""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_with_private(self, encrypted_data: bytes, private_key) -> bytes:
        """Расшифровывает данные закрытым ключом."""
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
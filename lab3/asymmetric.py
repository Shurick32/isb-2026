from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class Asymmetric:
    """Модуль для работы с алгоритмом RSA."""
    #key_size: Длина ключа RSA в битах (по умолчанию 2048).
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size 
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        """Генерирует пару ключей RSA."""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            #:return: Кортеж (private_key, public_key).
            return private_key, private_key.public_key()
        except ValueError as e:
            raise ValueError(f"Ошибка генерации ключей RSA {e}")

    def serialize_public_key(self, public_key) -> bytes:
        """Сериализует открытый ключ в формат PEM."""
        #public_key: Объект открытого ключа RSA.
        #return: Байтовая строка (bytes) в формате PEM.
        return public_key.public_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self, private_key) -> bytes:
        """Сериализует закрытый ключ в формат PEM."""
        #private_key: Объект закрытого ключа RSA.
        #return: Байтовая строка (bytes) в формате PEM.
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def load_private_key(self, pem_data: bytes):
        """Десериализует закрытый ключ из PEM."""
        #pem_data: Байтовые данные, считанные из файла .pem.
        #return: Объект закрытого ключа RSA, готовый к использованию для расшифровки.
        try:
            return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
        except (ValueError, TypeError) as e:
            raise ValueError(f"Не удалось загрузить закрытый ключ.{e}")

    def encrypt_with_public(self, data: bytes, public_key) -> bytes:
        """Шифрует данные открытым ключом (используется для симметричного ключа)."""
        #data: Исходные данные для шифрования (байты).
        #public_key: Открытый ключ RSA, которым будет произведено шифрование.
        #return: Зашифрованные данные (байты).
        try:
            return public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise RuntimeError(f"Ошибка асимметричного шифрования: {e}")

    def decrypt_with_private(self, encrypted_data: bytes, private_key) -> bytes:
        """Расшифровывает данные закрытым ключом."""
        #encrypted_data: Зашифрованные данные (байты).
        #private_key: Закрытый ключ RSA, соответствующий открытому ключу шифрования.\
            
        try:
            return private_key.decrypt( #return: Исходные расшифрованные данные (байты).
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            # Часто возникает, если ключи не совпадают или данные битые
            raise ValueError(f"Ошибка расшифровки RSA.{e}")
from asymmetric import Asymmetric
from symmetric import Symmetric
from file_operator import FileOper

class HybridSystem:
    """Оркестратор гибридной криптосистемы."""

    def __init__(self, file_manager: FileOper):
        self.fm = file_manager
        self.asym = Asymmetric(key_size=self.fm.params['rsa_key_size'])
        self.sym = Symmetric(block_size_bits=self.fm.params['seed_key_size_bits'])

    def generate_keys(self):
        """Сценарий 1: Генерация всех ключей системы."""
        print(" Генерация пары ключей RSA...")
        pub_key, priv_key = self.asym.generate_key_pair()
        
        print(" Генерация симметричного ключа SEED...")
        sym_key = self.sym.generate_key()

        print(" Шифрование симметричного ключа алгоритмом RSA...")
        enc_sym_key = self.asym.encrypt_with_public(sym_key, pub_key)

        self.fm.write_binary('public_key', self.asym.serialize_public_key(pub_key))
        self.fm.write_binary('private_key', self.asym.serialize_private_key(priv_key))
        self.fm.write_binary('symmetric_key_enc', enc_sym_key)
        
        print("[SUCCESS] Ключи успешно сгенерированы и сохранены.")

    def encrypt_file(self):
        """Сценарий 2: Шифрование текста."""
        print(" Загрузка закрытого ключа RSA...")
        priv_key_pem = self.fm.read_binary('private_key')
        priv_key = self.asym.load_private_key(priv_key_pem)

        print(" Расшифровка симметричного ключа...")
        enc_sym_key = self.fm.read_binary('symmetric_key_enc')
        sym_key = self.asym.decrypt_with_private(enc_sym_key, priv_key)

        print(" Чтение исходного файла...")
        plaintext = self.fm.read_binary('initial_file')

        print(" Симметричное шифрование данных (SEED)...")
        ciphertext = self.sym.encrypt_data(plaintext, sym_key)

        self.fm.write_binary('encrypted_file', ciphertext)
        print("[SUCCESS] Файл успешно зашифрован.")

    def decrypt_file(self):
        """Сценарий 3: Дешифрование текста."""
        print(" Загрузка закрытого ключа RSA...")
        priv_key_pem = self.fm.read_binary('private_key')
        priv_key = self.asym.load_private_key(priv_key_pem)

        print(" Расшифровка симметричного ключа...")
        enc_sym_key = self.fm.read_binary('symmetric_key_enc')
        sym_key = self.asym.decrypt_with_private(enc_sym_key, priv_key)

        print(" Чтение зашифрованного файла...")
        ciphertext = self.fm.read_binary('encrypted_file')

        print(" Симметричное дешифрование данных (SEED)...")
        plaintext = self.sym.decrypt_data(ciphertext, sym_key)

        self.fm.write_binary('decrypted_file', plaintext)
        print("[SUCCESS] Файл успешно расшифрован.")
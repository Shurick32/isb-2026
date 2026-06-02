import argparse
import sys
import json
import os
from key_operation import generate_keys, load_private_key, decrypt_symmetric_key
from symmetric_crypto import encrypt_file, decrypt_file

def load_settings(config_path: str):
    if not os.path.exists(config_path):
        print(f"Файл конфигурации '{config_path}' не найден. Укажите корректный путь через --config")
        sys.exit(1)
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def ensure_dirs(settings: dict):

    dirs = set()
    for path in settings.values():
        dir_path = os.path.dirname(path)
        if dir_path:
            dirs.add(dir_path)
    for d in sorted(dirs):
        os.makedirs(d, exist_ok=True)

def setup_parser():
    parser = argparse.ArgumentParser(
        description="Лабораторная №3: Гибридная криптосистема (RSA + SEED)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Режим дешифрования')
    parser.add_argument('-c', '--config', required=True, help='Путь к файлу настроек JSON')
    return parser

def main():
    parser = setup_parser()
    args = parser.parse_args()
    
    settings = load_settings(args.config)
    ensure_dirs(settings)
    print(f"📂 Загружена конфигурация из: {args.config}")

    try:
        if args.generation:
            print("\n[1] Запуск режима генерации ключей...")
            generate_keys(
                enc_sym_key_path=settings['symmetric_key'],
                pub_key_path=settings['public_key'],
                priv_key_path=settings['secret_key']
            )
            
        elif args.encryption:
            print("\n[2] Запуск режима шифрования...")
            print(" Расшифровка симметричного ключа...")
            private_key = load_private_key(settings['secret_key'])
            sym_key = decrypt_symmetric_key(settings['symmetric_key'], private_key)
            encrypt_file(
                plaintext_path=settings['initial_file'],
                sym_key=sym_key,
                ciphertext_path=settings['encrypted_file']
            )
            
        elif args.decryption:
            print("\n[3] Запуск режима дешифрования...")
            print(" Расшифровка симметричного ключа...")
            private_key = load_private_key(settings['secret_key'])
            sym_key = decrypt_symmetric_key(settings['symmetric_key'], private_key)
            decrypt_file(
                ciphertext_path=settings['encrypted_file'],
                sym_key=sym_key,
                decrypted_path=settings['decrypted_file']
            )
            
    except FileNotFoundError as e:
        print(f"Ошибка: файл не найден. Проверьте пути в {args.config}. ({e})")
        sys.exit(1)
    except KeyError as e:
        print(f"Ошибка: в {args.config} отсутствует обязательный параметр {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Произошла ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
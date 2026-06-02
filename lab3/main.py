import argparse
import sys
from file_operator import FileOper
from hybrid import HybridSystem

def main():
    parser = argparse.ArgumentParser(
        description="Лабораторная №3: Гибридная криптосистема (RSA + SEED)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Генерация ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Шифрование')
    group.add_argument('-dec', '--decryption', action='store_true', help='Дешифрования')
    
    args = parser.parse_args()

    try:
        fm = FileOper("settings.json")
        system = HybridSystem(fm)

        match True:
            case _ if args.generation:
                system.generate_keys()
            case _ if args.encryption:
                system.encrypt_file()
            case _ if args.decryption:
                system.decrypt_file()
    except FileNotFoundError as e:
        print(f"[ERROR] Ошибка доступа к файлу: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Ошибка данных: {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"\n[ERROR] Ошибка доступа: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[CRITICAL] Неожиданная ошибка: {e}", file=sys.stderr)
        sys.exit(1)
if __name__ == "__main__":
    main()
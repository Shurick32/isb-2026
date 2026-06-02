import os
import json
import sys
from typing import Dict, Any

class FileOper:
    """Класс для управления файловой системой и конфигурацией."""

    def __init__(self, config_path: str = "config.json"):
        """Инициализирует менеджер файлов."""
        #config_path: Путь к файлу конфигурации settings.json
        try:
            self.config = self._load_config(config_path)
            self._ensure_directories()
        except (FileNotFoundError, ValueError) as e:
            print(f"[FATAL ERROR] Ошибка инициализации менеджера файлов: {e}", file=sys.stderr)
            sys.exit(1)

    def _load_config(self, path: str) -> Dict[str, Any]:
        """Загружает конфигурацию из JSON файла."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Конфигурационный файл '{path}' не найден.")
        
        try:
            with open(path, 'r', encoding='utf-8') as f: #path: Путь к конфигурационному файлу.
                return json.load(f) # Словарь с параметрами конфигурации.
        except json.JSONDecodeError:
            raise ValueError(f"Ошибка форматирования в файле '{path}'.")

    def _ensure_directories(self):
        """Создает необходимые директории, если они отсутствуют."""
        for path in self.config['paths'].values():
            directory = os.path.dirname(path)
            if directory:
                try:
                    os.makedirs(directory, exist_ok=True)
                except PermissionError:
                    print(f"[ERROR] Нет прав на создание директории: {directory}", file=sys.stderr)
                    sys.exit(1)

    def read_binary(self, path_key: str) -> bytes:
        """Читает бинарный файл по ключу из конфига."""
        path = self.config['paths'][path_key]
        #path_key: Ключ словаря 'paths' в конфиге (например, 'private_key').
        try:
            with open(path, 'rb') as f:
                return f.read() #Содержимое файла в виде байтов.
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл не найден по пути: {path}")
        except PermissionError:
            raise PermissionError(f"Нет прав на чтение файла: {path}")

    def write_binary(self, path_key: str, data: bytes):
        """Записывает бинарные данные в файл по ключу из конфига."""
        path = self.config['paths'][path_key] #path_key: Ключ словаря 'paths' в конфиге. 
        try:
            with open(path, 'wb') as f:
                f.write(data) #data: Данные типа bytes для записи.
        except PermissionError:
            raise PermissionError(f"Нет прав на запись в файл: {path}")
        except OSError as e:
            raise OSError(f"Ошибка ввода-вывода при записи в {path}: {e}")

    @property
    def paths(self):
        """Возвращает словарь с путями к файлам."""
        return self.config['paths']
    
    @property
    def params(self):
        """Возвращает словарь с криптографическими параметрами (размеры ключей)."""
        return self.config['crypto_params']
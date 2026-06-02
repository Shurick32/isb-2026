import os
import json
from typing import Dict, Any

class FileOper:
    """Класс для управления файловой системой и конфигурацией."""

    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self._ensure_directories()

    def _load_config(self, path: str) -> Dict[str, Any]:
        """Загружает конфигурацию из JSON файла."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Конфигурационный файл '{path}' не найден.")
        except json.JSONDecodeError:
            raise ValueError(f"Ошибка форматирования в файле '{path}'.")

    def _ensure_directories(self):
        """Создает необходимые директории, если они отсутствуют."""
        for path in self.config['paths'].values():
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)

    def read_binary(self, path_key: str) -> bytes:
        """Читает бинарный файл по ключу из конфига."""
        path = self.config['paths'][path_key]
        try:
            with open(path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл не найден по пути: {path}")

    def write_binary(self, path_key: str, data: bytes):
        """Записывает бинарные данные в файл по ключу из конфига."""
        path = self.config['paths'][path_key]
        with open(path, 'wb') as f:
            f.write(data)

    @property
    def paths(self):
        return self.config['paths']
    
    @property
    def params(self):
        return self.config['crypto_params']
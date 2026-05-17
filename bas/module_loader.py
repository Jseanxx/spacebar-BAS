# YAML에 적힌 모듈명을 실제 파이썬 파일로 import

import importlib


def load_module(module_path):
    full_module_path = f"modules.{module_path}"
    return importlib.import_module(full_module_path)

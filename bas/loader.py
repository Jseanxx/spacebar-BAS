# YAML 파일 읽어서 파이썬 dict로 바꿔줌

from pathlib import Path
import yaml


BASE_DIR = Path(__file__).resolve().parent.parent


def load_campaign(campaign_id):
    path = BASE_DIR / "campaigns" / f"{campaign_id}.yaml"
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_target(target_id):
    path = BASE_DIR / "targets" / f"{target_id}.yaml"
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)

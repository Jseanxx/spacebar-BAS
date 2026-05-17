# 실행 결과를 outputs/runs/*.json  파일로 저장

from pathlib import Path
import json


BASE_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = BASE_DIR / "outputs" / "runs"


def write_run_result(execution_id, result):
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    path = RUNS_DIR / f"{execution_id}.json"
    with path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    return path

# react UI가 이 API.py 호출
"""
GET /health : API 살아있는지 확인
GET /campaigns : 캠페인 목록 가져오기
GET /campaigns/SB-05 : SB-05 캠페인 상세 가져오기
POST /runs : 캠페인 실행
GET /runs : 실행 기록 목록 가져오기
GET /runs/{id} : 특정 실행 결과 가져오기 
"""

from pathlib import Path
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from bas.controller import run_campaign
from bas.loader import load_campaign, load_target

from fastapi.middleware.cors import CORSMiddleware


BASE_DIR = Path(__file__).resolve().parent
CAMPAIGNS_DIR = BASE_DIR / "campaigns"
TARGETS_DIR = BASE_DIR / "targets"
RUNS_DIR = BASE_DIR / "outputs" / "runs"


app = FastAPI(title="Mini BAS API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



class RunRequest(BaseModel):
    campaign_id: str = "SB-05"
    selected_orders: list[int] | None = None
    include_normal: bool = True


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "mini-bas"
    }


@app.get("/campaigns")
def list_campaigns():
    campaigns = []

    for path in CAMPAIGNS_DIR.glob("*.yaml"):
        campaign_id = path.stem
        campaign = load_campaign(campaign_id)

        campaigns.append({
            "campaign_id": campaign.get("campaign_id"),
            "campaign_name": campaign.get("campaign_name"),
            "description": campaign.get("description"),
            "step_count": len(campaign.get("flow", []))
        })

    return {
        "campaigns": campaigns
    }


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str):
    try:
        return load_campaign(campaign_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign not found")


@app.get("/targets/{target_id}")
def get_target(target_id: str):
    try:
        return load_target(target_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Target not found")


@app.post("/runs")
def create_run(request: RunRequest):
    try:
        result, output_path = run_campaign(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            include_normal=request.include_normal,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign or target file not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "message": "campaign executed",
        "execution_id": result["execution_id"],
        "campaign_id": result["campaign_id"],
        "campaign_name": result["campaign_name"],
        "result_path": str(output_path),
        "step_count": len(result.get("steps", [])),
        "result": result
    }


@app.get("/runs")
def list_runs():
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    runs = []

    for path in sorted(RUNS_DIR.glob("*.json"), reverse=True):
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        runs.append({
            "execution_id": data.get("execution_id"),
            "campaign_id": data.get("campaign_id"),
            "campaign_name": data.get("campaign_name"),
            "started_at": data.get("started_at"),
            "finished_at": data.get("finished_at"),
            "step_count": len(data.get("steps", [])),
            "file": str(path)
        })

    return {
        "runs": runs
    }


@app.get("/runs/{execution_id}")
def get_run(execution_id: str):
    path = RUNS_DIR / f"{execution_id}.json"

    if not path.exists():
        raise HTTPException(status_code=404, detail="Run result not found")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

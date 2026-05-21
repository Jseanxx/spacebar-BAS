from pathlib import Path
from datetime import datetime, timezone, timedelta
import json
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from bas.controller import run_campaign
from bas.loader import load_campaign, load_target


BASE_DIR = Path(__file__).resolve().parent
CAMPAIGNS_DIR = BASE_DIR / "campaigns"
RUNS_DIR = BASE_DIR / "outputs" / "runs"

JOBS_DIR = BASE_DIR / "outputs" / "jobs"
AGENTS_DIR = BASE_DIR / "outputs" / "agents"

KST = timezone(timedelta(hours=9))

def now_kst():
    # Controller와 BasAgent 간 상태 시간을 한국 시간 기준으로 남깁니다.
    return datetime.now(KST).isoformat(timespec="seconds")


app = FastAPI(title="Mini BAS API", version="0.3.0")


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
    """
    캠페인 실행 요청 모델입니다.

    selected_orders가 None이면 전체 캠페인을 실행합니다.
    selected_orders가 있으면 선택한 단계와 필요한 의존 단계만 실행합니다.
    """

    campaign_id: str = "SB-05"
    selected_orders: list[int] | None = None
    include_normal: bool = True


class PreviewRequest(BaseModel):
    """
    실제 실행 없이 최종 실행 계획만 확인하는 요청 모델입니다.
    """

    campaign_id: str = "SB-05"
    selected_orders: list[int] | None = None
    include_normal: bool = True

class AgentRegisterRequest(BaseModel):
    """
    BasAgent가 중앙 Controller에 처음 등록할 때 사용하는 요청 모델입니다.

    agent_id는 CampaignAgent 환경 안에 설치된 BasAgent의 고유 이름입니다.
    예: jseanxx-sb05-agent
    """

    agent_id: str
    campaign_agent_id: str = "SB-05"
    display_name: str | None = None
    collector_type: str | None = "elastic_agent"


class AgentHeartbeatRequest(BaseModel):
    """
    BasAgent가 살아 있는지 Controller에 주기적으로 알리는 요청 모델입니다.
    """

    status: str = "online"


class JobRequest(BaseModel):
    """
    Controller가 BasAgent에게 실행시킬 작업을 만들 때 사용하는 요청 모델입니다.
    """

    agent_id: str
    campaign_id: str = "SB-05"
    selected_orders: list[int] | None = None
    include_normal: bool = True


class JobResultRequest(BaseModel):
    """
    BasAgent가 캠페인 실행 결과를 Controller에 업로드할 때 사용하는 요청 모델입니다.
    """

    status: str
    execution_id: str | None = None
    result: dict | None = None
    error: str | None = None


def get_bas_agent_status_payload():
    """
    현재 로컬 BAS 실행 엔진 상태를 반환합니다.

    최종 구조에서는 이 값이 실제 CampaignAgent 환경에 설치된 BasAgent의
    register/heartbeat 정보로 대체됩니다.
    """

    bas_agent = {
        "type": "local_bas_agent",
        "runner": "campaign_runner",
        "mode": "simulation",
        "policy": {
            "on_step_failure": "continue",
            "resolve_dependencies": True,
            "include_normal_supported": True,
        },
    }

    return {
        "bas_agent": bas_agent,

        # 기존 프론트/테스트 호환용 필드입니다.
        # 새 코드에서는 bas_agent를 기준으로 사용하면 됩니다.
        "agent": bas_agent,
    }


def load_sorted_steps(campaign):
    """
    campaign YAML의 flow를 order 기준으로 정렬합니다.

    중요한 줄:
    BAS 실행 순서는 YAML 작성 순서가 아니라 order 값으로 결정됩니다.
    """

    return sorted(campaign.get("flow", []), key=lambda item: item.get("order", 0))


def resolve_dependencies(steps, requested_orders):
    """
    selected_orders의 depends_on_orders를 따라가며 필요한 선행 단계를 자동 포함합니다.
    """

    step_by_order = {
        step.get("order"): step
        for step in steps
    }

    resolved = set(requested_orders or [])

    def visit(order):
        step = step_by_order.get(order)

        if not step:
            return

        for dependency in step.get("depends_on_orders", []):
            if dependency not in resolved:
                resolved.add(dependency)
                visit(dependency)

    for order in list(resolved):
        visit(order)

    return sorted(resolved)


def build_execution_plan(campaign_id, selected_orders=None, include_normal=True):
    """
    실제 모듈 실행 없이 최종 실행 계획만 계산합니다.

    이 함수의 의미:
    - 프론트에서 Run Campaign을 누르기 전에 실행 범위를 보여줄 수 있습니다.
    - 잘못된 selected_orders를 실제 실행 전에 차단할 수 있습니다.
    """

    campaign = load_campaign(campaign_id)
    steps = load_sorted_steps(campaign)

    requested_orders = sorted(selected_orders or [])
    valid_orders = {
        step.get("order")
        for step in steps
    }

    invalid_orders = [
        order for order in requested_orders
        if order not in valid_orders
    ]

    # 중요한 줄: YAML에 존재하지 않는 order 요청은 실행 전에 400 에러로 막습니다.
    if invalid_orders:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Invalid selected_orders",
                "invalid_orders": invalid_orders,
                "valid_orders": sorted(valid_orders),
            },
        )

    if not requested_orders:
        final_orders = [
            step.get("order")
            for step in steps
        ]

        return {
            "campaign_id": campaign.get("campaign_id"),
            "campaign_name": campaign.get("campaign_name"),
            "requested_orders": [],
            "auto_included_orders": [],
            "final_orders": final_orders,
            "steps": steps,
        }

    resolved_attack_orders = resolve_dependencies(steps, requested_orders)

    auto_included_orders = [
        order for order in resolved_attack_orders
        if order not in requested_orders
    ]

    max_order = max(resolved_attack_orders)
    final_orders = set(resolved_attack_orders)

    if include_normal:
        for step in steps:
            is_normal_step = step.get("phase") == "normal"
            is_before_attack = step.get("order", 0) <= max_order

            # 선택 공격 단계 이전의 normal 단계도 포함해 baseline 흐름을 보존합니다.
            if is_normal_step and is_before_attack:
                final_orders.add(step.get("order"))

    final_orders = sorted(final_orders)

    return {
        "campaign_id": campaign.get("campaign_id"),
        "campaign_name": campaign.get("campaign_name"),
        "requested_orders": requested_orders,
        "auto_included_orders": auto_included_orders,
        "final_orders": final_orders,
        "steps": [
            step for step in steps
            if step.get("order") in final_orders
        ],
    }

def read_json_file(path, default):
    # 파일이 아직 없으면 기본값을 반환합니다. MVP 단계에서 DB 대신 JSON 파일을 쓰기 위한 함수입니다.
    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def write_json_file(path, data):
    # JSON 저장 위치가 없으면 자동으로 만듭니다.
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def get_agent_path(agent_id):
    return AGENTS_DIR / f"{agent_id}.json"


def get_job_path(job_id):
    return JOBS_DIR / f"{job_id}.json"


def load_job(job_id):
    path = get_job_path(job_id)

    if not path.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    return read_json_file(path, {})


def delete_campaign_history_files(directory, campaign_id, skip_running_jobs=False):
    directory.mkdir(parents=True, exist_ok=True)

    deleted = []
    skipped = []

    for path in sorted(directory.glob("*.json")):
        data = read_json_file(path, {})

        if data.get("campaign_id") != campaign_id:
            continue

        if skip_running_jobs and data.get("status") == "running":
            skipped.append(path.name)
            continue

        path.unlink()
        deleted.append(path.name)

    return deleted, skipped

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "mini-bas",
    }


@app.get("/bas-agent/status")
def get_bas_agent_status():
    """
    현재 BAS 실행 엔진 정보를 반환합니다.

    프론트에서 BasAgent 상태 배지를 보여줄 때 사용할 수 있습니다.
    """

    return get_bas_agent_status_payload()


@app.get("/agent/status")
def get_agent_status_legacy():
    """
    기존 /agent/status 호출을 위한 호환용 엔드포인트입니다.

    새 프론트에서는 /bas-agent/status를 사용하는 것을 권장합니다.
    """

    return get_bas_agent_status_payload()

@app.post("/agents/register")
def register_agent(request: AgentRegisterRequest):
    """
    BasAgent 등록 API입니다.

    지금은 DB 없이 outputs/agents/{agent_id}.json 파일로 저장합니다.
    나중에 SQLite나 DB로 바꿔도 API 형태는 유지할 수 있습니다.
    """

    agent = {
        "agent_id": request.agent_id,
        "campaign_agent_id": request.campaign_agent_id,
        "display_name": request.display_name or request.agent_id,
        "collector_type": request.collector_type,
        "status": "registered",
        "registered_at": now_kst(),
        "last_heartbeat_at": None,
    }

    write_json_file(get_agent_path(request.agent_id), agent)

    return {
        "message": "agent registered",
        "agent": agent,
    }


@app.post("/agents/{agent_id}/heartbeat")
def heartbeat_agent(agent_id: str, request: AgentHeartbeatRequest):
    """
    BasAgent 생존 확인 API입니다.

    BasAgent는 주기적으로 이 API를 호출해서 Controller에 살아 있음을 알립니다.
    """

    path = get_agent_path(agent_id)
    agent = read_json_file(path, {
        "agent_id": agent_id,
        "campaign_agent_id": None,
        "display_name": agent_id,
        "collector_type": None,
        "registered_at": None,
    })

    agent["status"] = request.status
    agent["last_heartbeat_at"] = now_kst()

    write_json_file(path, agent)

    return {
        "message": "heartbeat received",
        "agent": agent,
    }


@app.get("/agents")
def list_agents():
    """
    등록된 BasAgent 목록을 반환합니다.
    """

    AGENTS_DIR.mkdir(parents=True, exist_ok=True)

    agents = []

    for path in sorted(AGENTS_DIR.glob("*.json")):
        agents.append(read_json_file(path, {}))

    return {
        "agents": agents,
    }


@app.post("/jobs")
def create_job(request: JobRequest):
    """
    BasAgent가 가져갈 실행 Job을 생성합니다.

    이 API는 나중에 React UI의 '캠페인 실행' 버튼과 연결됩니다.
    """

    try:
        build_execution_plan(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            include_normal=request.include_normal,
        )
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign file not found")

    job_id = f"job-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    job = {
        "job_id": job_id,
        "agent_id": request.agent_id,
        "campaign_id": request.campaign_id,
        "selected_orders": request.selected_orders,
        "include_normal": request.include_normal,
        "status": "queued",
        "created_at": now_kst(),
        "started_at": None,
        "finished_at": None,
        "execution_id": None,
        "result": None,
        "error": None,
    }

    write_json_file(get_job_path(job_id), job)

    return {
        "message": "job created",
        "job": job,
    }


@app.get("/jobs")
def list_jobs():
    """
    생성된 Job 목록을 반환합니다.
    """

    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    jobs = []

    for path in sorted(JOBS_DIR.glob("*.json"), reverse=True):
        jobs.append(read_json_file(path, {}))

    return {
        "jobs": jobs,
    }


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    """
    특정 Job 상세 정보를 반환합니다.
    """

    return load_job(job_id)


@app.get("/agents/{agent_id}/jobs/next")
def get_next_job(agent_id: str):
    """
    BasAgent가 자신에게 할당된 다음 queued Job을 가져가는 API입니다.

    중요한 점:
    - status가 queued인 Job만 가져갑니다.
    - 가져가는 순간 running으로 바꿔 중복 실행을 줄입니다.
    """

    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    for path in sorted(JOBS_DIR.glob("*.json")):
        job = read_json_file(path, {})

        if job.get("agent_id") != agent_id:
            continue

        if job.get("status") != "queued":
            continue

        job["status"] = "running"
        job["started_at"] = now_kst()
        write_json_file(path, job)

        return {
            "job": job,
        }

    return {
        "job": None,
    }


@app.post("/agents/{agent_id}/jobs/{job_id}/result")
def submit_job_result(agent_id: str, job_id: str, request: JobResultRequest):
    """
    BasAgent가 캠페인 실행 결과를 Controller에 업로드하는 API입니다.
    """

    job = load_job(job_id)

    if job.get("agent_id") != agent_id:
        raise HTTPException(status_code=403, detail="Job does not belong to this agent")

    job["status"] = request.status
    job["finished_at"] = now_kst()
    job["execution_id"] = request.execution_id
    job["result"] = request.result
    job["error"] = request.error

    write_json_file(get_job_path(job_id), job)

    return {
        "message": "job result received",
        "job": job,
    }

@app.get("/campaigns")
def list_campaigns():
    campaigns = []

    for path in CAMPAIGNS_DIR.glob("*.yaml"):
        campaign = load_campaign(path.stem)

        campaigns.append({
            "campaign_id": campaign.get("campaign_id"),
            "campaign_name": campaign.get("campaign_name"),
            "description": campaign.get("description"),
            "step_count": len(campaign.get("flow", [])),
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


@app.delete("/campaigns/{campaign_id}/history")
def reset_campaign_history(campaign_id: str):
    """
    특정 캠페인의 실행 기록만 초기화합니다.

    삭제 대상:
    - outputs/runs/*.json 중 campaign_id가 일치하는 파일
    - outputs/jobs/*.json 중 campaign_id가 일치하는 파일

    유지 대상:
    - campaign YAML
    - target YAML
    - agent 등록/heartbeat 파일
    """

    try:
        load_campaign(campaign_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign not found")

    deleted_runs, _ = delete_campaign_history_files(
        RUNS_DIR,
        campaign_id,
    )
    deleted_jobs, skipped_jobs = delete_campaign_history_files(
        JOBS_DIR,
        campaign_id,
        skip_running_jobs=True,
    )

    return {
        "message": "campaign history reset",
        "campaign_id": campaign_id,
        "deleted_runs": len(deleted_runs),
        "deleted_jobs": len(deleted_jobs),
        "skipped_jobs": skipped_jobs,
    }


@app.get("/targets/{target_id}")
def get_target(target_id: str):
    try:
        return load_target(target_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Target not found")


@app.post("/runs/preview")
def preview_run(request: PreviewRequest):
    """
    실제 실행 없이 최종 실행 계획만 반환합니다.
    """

    try:
        return build_execution_plan(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            include_normal=request.include_normal,
        )
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign file not found")


@app.post("/runs")
def create_run(request: RunRequest):
    try:
        # 실제 실행 전에 selected_orders가 유효한지 먼저 검증합니다.
        build_execution_plan(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            include_normal=request.include_normal,
        )

        result, output_path = run_campaign(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            include_normal=request.include_normal,
        )

    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign or target file not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "message": "campaign executed",
        "execution_id": result["execution_id"],
        "campaign_id": result["campaign_id"],
        "campaign_name": result["campaign_name"],
        "bas_agent": result.get("bas_agent"),

        # 기존 프론트/테스트 호환용 필드입니다.
        "agent": result.get("agent") or result.get("bas_agent"),

        "result_path": str(output_path),
        "step_count": len(result.get("steps", [])),
        "requested_orders": result.get("requested_orders"),
        "auto_included_orders": result.get("auto_included_orders"),
        "final_orders": result.get("final_orders"),
        "result": result,
    }


@app.get("/runs")
def list_runs():
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    runs = []

    for path in sorted(RUNS_DIR.glob("*.json"), reverse=True):
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        bas_agent = data.get("bas_agent") or data.get("agent")

        runs.append({
            "execution_id": data.get("execution_id"),
            "campaign_id": data.get("campaign_id"),
            "campaign_name": data.get("campaign_name"),
            "started_at": data.get("started_at"),
            "finished_at": data.get("finished_at"),
            "bas_agent": bas_agent,

            # 기존 프론트/테스트 호환용 필드입니다.
            "agent": bas_agent,

            "requested_orders": data.get("requested_orders"),
            "auto_included_orders": data.get("auto_included_orders"),
            "final_orders": data.get("final_orders"),
            "step_count": len(data.get("steps", [])),
            "file": str(path),
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

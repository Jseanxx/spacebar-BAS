from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
import json
import os
import time
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from bas.controller import run_campaign
from bas.elk_checker import check_elk, resolve_query
from bas.loader import load_campaign, load_target
from bas.report_builder import REPORTS_DIR, build_report_from_operation, build_report_from_run, render_summary_html


BASE_DIR = Path(__file__).resolve().parent
CAMPAIGNS_DIR = BASE_DIR / "campaigns"
RUNS_DIR = BASE_DIR / "outputs" / "runs"

JOBS_DIR = BASE_DIR / "outputs" / "jobs"
AGENTS_DIR = BASE_DIR / "outputs" / "agents"
OPERATIONS_DIR = BASE_DIR / "outputs" / "operations"

KST = timezone(timedelta(hours=9))

def now_kst():
    # Controller와 BasAgent 간 상태 시간을 한국 시간 기준으로 남깁니다.
    return datetime.now(KST).isoformat(timespec="seconds")


app = FastAPI(title="Mini BAS API", version="0.3.0")


def verify_agent_token(http_request: Request):
    """
    Optional shared-secret check for public Controller deployments.

    Local/dev deployments can omit BAS_AGENT_TOKEN. When it is set, BasAgent
    register/heartbeat/job polling endpoints must include either
    X-BAS-Agent-Token: <token> or Authorization: Bearer <token>.
    """

    expected = os.environ.get("BAS_AGENT_TOKEN")
    if not expected:
        return

    provided = http_request.headers.get("x-bas-agent-token")
    authorization = http_request.headers.get("authorization") or ""
    if not provided and authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()

    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid BasAgent token")


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://[::1]:5173",
        "http://[::1]:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class StepSelection(BaseModel):
    campaign_id: str
    order: int
    inputs: Optional[dict[str, object]] = None


class RunRequest(BaseModel):
    """
    캠페인 실행 요청 모델입니다.

    selected_orders가 None이면 전체 캠페인을 실행합니다.
    selected_orders가 있으면 선택한 단계와 필요한 의존 단계만 실행합니다.
    """

    campaign_id: str = "SB-05"
    selected_orders: Optional[list[int]] = None
    selected_steps: Optional[list[StepSelection]] = None
    include_normal: bool = True


class PreviewRequest(BaseModel):
    """
    실제 실행 없이 최종 실행 계획만 확인하는 요청 모델입니다.
    """

    campaign_id: str = "SB-05"
    selected_orders: Optional[list[int]] = None
    selected_steps: Optional[list[StepSelection]] = None
    include_normal: bool = True

class AgentRegisterRequest(BaseModel):
    """
    BasAgent가 중앙 Controller에 처음 등록할 때 사용하는 요청 모델입니다.

    agent_id는 CampaignAgent 환경 안에 설치된 BasAgent의 고유 이름입니다.
    예: jseanxx-sb05-agent
    """

    agent_id: str
    campaign_agent_id: str = "SB-05"
    display_name: Optional[str] = None
    collector_type: Optional[str] = "elastic_agent"
    agent_role: Optional[str] = None
    asset_id: Optional[str] = None
    segment_id: Optional[str] = None
    hostname: Optional[str] = None
    platform: Optional[str] = None
    execution_mode: Optional[str] = "real"
    safety_mode: Optional[str] = None
    capabilities: Optional[Union[list[str], str]] = None
    controls: Optional[Union[list[str], str]] = None


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
    selected_orders: Optional[list[int]] = None
    selected_steps: Optional[list[StepSelection]] = None
    include_normal: bool = True
    execution_mode: Optional[str] = None


class BlockedJobRequest(BaseModel):
    """
    Agent가 꺼져 있어 실행하지 못한 요청을 UI/보고서용으로 남길 때 사용합니다.
    """

    campaign_id: str = "SB-AD"
    selected_steps: Optional[list[StepSelection]] = None
    reason: str = "agent_offline"
    missing_agent_roles: Optional[list[str]] = None


class OperationRequest(BaseModel):
    """
    여러 Agent 역할에 걸친 SB-AD 실행 요청 모델입니다.
    """

    campaign_id: str = "SB-AD"
    selected_orders: Optional[list[int]] = None
    selected_steps: Optional[list[StepSelection]] = None
    include_normal: bool = False
    operation_mode: str = "multi_agent"
    execution_mode: str = "real"


class JobResultRequest(BaseModel):
    """
    BasAgent가 캠페인 실행 결과를 Controller에 업로드할 때 사용하는 요청 모델입니다.
    """

    status: str
    execution_id: Optional[str] = None
    result: Optional[dict] = None
    error: Optional[str] = None


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


def load_technique_library():
    """
    모든 campaign YAML의 flow를 독립 실행 가능한 technique library로 모읍니다.

    campaign은 실행 컨텍스트로 남기고, 사용자는 여기서 원하는 step을 큐에 담아
    조합형 operation을 만들 수 있습니다.
    """

    techniques = []

    for path in sorted(CAMPAIGNS_DIR.glob("*.yaml")):
        campaign = load_campaign(path.stem)
        campaign_id = campaign.get("campaign_id") or path.stem

        for step in load_sorted_steps(campaign):
            step_copy = dict(step)
            step_copy["source_campaign_id"] = campaign_id
            step_copy["source_campaign_name"] = campaign.get("campaign_name")
            step_copy["selection_id"] = f"{campaign_id}:{step.get('order')}"
            techniques.append(step_copy)

    return techniques


def resolve_selected_steps(selected_steps):
    """
    selected_steps payload를 실제 step 객체 목록으로 변환합니다.
    """

    if not selected_steps:
        return None

    library = {
        technique["selection_id"]: technique
        for technique in load_technique_library()
    }

    resolved = []
    invalid_steps = []

    for selection in selected_steps:
        selection_id = f"{selection.campaign_id}:{selection.order}"
        step = library.get(selection_id)

        if not step:
            invalid_steps.append({
                "campaign_id": selection.campaign_id,
                "order": selection.order,
            })
            continue

        step_copy = dict(step)
        step_copy["selected_inputs"] = selection.inputs or {}
        resolved.append(step_copy)

    if invalid_steps:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Invalid selected_steps",
                "invalid_steps": invalid_steps,
            },
        )

    return resolved


def get_step_behavior(step):
    return step.get("params", {}).get("behavior")


def build_technique_compatibility(campaign_id):
    """
    선택한 campaign target 기준으로 전체 technique library를 dry-run 판정합니다.

    실제 공격이나 ELK 검색은 수행하지 않고:
    - 실행 구성: step.requires가 target.capabilities에 모두 있는지
    - 탐지 기준: exact query 또는 자동 생성 query를 만들 수 있는지
    를 계산합니다.
    """

    target = load_target(campaign_id)
    capabilities = set(target.get("capabilities", []))
    compatibility = {}

    for step in load_technique_library():
        selection_id = step.get("selection_id")
        requires = step.get("requires", [])
        missing_capabilities = [
            requirement
            for requirement in requires
            if requirement not in capabilities
        ]

        behavior = get_step_behavior(step)
        query_source = "not_applicable"
        query = None

        if behavior:
            query, query_source = resolve_query(target, behavior)

        query_ready = query_source in ("configured", "generated", "not_applicable")
        is_compatible = not missing_capabilities and query_ready

        compatibility[selection_id] = {
            "selection_id": selection_id,
            "status": "compatible" if is_compatible else "incompatible",
            "label": "호환" if is_compatible else "비호환",
            "missing_capabilities": missing_capabilities,
            "behavior": behavior,
            "query_source": query_source,
            "query_preview": query,
        }

    return compatibility


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


def build_execution_plan(campaign_id, selected_orders=None, selected_steps=None, include_normal=True):
    """
    실제 모듈 실행 없이 최종 실행 계획만 계산합니다.

    이 함수의 의미:
    - 프론트에서 Run Campaign을 누르기 전에 실행 범위를 보여줄 수 있습니다.
    - 잘못된 selected_orders를 실제 실행 전에 차단할 수 있습니다.
    """

    campaign = load_campaign(campaign_id)

    custom_steps = resolve_selected_steps(selected_steps)
    if custom_steps is not None:
        return {
            "campaign_id": campaign.get("campaign_id"),
            "campaign_name": campaign.get("campaign_name"),
            "requested_orders": [],
            "requested_steps": [
                {
                    "campaign_id": step.get("source_campaign_id"),
                    "order": step.get("order"),
                    "inputs": step.get("selected_inputs", {}),
                }
                for step in custom_steps
            ],
            "auto_included_orders": [],
            "final_orders": [
                step.get("order")
                for step in custom_steps
            ],
            "steps": custom_steps,
            "operation_mode": "custom",
        }

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
            "requested_steps": [],
            "auto_included_orders": [],
            "final_orders": final_orders,
            "steps": steps,
            "operation_mode": "campaign",
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
        "requested_steps": [],
        "auto_included_orders": auto_included_orders,
        "final_orders": final_orders,
        "steps": [
            step for step in steps
            if step.get("order") in final_orders
        ],
        "operation_mode": "campaign",
    }

def read_json_file(path, default):
    # 파일이 아직 없으면 기본값을 반환합니다. MVP 단계에서 DB 대신 JSON 파일을 쓰기 위한 함수입니다.
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return default


def write_json_file(path, data):
    # JSON 저장 위치가 없으면 자동으로 만듭니다.
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def normalize_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return [
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    ]


def merge_unique_lists(*values):
    merged = []

    for value in values:
        for item in normalize_list(value):
            if item not in merged:
                merged.append(item)

    return merged


def load_registered_agents():
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)

    agents = []

    for path in sorted(AGENTS_DIR.glob("*.json")):
        agent = read_json_file(path, {})
        if agent.get("status") == "online" and not is_agent_fresh(agent):
            agent = {
                **agent,
                "reported_status": agent.get("status"),
                "status": "offline",
                "stale": True,
            }
        agents.append(agent)

    return agents


def parse_iso_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def is_agent_fresh(agent, stale_after_seconds=60):
    if not agent or agent.get("status") != "online":
        return False

    heartbeat_at = parse_iso_datetime(agent.get("last_heartbeat_at"))
    if not heartbeat_at:
        return False

    return datetime.now(KST) - heartbeat_at <= timedelta(seconds=stale_after_seconds)


def load_agent_or_404(agent_id):
    agent = read_json_file(get_agent_path(agent_id), None)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return agent


def resolve_step_agent_role(step):
    params = step.get("params", {}) or {}
    commands = params.get("commands", []) or []

    if commands and commands[0].get("agent_role"):
        return commands[0].get("agent_role")

    return params.get("agent_role") or step.get("agent_role") or "campaign_agent"


def resolve_step_asset_id(step):
    params = step.get("params", {}) or {}
    explicit_asset_id = params.get("target_asset_id") or params.get("asset_id") or step.get("target_asset_id") or step.get("asset_id")
    if explicit_asset_id:
        return str(explicit_asset_id).lower()

    target_id = step.get("target") or step.get("source_campaign_id") or step.get("campaign_id")
    behavior = params.get("behavior") or step.get("behavior")
    if target_id == "SB-05":
        sb05_behavior_asset_map = {
            "sb05_ssh_access_check": "sb05-attacker",
            "kube_get_pods": "sb05-kubernetes",
            "kube_get_services": "prod-platform",
            "kube_get_deployments": "prod-platform",
            "kube_resource_discovery": "sb05-kubernetes",
            "kube_secret_access": "prod-platform",
            "kube_pod_exec": "prod-platform",
            "kube_deploy_collector": "sb05-kubernetes",
            "kube_rbac_addition": "sb05-kubernetes",
            "local_data_staging": "sb05-attacker",
            "archive_staged_data": "sb05-attacker",
            "s3_exfiltration": "sb05-k8s-drain",
        }
        if behavior in sb05_behavior_asset_map:
            return sb05_behavior_asset_map[behavior]

    behavior_asset_map = {
        "kerberoasting_tgs_request": "dc01",
        "winrm_remote_execution": "fs01",
        "powershell_over_winrm": "fs01",
        "ingress_tool_transfer": "fs01",
        "lsass_memory_dump": "fs01",
        "rundll32_comsvcs_proxy": "fs01",
        "local_data_staging": "fs01",
        "exfiltration_over_c2": "fs01",
        "masquerading_legitimate_name": "fs01",
        "archive_collected_data": "fs01",
        "dcsync_replication": "dc01",
        "golden_ticket_service_ticket": "dc01",
        "valid_domain_account_remote_logon": "dc01",
        "service_execution": "dc01",
        "ntds_dump": "dc01",
    }
    if behavior in behavior_asset_map:
        return behavior_asset_map[behavior]

    execution_host = str(params.get("execution_host") or step.get("execution_host") or "").lower()
    if "fs01" in execution_host:
        return "fs01"
    if "dc01" in execution_host:
        return "dc01"
    if "pc01" in execution_host:
        return "pc01"
    if "attacker" in execution_host:
        return "attacker"

    role = resolve_step_agent_role(step)
    return role if role in ("attacker", "pc01", "fs01", "dc01", "elk") else None


def select_online_agent(campaign_id, agent_role):
    campaign_prefix = str(campaign_id or "").lower().replace("-", "")

    def campaign_matches(agent):
        explicit_campaign = agent.get("campaign_agent_id")
        if explicit_campaign == campaign_id:
            return True
        if explicit_campaign:
            return False
        agent_id = str(agent.get("agent_id") or "").lower().replace("-", "")
        return bool(campaign_prefix and agent_id.startswith(campaign_prefix))

    def role_matches(agent):
        if agent_role == "campaign_agent":
            return True
        explicit_role = agent.get("agent_role")
        if explicit_role == agent_role:
            return True
        if explicit_role:
            return False
        return infer_agent_asset_id(agent) == agent_role

    candidates = [
        agent
        for agent in load_registered_agents()
        if campaign_matches(agent)
        and is_agent_fresh(agent)
        and role_matches(agent)
    ]

    if agent_role == "campaign_agent":
        candidates.sort(key=lambda agent: agent.get("last_heartbeat_at") or "", reverse=True)
        candidates.sort(key=lambda agent: 0 if agent.get("agent_role") in (None, "", "campaign_agent") else 1)
        return candidates[0] if candidates else None

    candidates.sort(key=lambda agent: agent.get("last_heartbeat_at") or "", reverse=True)
    return candidates[0] if candidates else None


def infer_agent_asset_id(agent):
    explicit_asset_id = agent.get("asset_id")
    if explicit_asset_id:
        return str(explicit_asset_id).lower()

    explicit_role = agent.get("agent_role")
    if explicit_role and explicit_role not in ("campaign_agent", "log_source", "detection_backend"):
        return str(explicit_role).lower()

    searchable = " ".join(
        str(agent.get(field) or "")
        for field in ("agent_id", "display_name", "hostname", "agent_role")
    ).lower()

    for asset_id in ("attacker", "bastion", "pms", "win01", "pc01", "fs01", "dc01", "soc01", "elk"):
        if asset_id in searchable:
            return asset_id

    return None


def build_discovered_asset_from_agent(agent):
    asset_id = (
        infer_agent_asset_id(agent)
        or agent.get("agent_role")
        or agent.get("hostname")
        or agent.get("agent_id")
    )

    return {
        "asset_id": asset_id,
        "name": agent.get("display_name") or agent.get("hostname") or asset_id,
        "hostname": agent.get("hostname"),
        "platform": agent.get("platform"),
        "role": agent.get("agent_role") or "BAS Agent discovered asset",
        "segment_id": agent.get("segment_id"),
        "agent_role": agent.get("agent_role"),
        "agent_required": True,
        "criticality": "medium",
        "controls": normalize_list(agent.get("controls")),
        "capabilities": normalize_list(agent.get("capabilities")),
        "discovery_source": "agent_registration",
        "discovered_by_agent": agent.get("agent_id"),
    }


def build_asset_discovery(target_id):
    target = load_target(target_id)
    target_assets = target.get("assets", []) or []
    assets_by_id = {
        asset.get("asset_id"): dict(asset)
        for asset in target_assets
        if asset.get("asset_id")
    }
    asset_id_by_agent_role = {
        asset.get("agent_role"): asset.get("asset_id")
        for asset in target_assets
        if asset.get("agent_role") and asset.get("asset_id")
    }
    required_asset_ids = [
        asset.get("asset_id")
        for asset in target_assets
        if asset.get("agent_required") and asset.get("asset_id")
    ]
    target_agents = [
        agent
        for agent in load_registered_agents()
        if agent.get("campaign_agent_id") == target_id
    ]

    for agent in target_agents:
        discovered = build_discovered_asset_from_agent(agent)
        asset_id = asset_id_by_agent_role.get(agent.get("agent_role")) or discovered.get("asset_id")
        agent_label = " ".join(
            str(agent.get(field) or "")
            for field in ("agent_id", "display_name", "hostname", "agent_role")
        ).lower()
        is_generic_bas_agent = "basagent" in agent_label or "bas-agent" in agent_label

        if is_generic_bas_agent and asset_id not in assets_by_id and len(required_asset_ids) == 1:
            asset_id = required_asset_ids[0]

        if is_generic_bas_agent and asset_id not in assets_by_id:
            continue

        if asset_id:
            discovered["asset_id"] = asset_id

        if not asset_id:
            continue

        existing = assets_by_id.get(asset_id, {})
        existing_agent = existing.get("agent") or {}
        if existing_agent.get("status") == "online" and agent.get("status") != "online":
            continue

        merged = {
            **discovered,
            **existing,
            "controls": merge_unique_lists(existing.get("controls"), discovered.get("controls")),
            "capabilities": merge_unique_lists(existing.get("capabilities"), discovered.get("capabilities")),
            "discovery_source": "target_inventory+agent_registration" if existing else "agent_registration",
            "discovered_by_agent": agent.get("agent_id"),
            "agent": {
                "agent_id": agent.get("agent_id"),
                "display_name": agent.get("display_name"),
                "status": agent.get("status"),
                "last_heartbeat_at": agent.get("last_heartbeat_at"),
            },
        }

        for key, value in discovered.items():
            if merged.get(key) in (None, "", []):
                merged[key] = value

        assets_by_id[asset_id] = merged

    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "discovery_mode": "target_inventory_plus_agent_registration",
        "assets": list(assets_by_id.values()),
        "segments": target.get("segments", []),
        "security_controls": target.get("security_controls", []),
        "attack_paths": target.get("attack_paths", []),
        "agents": target_agents,
        "summary": {
            "target_inventory_assets": len(target_assets),
            "registered_agents": len(target_agents),
            "discovered_assets": len(assets_by_id),
        },
    }


def dump_step_selection(selection):
    return {
        "campaign_id": selection.campaign_id,
        "order": selection.order,
        "inputs": selection.inputs or {},
    }


def get_agent_path(agent_id):
    return AGENTS_DIR / f"{agent_id}.json"


def get_job_path(job_id):
    return JOBS_DIR / f"{job_id}.json"


def get_operation_path(operation_id):
    return OPERATIONS_DIR / f"{operation_id}.json"


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


def load_operation(operation_id):
    path = get_operation_path(operation_id)

    if not path.exists():
        raise HTTPException(status_code=404, detail="Operation not found")

    return read_json_file(path, {})


def write_operation(operation):
    write_json_file(get_operation_path(operation["operation_id"]), operation)


def apply_report_classification_to_operation(operation, report):
    classified_by_key = {}
    for classified_step in report.get("steps", []):
        key = (classified_step.get("order"), classified_step.get("job_id"))
        classified_by_key[key] = classified_step
        classified_by_key[(classified_step.get("order"), None)] = classified_step

    for step in operation.get("final_steps", []):
        classified_step = classified_by_key.get((step.get("order"), step.get("job_id"))) \
            or classified_by_key.get((step.get("order"), None))
        if not classified_step:
            continue

        for field in (
            "execution_status",
            "detection_status",
            "source_status",
            "alert_status",
            "source_event_count",
            "alert_count",
            "gap_type",
            "recommendation",
            "attack_name",
            "target_asset",
            "required_condition",
            "expected_log",
            "detection_rule",
            "detection_result",
            "coverage_status",
            "system_impact",
            "risk_level",
            "recommended_sensor",
            "improvement_plan",
            "queries",
        ):
            step[field] = classified_step.get(field)


def attach_operation_report(operation):
    try:
        if (
            operation.get("status") in ("completed", "simulated", "blocked", "failed")
            and operation.get("execution_mode") != "simulation"
        ):
            operation = attach_deferred_elk_checks(operation)
        report = build_report_from_operation(operation)
        apply_report_classification_to_operation(operation, report)
        operation["report"] = {
            "report_id": report.get("report_id"),
            "source_id": report.get("source_id"),
            "generated_at": report.get("generated_at"),
            "summary": report.get("summary"),
            "backlog_count": len(report.get("backlog", [])),
            "artifact_paths": report.get("artifact_paths"),
        }
        operation.pop("report_error", None)
    except Exception as exc:
        operation["report_error"] = str(exc)

    return operation


def get_operation_step_evidence(step):
    module_result = step.get("module_result") or {}
    result_step = step.get("result_step") or {}
    result_module = result_step.get("module_result") or {}
    runtime_context = (
        step.get("runtime_context")
        or result_step.get("runtime_context")
        or module_result.get("runtime_context")
        or result_module.get("runtime_context")
        or {}
    )

    return {
        "evidence_key": module_result.get("evidence_key") or result_module.get("evidence_key"),
        "target_id": step.get("target_id") or result_step.get("target_id"),
        "operation_id": step.get("operation_id") or runtime_context.get("_operation_id"),
        "job_id": step.get("job_id") or runtime_context.get("_job_id"),
        "execution_marker": step.get("execution_marker") or runtime_context.get("_execution_marker"),
        "step_order": step.get("order") or runtime_context.get("_step_order"),
        "time_window": {
            "started_at": result_step.get("started_at") or step.get("started_at"),
            "finished_at": result_step.get("finished_at") or step.get("finished_at"),
        },
    }


def should_defer_check_step(step):
    if step.get("status") in ("simulated", "blocked", "failed"):
        return False

    evidence = get_operation_step_evidence(step)
    return bool(evidence["evidence_key"] and evidence["target_id"])


def run_step_elk_check(step):
    evidence = get_operation_step_evidence(step)
    target = load_target(evidence["target_id"])
    return check_elk(
        target,
        evidence["evidence_key"],
        execution_context={
            "operation_id": evidence.get("operation_id"),
            "job_id": evidence.get("job_id"),
            "execution_marker": evidence.get("execution_marker"),
            "step_order": evidence.get("step_order"),
            "time_window": evidence.get("time_window") or {},
        },
    )


def attach_deferred_elk_checks(operation):
    if operation.get("execution_mode") == "simulation":
        return operation

    steps_to_check = [
        step
        for step in operation.get("final_steps", [])
        if should_defer_check_step(step)
    ]
    if not steps_to_check:
        return operation

    if all((step.get("elk_check") or {}).get("checked") for step in steps_to_check):
        return operation

    target_wait_seconds = 0
    try:
        target_config = load_target(operation.get("campaign_id"))
        target_wait_seconds = int((target_config.get("elk") or {}).get("alert_wait_seconds") or 0)
    except Exception:
        target_wait_seconds = 0

    wait_seconds = int(os.environ.get(
        "BAS_OPERATION_ELK_WAIT_SECONDS",
        os.environ.get("BAS_STEP_ALERT_WAIT_SECONDS", str(target_wait_seconds)),
    ) or "0")

    operation["elk_validation_status"] = "waiting" if wait_seconds > 0 else "running"
    operation["elk_validation_strategy"] = "deferred_parallel"
    operation["elk_validation_started_at"] = now_kst()
    write_operation(operation)

    if wait_seconds > 0:
        time.sleep(wait_seconds)

    max_workers = int(os.environ.get("BAS_ELK_PARALLEL_WORKERS", "8") or "8")
    max_workers = max(1, min(max_workers, len(steps_to_check)))
    step_indices = {id(step): index for index, step in enumerate(operation.get("final_steps", []))}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_by_index = {
            executor.submit(run_step_elk_check, step): step_indices[id(step)]
            for step in steps_to_check
        }

        for future in as_completed(future_by_index):
            step_index = future_by_index[future]
            try:
                operation["final_steps"][step_index]["elk_check"] = future.result()
            except Exception as exc:
                operation["final_steps"][step_index]["elk_check"] = {
                    "checked": False,
                    "matched": None,
                    "event_count": None,
                    "sample_events": [],
                    "message": f"Deferred ELK check failed: {exc}",
                }

    operation["elk_validation_status"] = "completed"
    operation["elk_validation_finished_at"] = now_kst()
    return operation


def build_operation_summary(final_steps):
    summary = {
        "total": len(final_steps),
        "queued": 0,
        "running": 0,
        "success": 0,
        "failed": 0,
        "blocked": 0,
        "simulated": 0,
        "pending": 0,
        "cancelled": 0,
    }

    for step in final_steps:
        status = step.get("status", "pending")

        if status in ("completed", "success"):
            summary["success"] += 1
        elif status == "simulated":
            summary["simulated"] += 1
        elif status == "failed":
            summary["failed"] += 1
        elif status == "blocked":
            summary["blocked"] += 1
        elif status == "cancelled":
            summary["cancelled"] += 1
        elif status == "running":
            summary["running"] += 1
        elif status == "queued":
            summary["queued"] += 1
        else:
            summary["pending"] += 1

    return summary


def create_operation_job(operation, step_entry):
    if step_entry.get("execution_location") == "controller":
        return create_controller_operation_job(operation, step_entry)

    agent = select_online_agent(operation["campaign_id"], step_entry["agent_role"])

    if not agent:
        if operation.get("execution_mode") == "simulation":
            step_entry["status"] = "simulated"
            step_entry["simulation_reason"] = "agent_offline"
        else:
            step_entry["status"] = "blocked"
            step_entry["blocked_reason"] = "agent_offline"
        step_entry["would_route_to"] = step_entry["agent_role"]
        step_entry["finished_at"] = now_kst()
        operation["summary"] = build_operation_summary(operation["final_steps"])
        write_operation(operation)
        return None

    job_id = f"job-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    execution_marker = step_entry.get("execution_marker") or f"{operation['operation_id']}-step-{step_entry.get('order')}"
    runtime_context = {
        "_operation_id": operation["operation_id"],
        "_job_id": job_id,
        "_execution_marker": execution_marker,
        "_step_order": step_entry.get("order"),
    }
    job = {
        "job_id": job_id,
        "operation_id": operation["operation_id"],
        "agent_id": agent.get("agent_id"),
        "agent_role": step_entry["agent_role"],
        "campaign_id": operation["campaign_id"],
        "selected_orders": None,
        "selected_steps": [
            {
                "campaign_id": step_entry["campaign_id"],
                "order": step_entry["order"],
                "inputs": step_entry.get("inputs", {}),
                "runtime_context": runtime_context,
            }
        ],
        "include_normal": False,
        "execution_mode": operation.get("execution_mode"),
        "defer_elk_checks": True,
        "status": "queued",
        "created_at": now_kst(),
        "started_at": None,
        "finished_at": None,
        "execution_id": None,
        "result": None,
        "error": None,
    }

    step_entry["status"] = "queued"
    step_entry["agent_id"] = agent.get("agent_id")
    step_entry["job_id"] = job_id
    step_entry["operation_id"] = operation["operation_id"]
    step_entry["execution_marker"] = execution_marker
    step_entry["runtime_context"] = runtime_context
    operation["status"] = "running"
    operation["summary"] = build_operation_summary(operation["final_steps"])

    write_json_file(get_job_path(job_id), job)
    write_operation(operation)

    return job


def create_controller_operation_job(operation, step_entry):
    job_id = f"job-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    runtime_context = step_entry.get("runtime_context") or {
        "_operation_id": operation["operation_id"],
        "_execution_marker": step_entry.get("execution_marker"),
        "_step_order": step_entry.get("order"),
    }
    job = {
        "job_id": job_id,
        "operation_id": operation["operation_id"],
        "agent_id": "controller",
        "agent_role": "controller",
        "campaign_id": operation["campaign_id"],
        "selected_orders": None,
        "selected_steps": [
            {
                "campaign_id": step_entry["campaign_id"],
                "order": step_entry["order"],
                "inputs": step_entry.get("inputs", {}),
                "runtime_context": runtime_context,
            }
        ],
        "include_normal": False,
        "execution_mode": operation.get("execution_mode"),
        "defer_elk_checks": True,
        "status": "running",
        "created_at": now_kst(),
        "started_at": now_kst(),
        "finished_at": None,
        "execution_id": None,
        "result": None,
        "error": None,
    }

    step_entry["status"] = "running"
    step_entry["agent_id"] = "controller"
    step_entry["agent_role"] = "controller"
    step_entry["job_id"] = job_id
    step_entry["operation_id"] = operation["operation_id"]
    step_entry["runtime_context"] = runtime_context
    operation["status"] = "running"
    operation["summary"] = build_operation_summary(operation["final_steps"])
    write_json_file(get_job_path(job_id), job)
    write_operation(operation)

    previous_defer_elk = os.environ.get("BAS_DEFER_ELK_CHECKS")
    if job.get("defer_elk_checks", False):
        os.environ["BAS_DEFER_ELK_CHECKS"] = "1"

    try:
        result, _ = run_campaign(
            campaign_id=operation["campaign_id"],
            selected_orders=None,
            selected_steps=job["selected_steps"],
            include_normal=False,
            execution_mode=operation.get("execution_mode"),
        )
        job["status"] = "completed"
        job["execution_id"] = result.get("execution_id")
        job["result"] = result
        job["error"] = None
    except Exception as exc:
        job["status"] = "failed"
        job["execution_id"] = None
        job["result"] = None
        job["error"] = str(exc)
    finally:
        if previous_defer_elk is None:
            os.environ.pop("BAS_DEFER_ELK_CHECKS", None)
        else:
            os.environ["BAS_DEFER_ELK_CHECKS"] = previous_defer_elk

    job["finished_at"] = now_kst()
    write_json_file(get_job_path(job_id), job)
    update_operation_from_job_result(job)

    return job


def enqueue_next_operation_job(operation):
    if operation.get("status") in ("completed", "blocked", "cancelled", "failed", "simulated"):
        return None

    active_step = next(
        (
            step
            for step in operation.get("final_steps", [])
            if step.get("status") in ("queued", "running")
        ),
        None,
    )
    if active_step:
        return None

    while True:
        next_step = next(
            (
                step
                for step in operation.get("final_steps", [])
                if step.get("status", "pending") == "pending"
            ),
            None,
        )

        if not next_step:
            summary = build_operation_summary(operation["final_steps"])
            if summary["blocked"] == summary["total"]:
                operation["status"] = "blocked"
            elif summary["cancelled"] == summary["total"]:
                operation["status"] = "cancelled"
            elif summary["simulated"] == summary["total"]:
                operation["status"] = "simulated"
            else:
                operation["status"] = "completed"
            operation["finished_at"] = now_kst()
            operation["summary"] = summary
            operation = attach_deferred_elk_checks(operation)
            operation = attach_operation_report(operation)
            write_operation(operation)
            return None

        job = create_operation_job(operation, next_step)
        if job:
            return job

        operation = load_operation(operation["operation_id"])


def get_primary_job_step(job):
    result = job.get("result") or {}
    steps = result.get("steps") or []
    return steps[0] if steps else {}


def resolve_operation_step_status(job):
    result_step = get_primary_job_step(job)
    step_status = result_step.get("status")

    if step_status in ("success", "simulated", "failed", "blocked"):
        return step_status

    if step_status in ("manual_required", "not_supported"):
        return "simulated" if job.get("execution_mode") == "simulation" else "blocked"

    if job.get("status") != "completed":
        return "failed"

    return "success"


def sync_operation_result_fields(step_entry, job):
    result_step = get_primary_job_step(job)

    if result_step:
        step_entry["phase"] = result_step.get("phase")
        step_entry["elk_check"] = result_step.get("elk_check")
        step_entry["module_result"] = result_step.get("module_result")
        step_entry["result_step"] = result_step
        step_entry["target_id"] = result_step.get("target_id")

    if step_entry.get("status") == "simulated" and not step_entry.get("simulation_reason"):
        step_entry["simulation_reason"] = result_step.get("module_result", {}).get("message") or "module_simulated"
    if step_entry.get("status") == "blocked" and not step_entry.get("blocked_reason"):
        step_entry["blocked_reason"] = result_step.get("status") or result_step.get("module_result", {}).get("message") or "real_execution_blocked"


def emit_sbav_controller_normalized_events(step_entry):
    """
    SB-AV Windows mini Agent가 구버전 schema로 source event를 보냈더라도,
    Controller가 동일 step 결과를 Hanguel handoff schema로 한 번 더 적재합니다.

    Windows VM의 실행 중인 PowerShell Agent를 재시작하지 않아도
    `hanguel.ad_agent` / `hanguel.classification` / `hanguel.risk_score`
    기반 correlation 검증을 이어가기 위한 보정 경로입니다.
    """

    if step_entry.get("campaign_id") != "SB-AV":
        return None
    if step_entry.get("agent_role") not in ("win01", "dc01"):
        return None
    if step_entry.get("status") != "success":
        return None

    module_result = step_entry.get("module_result") or {}
    if module_result.get("controller_hanguel_event_emission"):
        return module_result.get("controller_hanguel_event_emission")

    try:
        from modules.attack import sb_av_hanguel_chain

        target = load_target("SB-AV")
        campaign = load_campaign("SB-AV")
        campaign_step = next(
            (
                item
                for item in campaign.get("flow", [])
                if item.get("order") == step_entry.get("order")
            ),
            {},
        )
        params = dict((campaign_step.get("params") or {}))
        runtime_context = step_entry.get("runtime_context") or {}
        params.update(runtime_context)
        params["_operation_id"] = params.get("_operation_id") or step_entry.get("operation_id")
        params["_execution_marker"] = params.get("_execution_marker") or step_entry.get("execution_marker")
        params["_step_order"] = params.get("_step_order") or step_entry.get("order")

        if not params.get("behavior"):
            params["behavior"] = module_result.get("behavior")
        if not params.get("technique_id"):
            params["technique_id"] = step_entry.get("technique_id")

        base_result = {
            "status": module_result.get("status") or step_entry.get("status"),
            "command_results": module_result.get("command_results") or [],
        }
        emission = sb_av_hanguel_chain.emit_hanguel_events(target, params, base_result)
        module_result["controller_hanguel_event_emission"] = emission
        step_entry["module_result"] = module_result
        return emission
    except Exception as exc:
        module_result["controller_hanguel_event_emission"] = {
            "configured": False,
            "message": f"Controller-side SB-AV Hanguel event emission failed: {exc}",
        }
        step_entry["module_result"] = module_result
        return module_result["controller_hanguel_event_emission"]


def finalize_operation_if_done(operation):
    summary = build_operation_summary(operation["final_steps"])
    operation["summary"] = summary

    if summary["pending"] == 0 and summary["queued"] == 0 and summary["running"] == 0:
        if summary["blocked"] == summary["total"]:
            operation["status"] = "blocked"
        elif summary["cancelled"] == summary["total"]:
            operation["status"] = "cancelled"
        elif summary["simulated"] == summary["total"]:
            operation["status"] = "simulated"
        elif summary["failed"] == summary["total"]:
            operation["status"] = "failed"
        else:
            operation["status"] = "completed"
        operation["finished_at"] = now_kst()
        operation = attach_deferred_elk_checks(operation)
        operation = attach_operation_report(operation)
        write_operation(operation)

    return operation


def update_operation_from_job_result(job):
    operation_id = job.get("operation_id")
    if not operation_id:
        return None

    operation = load_operation(operation_id)
    step_entry = next(
        (
            step
            for step in operation.get("final_steps", [])
            if step.get("job_id") == job.get("job_id")
        ),
        None,
    )

    if not step_entry:
        return operation

    if (
        step_entry.get("status") == "success"
        and job.get("status") == "failed"
        and not job.get("result")
        and str(job.get("error") or "").lower() == "timed out"
    ):
        return operation

    resolved_status = resolve_operation_step_status(job)
    step_entry["status"] = resolved_status
    step_entry["finished_at"] = job.get("finished_at")
    step_entry["execution_id"] = job.get("execution_id")
    step_entry["error"] = job.get("error") if resolved_status == "failed" else None
    step_entry["result"] = job.get("result")
    sync_operation_result_fields(step_entry, job)
    emit_sbav_controller_normalized_events(step_entry)
    operation["sub_jobs"] = merge_unique_lists(operation.get("sub_jobs"), [job.get("job_id")])
    operation = finalize_operation_if_done(operation)

    enqueue_next_operation_job(operation)
    return load_operation(operation_id)


def mark_operation_job_running(job):
    operation_id = job.get("operation_id")
    if not operation_id:
        return

    operation = load_operation(operation_id)
    for step in operation.get("final_steps", []):
        if step.get("job_id") == job.get("job_id"):
            step["status"] = "running"
            step["started_at"] = job.get("started_at")
            break

    operation["summary"] = build_operation_summary(operation.get("final_steps", []))
    write_operation(operation)

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
def register_agent(request: AgentRegisterRequest, http_request: Request):
    """
    BasAgent 등록 API입니다.

    지금은 DB 없이 outputs/agents/{agent_id}.json 파일로 저장합니다.
    나중에 SQLite나 DB로 바꿔도 API 형태는 유지할 수 있습니다.
    """

    verify_agent_token(http_request)

    agent = {
        "agent_id": request.agent_id,
        "campaign_agent_id": request.campaign_agent_id,
        "display_name": request.display_name or request.agent_id,
        "collector_type": request.collector_type,
        "agent_role": request.agent_role,
        "asset_id": request.asset_id,
        "segment_id": request.segment_id,
        "hostname": request.hostname,
        "platform": request.platform,
        "execution_mode": request.execution_mode,
        "safety_mode": request.safety_mode,
        "capabilities": normalize_list(request.capabilities),
        "controls": normalize_list(request.controls),
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
def heartbeat_agent(agent_id: str, request: AgentHeartbeatRequest, http_request: Request):
    """
    BasAgent 생존 확인 API입니다.

    BasAgent는 주기적으로 이 API를 호출해서 Controller에 살아 있음을 알립니다.
    """

    verify_agent_token(http_request)

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

    agents = load_registered_agents()

    return {
        "agents": agents,
    }


@app.get("/targets/{target_id}/asset-discovery")
def discover_target_assets(target_id: str):
    """
    target YAML의 기준 자산과 실제 등록된 BasAgent 메타데이터를 합쳐
    BAS 검증 대상 자산 목록을 반환합니다.
    """

    try:
        return build_asset_discovery(target_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Target not found")


@app.post("/operations")
def create_operation(request: OperationRequest):
    """
    selected step을 agent_role 기준으로 순차 라우팅하는 multi-agent operation을 생성합니다.
    """

    try:
        plan = build_execution_plan(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            selected_steps=request.selected_steps,
            include_normal=request.include_normal,
        )
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign file not found")

    operation_id = f"op-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    final_steps = []
    missing_roles = []

    for step in sorted(plan.get("steps", []), key=lambda item: item.get("order", 0)):
        role = resolve_step_agent_role(step)
        step_entry = {
            "campaign_id": step.get("source_campaign_id") or step.get("campaign_id") or request.campaign_id,
            "order": step.get("order"),
            "technique_id": step.get("technique_id"),
            "name": step.get("name"),
            "agent_role": role,
            "asset_id": resolve_step_asset_id(step),
            "execution_host": (step.get("params") or {}).get("execution_host"),
            "execution_location": (step.get("params") or {}).get("execution_location"),
            "inputs": step.get("selected_inputs", {}),
            "status": "pending",
            "agent_id": None,
            "job_id": None,
            "operation_id": operation_id,
            "execution_marker": f"{operation_id}-step-{step.get('order')}",
            "runtime_context": {
                "_operation_id": operation_id,
                "_execution_marker": f"{operation_id}-step-{step.get('order')}",
                "_step_order": step.get("order"),
            },
        }

        if step_entry.get("execution_location") != "controller" and not select_online_agent(request.campaign_id, role):
            missing_roles.append(role)

        final_steps.append(step_entry)

    operation = {
        "operation_id": operation_id,
        "campaign_id": request.campaign_id,
        "campaign_name": plan.get("campaign_name"),
        "operation_mode": request.operation_mode,
        "execution_mode": request.execution_mode,
        "status": "pending",
        "created_at": now_kst(),
        "started_at": now_kst(),
        "finished_at": None,
        "requested_orders": plan.get("requested_orders", []),
        "requested_steps": plan.get("requested_steps", []),
        "final_steps": final_steps,
        "sub_jobs": [],
        "blocked_roles": sorted(set(missing_roles)),
        "summary": build_operation_summary(final_steps),
    }

    write_operation(operation)
    enqueue_next_operation_job(operation)
    operation = load_operation(operation_id)

    return {
        "message": "operation created",
        "operation": operation,
    }


@app.get("/operations")
def list_operations():
    OPERATIONS_DIR.mkdir(parents=True, exist_ok=True)

    operations = [
        read_json_file(path, {})
        for path in sorted(OPERATIONS_DIR.glob("*.json"), reverse=True)
    ]

    return {
        "operations": operations,
    }


@app.get("/operations/{operation_id}")
def get_operation(operation_id: str):
    return load_operation(operation_id)


@app.post("/operations/{operation_id}/cancel")
def cancel_operation(operation_id: str):
    operation = load_operation(operation_id)

    if operation.get("status") in ("completed", "failed", "blocked", "cancelled"):
        return {
            "message": "operation already finished",
            "operation": operation,
        }

    operation["status"] = "cancelled"
    operation["finished_at"] = now_kst()

    for step in operation.get("final_steps", []):
        if step.get("status") in ("pending", "queued"):
            step["status"] = "blocked"
            step["blocked_reason"] = "operation_cancelled"

    operation["summary"] = build_operation_summary(operation.get("final_steps", []))
    write_operation(operation)

    return {
        "message": "operation cancelled",
        "operation": operation,
    }


@app.post("/operations/{operation_id}/steps/{step_index}/cancel")
def cancel_operation_step(operation_id: str, step_index: int):
    operation = load_operation(operation_id)
    steps = operation.get("final_steps", [])

    if step_index < 0 or step_index >= len(steps):
        raise HTTPException(status_code=404, detail="Operation step not found")

    step = steps[step_index]
    status = step.get("status", "pending")

    if status == "running":
        raise HTTPException(status_code=409, detail="Running step cannot be cancelled from the UI")

    if status in ("completed", "success", "simulated", "failed", "blocked", "cancelled"):
        return {
            "message": "step already finished",
            "operation": operation,
        }

    job_id = step.get("job_id")
    if job_id:
        try:
            job = load_job(job_id)
            if job.get("status") == "queued":
                job["status"] = "cancelled"
                job["finished_at"] = now_kst()
                job["error"] = "cancelled_by_user"
                write_json_file(get_job_path(job_id), job)
            elif job.get("status") == "running":
                raise HTTPException(status_code=409, detail="Running step cannot be cancelled from the UI")
        except HTTPException as exc:
            if exc.status_code == 409:
                raise

    step["status"] = "cancelled"
    step["cancelled_reason"] = "cancelled_by_user"
    step["finished_at"] = now_kst()
    operation["summary"] = build_operation_summary(steps)
    write_operation(operation)

    operation = load_operation(operation_id)
    operation = finalize_operation_if_done(operation)

    if operation.get("status") not in ("completed", "failed", "blocked", "cancelled", "simulated"):
        enqueue_next_operation_job(operation)
        operation = load_operation(operation_id)

    return {
        "message": "step cancelled",
        "operation": operation,
    }


def normalize_report_source_id(report_id):
    if report_id.startswith("report-"):
        candidate = report_id.removeprefix("report-")
        if (REPORTS_DIR / f"{candidate}.report.json").exists():
            return candidate

    return report_id


def load_report(report_id):
    source_id = normalize_report_source_id(report_id)
    path = REPORTS_DIR / f"{source_id}.report.json"

    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return read_json_file(path, {})


def read_report_artifact(report_id, suffix, media_type):
    source_id = normalize_report_source_id(report_id)
    path = REPORTS_DIR / f"{source_id}.{suffix}"

    if not path.exists():
        raise HTTPException(status_code=404, detail="Report artifact not found")

    return Response(content=path.read_text(encoding="utf-8"), media_type=media_type)


@app.post("/operations/{operation_id}/report")
def create_operation_report(operation_id: str):
    operation = load_operation(operation_id)

    try:
        report = build_report_from_operation(operation)
        apply_report_classification_to_operation(operation, report)
        operation["report"] = {
            "report_id": report.get("report_id"),
            "source_id": report.get("source_id"),
            "generated_at": report.get("generated_at"),
            "summary": report.get("summary"),
            "backlog_count": len(report.get("backlog", [])),
            "artifact_paths": report.get("artifact_paths"),
        }
        operation.pop("report_error", None)
        write_operation(operation)
        return report
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/runs/{execution_id}/report")
def create_run_report(execution_id: str):
    try:
        return build_report_from_run(execution_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Run result not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/reports")
def list_reports():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    reports = []

    for path in sorted(REPORTS_DIR.glob("*.report.json"), reverse=True):
        report = read_json_file(path, {})
        reports.append({
            "report_id": report.get("report_id"),
            "source_type": report.get("source_type"),
            "source_id": report.get("source_id"),
            "campaign_id": report.get("campaign_id"),
            "campaign_name": report.get("campaign_name"),
            "generated_at": report.get("generated_at"),
            "summary": report.get("summary"),
            "backlog_count": len(report.get("backlog", [])),
            "file": str(path),
        })

    return {"reports": reports}


@app.get("/reports/{report_id}")
def get_report(report_id: str):
    return load_report(report_id)


@app.get("/reports/{report_id}/summary.md")
def get_report_summary(report_id: str):
    return read_report_artifact(report_id, "summary.md", "text/markdown")


@app.get("/reports/{report_id}/summary.html")
def get_report_summary_html(report_id: str):
    return Response(content=render_summary_html(load_report(report_id)), media_type="text/html")


@app.get("/reports/{report_id}/technical.md")
def get_report_technical(report_id: str):
    return read_report_artifact(report_id, "technical.md", "text/markdown")


@app.get("/reports/{report_id}/backlog.csv")
def get_report_backlog(report_id: str):
    return read_report_artifact(report_id, "detection-backlog.csv", "text/csv")


@app.get("/reports/{report_id}/coverage.csv")
def get_report_coverage(report_id: str):
    return read_report_artifact(report_id, "coverage.csv", "text/csv")


@app.get("/reports/{report_id}/navigator.json")
def get_report_navigator(report_id: str):
    source_id = normalize_report_source_id(report_id)
    path = REPORTS_DIR / f"{source_id}.attack-navigator.json"

    if not path.exists():
        raise HTTPException(status_code=404, detail="Report artifact not found")

    return read_json_file(path, {})


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
            selected_steps=request.selected_steps,
            include_normal=request.include_normal,
        )
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign file not found")

    agent = load_agent_or_404(request.agent_id)
    if not is_agent_fresh(agent):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Agent is offline or heartbeat is stale",
                "agent_id": request.agent_id,
                "agent_role": agent.get("agent_role"),
                "status": agent.get("status"),
                "last_heartbeat_at": agent.get("last_heartbeat_at"),
            },
        )

    job_id = f"job-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    job = {
        "job_id": job_id,
        "agent_id": request.agent_id,
        "campaign_id": request.campaign_id,
        "selected_orders": request.selected_orders,
        "selected_steps": [
            dump_step_selection(selection)
            for selection in request.selected_steps or []
        ],
        "include_normal": request.include_normal,
        "execution_mode": request.execution_mode or agent.get("execution_mode") or "simulation",
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


@app.post("/jobs/blocked")
def create_blocked_job(request: BlockedJobRequest):
    """
    Agent가 꺼져 있어 실행을 의도적으로 차단한 기록을 남깁니다.

    실제 Agent job은 만들지 않으므로, Agent가 켜진 뒤 같은 큐를 다시 실행하면 됩니다.
    """

    job_id = f"blocked-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    job = {
        "job_id": job_id,
        "agent_id": None,
        "campaign_id": request.campaign_id,
        "selected_orders": None,
        "selected_steps": [
            dump_step_selection(selection)
            for selection in request.selected_steps or []
        ],
        "include_normal": False,
        "status": "blocked",
        "reason": request.reason,
        "missing_agent_roles": request.missing_agent_roles or [],
        "created_at": now_kst(),
        "started_at": None,
        "finished_at": now_kst(),
        "execution_id": None,
        "result": None,
        "error": request.reason,
    }

    write_json_file(get_job_path(job_id), job)

    return {
        "message": "job blocked",
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
def get_next_job(agent_id: str, http_request: Request):
    """
    BasAgent가 자신에게 할당된 다음 queued Job을 가져가는 API입니다.

    중요한 점:
    - status가 queued인 Job만 가져갑니다.
    - 가져가는 순간 running으로 바꿔 중복 실행을 줄입니다.
    """

    verify_agent_token(http_request)

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
        mark_operation_job_running(job)

        return {
            "job": job,
        }

    return {
        "job": None,
    }


@app.post("/agents/{agent_id}/jobs/{job_id}/result")
def submit_job_result(agent_id: str, job_id: str, request: JobResultRequest, http_request: Request):
    """
    BasAgent가 캠페인 실행 결과를 Controller에 업로드하는 API입니다.
    """

    verify_agent_token(http_request)

    job = load_job(job_id)

    if job.get("agent_id") != agent_id:
        raise HTTPException(status_code=403, detail="Job does not belong to this agent")

    agent_path = get_agent_path(agent_id)
    agent = read_json_file(agent_path, None)
    if agent:
        agent["status"] = "online"
        agent["last_heartbeat_at"] = now_kst()
        write_json_file(agent_path, agent)

    if (
        request.status == "failed"
        and not request.result
        and str(request.error or "").lower() == "timed out"
        and job.get("status") == "completed"
        and job.get("result")
    ):
        operation = load_operation(job.get("operation_id")) if job.get("operation_id") else None
        return {
            "message": "late timeout result ignored",
            "job": job,
            "operation": operation,
        }

    job["status"] = request.status
    job["finished_at"] = now_kst()
    job["execution_id"] = request.execution_id
    job["result"] = request.result
    job["error"] = request.error

    write_json_file(get_job_path(job_id), job)
    operation = update_operation_from_job_result(job)

    return {
        "message": "job result received",
        "job": job,
        "operation": operation,
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


@app.get("/techniques")
def list_techniques():
    return {
        "techniques": load_technique_library()
    }


@app.get("/campaigns/{campaign_id}/technique-compatibility")
def get_technique_compatibility(campaign_id: str):
    try:
        return {
            "campaign_id": campaign_id,
            "compatibility": build_technique_compatibility(campaign_id),
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign or target not found")


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
    - operation/report 기록
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
            selected_steps=request.selected_steps,
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
            selected_steps=request.selected_steps,
            include_normal=request.include_normal,
        )

        result, output_path = run_campaign(
            campaign_id=request.campaign_id,
            selected_orders=request.selected_orders,
            selected_steps=[
                dump_step_selection(selection)
                for selection in request.selected_steps or []
            ],
            include_normal=request.include_normal,
        )

    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Campaign or target file not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    report = None
    report_error = None
    try:
        report = build_report_from_run(result["execution_id"])
    except Exception as exc:
        report_error = str(exc)

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
        "requested_steps": result.get("requested_steps"),
        "auto_included_orders": result.get("auto_included_orders"),
        "final_orders": result.get("final_orders"),
        "report": {
            "report_id": report.get("report_id"),
            "source_id": report.get("source_id"),
            "generated_at": report.get("generated_at"),
            "summary": report.get("summary"),
            "backlog_count": len(report.get("backlog", [])),
            "artifact_paths": report.get("artifact_paths"),
        } if report else None,
        "report_error": report_error,
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
            "requested_steps": data.get("requested_steps"),
            "auto_included_orders": data.get("auto_included_orders"),
            "final_orders": data.get("final_orders"),
            "step_count": len(data.get("steps", [])),
            "steps": data.get("steps", []),
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

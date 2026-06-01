from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone, timedelta
from html import escape
from pathlib import Path

from bas.elk_checker import resolve_alert_query, resolve_query
from bas.loader import load_campaign, load_target


BASE_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = BASE_DIR / "outputs" / "runs"
OPERATIONS_DIR = BASE_DIR / "outputs" / "operations"
REPORTS_DIR = BASE_DIR / "outputs" / "reports"
KST = timezone(timedelta(hours=9))

FINAL_STATUSES = {"completed", "success"}
FAILED_STATUSES = {"failed", "error", "manual_required", "not_supported"}
BLOCKED_STATUSES = {"blocked", "blocked_by_safety_gate"}
GAP_ANALYSIS_STATUSES = {
    "missed",
    "logged_only",
    "alert_without_source_sample",
    "not_checked",
    "execution_failed",
}
REPORT_VERSION = "0.1"
GENERATOR_VERSION = "sb-ad-report-builder-0.1"

RISK_LABELS = {
    "low": "낮음",
    "medium": "중간",
    "high": "높음",
    "critical": "치명",
}

DELETE_ACTION_PATTERN = re.compile(
    r"remove-item|\brm\s+-[a-z]*f|\bdel\s+|kubectl\s+delete|aws\s+s3\s+rm|\brmdir\b|remove-scheduledtask|schtasks\b.*\bdelete\b",
    re.IGNORECASE,
)

DETECTION_RESULT_LABELS = {
    "detected": "탐지됨",
    "logged_only": "로그만 확인",
    "alert_without_source_sample": "알림만 확인",
    "missed": "미탐",
    "not_checked": "확인 안 됨",
    "blocked": "차단됨",
    "execution_failed": "실행 실패",
}

DETECTION_STATUS_ALIASES = {
    "detected": "detected",
    "탐지": "detected",
    "탐지됨": "detected",
    "covered": "detected",
    "커버됨": "detected",
    "logged_only": "logged_only",
    "logged only": "logged_only",
    "로그만": "logged_only",
    "로그만 확인": "logged_only",
    "부분 커버": "logged_only",
    "alert_without_source_sample": "alert_without_source_sample",
    "알림만 확인": "alert_without_source_sample",
    "missed": "missed",
    "미탐": "missed",
    "공백": "missed",
    "not_checked": "not_checked",
    "not checked": "not_checked",
    "미확인": "not_checked",
    "확인 안 됨": "not_checked",
    "확인 필요": "not_checked",
    "blocked": "blocked",
    "차단": "blocked",
    "차단됨": "blocked",
    "execution_failed": "execution_failed",
    "실행 실패": "execution_failed",
}

COVERAGE_STATUS_LABELS = {
    "detected": "커버됨",
    "logged_only": "부분 커버",
    "alert_without_source_sample": "부분 커버",
    "missed": "공백",
    "not_checked": "확인 필요",
    "blocked": "차단",
    "execution_failed": "실행 실패",
}

EXECUTION_STATUS_LABELS = {
    "success": "성공",
    "simulated": "시뮬레이션",
    "blocked": "차단",
    "failed": "실패",
    "unknown": "확인 필요",
}

GAP_LABELS = {
    "not_checked": "검증 미완료",
    "agent_or_execution_failed": "에이전트/실행 실패",
    "no_alert": "알림 룰 미탐",
    "query_too_narrow": "쿼리 범위 재검토",
    "no_telemetry": "로그 미수집",
    "review_required": "검토 필요",
}

ACTION_LABELS = {
    "keep": "유지",
    "tune_or_create_rule": "탐지 룰 튜닝 또는 신규 생성",
    "fix_telemetry_then_rule": "로그 수집 경로 보완 후 룰 작성",
    "fix_validation_pipeline": "ELK 쿼리/연동 검증",
    "fix_agent_or_execution": "Agent 또는 실행 조건 점검",
    "review_safety_or_prevention_control": "안전 게이트 또는 차단 정책 검토",
    "rerun_real_or_implement_module": "Real 모드 재실행 또는 모듈 구현",
    "review_detection_logic": "탐지 로직 검토",
}

ACTION_REASONS_KO = {
    "keep": "원본 로그와 탐지 알림이 모두 확인되었습니다.",
    "tune_or_create_rule": "원본 로그는 있으나 매칭되는 탐지 알림이 없습니다.",
    "fix_telemetry_then_rule": "원본 로그와 탐지 알림이 모두 확인되지 않았습니다.",
    "fix_validation_pipeline": "ELK 쿼리, 연결 상태 또는 실시간 검증 증거를 확인해야 합니다.",
    "fix_agent_or_execution": "BAS 단계가 완료되지 않아 탐지 여부를 검증할 수 없습니다.",
    "review_safety_or_prevention_control": "정상 탐지 검증 전에 실행이 차단되었습니다.",
    "rerun_real_or_implement_module": "실제 실행 증거가 아니므로 Real 모드 검증이 필요합니다.",
    "review_detection_logic": "알림 증거와 원본 로그 샘플의 매칭 조건을 다시 확인해야 합니다.",
}

TACTIC_ORDER = [
    "initial_access",
    "execution",
    "command_and_control",
    "discovery",
    "credential_access",
    "lateral_movement",
    "collection",
    "exfiltration",
    "defense_evasion",
    "persistence",
    "privilege_escalation",
    "other",
]

TACTIC_LABELS = {
    "initial_access": "초기 침투",
    "execution": "실행",
    "command_and_control": "C2",
    "discovery": "탐색",
    "credential_access": "자격 증명 접근",
    "lateral_movement": "측면 이동",
    "collection": "수집",
    "exfiltration": "유출",
    "defense_evasion": "방어 회피",
    "persistence": "지속성",
    "privilege_escalation": "권한 상승",
    "other": "기타",
}

TECHNIQUE_TACTICS = {
    "T1204.002": "initial_access",
    "T1059.003": "execution",
    "T1059.001": "execution",
    "T1095": "command_and_control",
    "T1105": "command_and_control",
    "T1018": "discovery",
    "T1033": "discovery",
    "T1069": "discovery",
    "T1069.001": "discovery",
    "T1069.002": "discovery",
    "T1087.001": "discovery",
    "T1087.002": "discovery",
    "T1135": "discovery",
    "T1558.003": "credential_access",
    "T1552.001": "credential_access",
    "T1003.001": "credential_access",
    "T1003.002": "credential_access",
    "T1003.003": "credential_access",
    "T1003.006": "credential_access",
    "T1021.004": "lateral_movement",
    "T1021.006": "lateral_movement",
    "T1074.001": "collection",
    "T1560.001": "collection",
    "T1041": "exfiltration",
    "T1036.005": "defense_evasion",
    "T1027.010": "defense_evasion",
    "T1027.013": "defense_evasion",
    "T1218.011": "defense_evasion",
    "T1558.001": "persistence",
    "T1078.002": "persistence",
    "T1569.002": "privilege_escalation",
}


def now_kst():
    return datetime.now(KST).isoformat(timespec="seconds")


def read_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def safe_load_campaign(campaign_id):
    try:
        return load_campaign(campaign_id)
    except FileNotFoundError:
        return {}


def safe_load_target(target_id):
    try:
        return load_target(target_id)
    except FileNotFoundError:
        return {}


def build_flow_index(campaign_id):
    campaign = safe_load_campaign(campaign_id)
    flow_index = {}

    for step in campaign.get("flow", []):
        flow_index[step.get("order")] = step

    return campaign, flow_index


def merge_step_with_definition(step, definition):
    params = definition.get("params", {}) if definition else {}
    merged = {
        **(definition or {}),
        **step,
        "risk": step.get("risk") or params.get("risk") or definition.get("risk") if definition else step.get("risk"),
        "execution_host": step.get("execution_host") or params.get("execution_host") if definition else step.get("execution_host"),
    }

    merged["name"] = step.get("name") or definition.get("name") if definition else step.get("name")
    merged["technique_id"] = step.get("technique_id") or definition.get("technique_id") if definition else step.get("technique_id")
    merged["phase"] = step.get("phase") or definition.get("phase") if definition else step.get("phase")
    merged["module"] = step.get("module") or definition.get("module") if definition else step.get("module")
    return merged


def normalize_source_steps(source):
    campaign_id = source.get("campaign_id")
    _, flow_index = build_flow_index(campaign_id)
    raw_steps = source.get("final_steps") or source.get("steps") or []
    normalized = []

    for step in raw_steps:
        result_step = step.get("result_step")
        if not result_step and step.get("result", {}).get("steps"):
            result_step = step["result"]["steps"][0]

        base_step = {
            **step,
            **(result_step or {}),
            "operation_status": step.get("status"),
            "operation_agent_role": step.get("agent_role"),
            "operation_job_id": step.get("job_id"),
            "operation_execution_id": step.get("execution_id"),
            "simulation_reason": step.get("simulation_reason"),
        }
        if step.get("elk_check") and not base_step.get("elk_check"):
            base_step["elk_check"] = step.get("elk_check")
        if step.get("module_result") and not base_step.get("module_result"):
            base_step["module_result"] = step.get("module_result")

        normalized.append(merge_step_with_definition(base_step, flow_index.get(base_step.get("order"))))

    return normalized


def is_checked(check):
    return bool((check or {}).get("checked"))


def is_matched(check):
    return bool((check or {}).get("matched"))


def event_count(check):
    value = (check or {}).get("event_count")
    return value if isinstance(value, int) else 0


def normalize_detection_status(value):
    if not value:
        return None

    normalized = str(value).strip().lower()
    return DETECTION_STATUS_ALIASES.get(normalized)


def fallback_detection_status(step):
    for field in ("detection_status", "detection_result", "coverage_status"):
        status = normalize_detection_status(step.get(field))
        if status:
            return status

    return None


def get_alert_check(elk_check):
    return (elk_check or {}).get("alert_check") or (elk_check or {}).get("alert") or {}


def canonical_execution_status(step):
    module_result = step.get("module_result") or {}
    status = step.get("status") or step.get("operation_status") or module_result.get("status")

    if is_simulated_step(step):
        return "simulated"
    if status in FINAL_STATUSES:
        return "success"
    if status in BLOCKED_STATUSES:
        return "blocked"
    if status in FAILED_STATUSES:
        return "failed"
    if step.get("error"):
        return "failed"
    return status or "unknown"


def is_simulated_step(step):
    module_result = step.get("module_result") or {}
    message = str(module_result.get("message") or step.get("simulation_reason") or "").lower()
    mode = str(module_result.get("execution_mode") or "").lower()
    return (
        step.get("status") == "simulated"
        or step.get("operation_status") == "simulated"
        or mode == "simulation"
        or "simulated" in message
    )


def classify_gap(detection_status, source_checked, source_matched, alert_checked, alert_matched, simulated):
    if simulated:
        return "not_checked"
    if detection_status == "execution_failed":
        return "agent_or_execution_failed"
    if detection_status == "not_checked":
        return "not_checked"
    if detection_status == "logged_only":
        return "no_alert"
    if detection_status == "alert_without_source_sample":
        return "query_too_narrow"
    if detection_status == "missed" and not source_matched and not alert_matched:
        return "no_telemetry" if source_checked else "not_checked"
    return None


def classify_detection_status(step):
    execution_status = canonical_execution_status(step)
    elk_check = step.get("elk_check") or {}
    alert_check = get_alert_check(elk_check)
    source_checked = is_checked(elk_check)
    source_matched = is_matched(elk_check)
    alert_checked = is_checked(alert_check)
    alert_matched = is_matched(alert_check)
    simulated = execution_status == "simulated"
    fallback_status = fallback_detection_status(step)

    if execution_status == "blocked":
        detection_status = "blocked"
    elif execution_status == "failed":
        detection_status = "execution_failed"
    elif simulated:
        detection_status = "not_checked"
    elif not source_checked and not alert_checked:
        detection_status = fallback_status or "not_checked"
    elif source_matched and alert_matched:
        detection_status = "detected"
    elif source_matched and not alert_matched:
        detection_status = "logged_only"
    elif not source_matched and alert_matched:
        detection_status = "alert_without_source_sample"
    else:
        detection_status = fallback_status or "missed"

    if fallback_status and not source_checked and not alert_checked:
        if detection_status == "detected":
            source_checked = True
            source_matched = True
            alert_checked = True
            alert_matched = True
        elif detection_status == "logged_only":
            source_checked = True
            source_matched = True
            alert_checked = True
            alert_matched = False
        elif detection_status == "alert_without_source_sample":
            source_checked = True
            source_matched = False
            alert_checked = True
            alert_matched = True
        elif detection_status == "missed":
            source_checked = True
            source_matched = False
            alert_checked = True
            alert_matched = False

    return {
        "execution_status": execution_status,
        "detection_status": detection_status,
        "source_status": "matched" if source_matched else "not_matched" if source_checked else "not_checked",
        "alert_status": "matched" if alert_matched else "not_matched" if alert_checked else "not_checked",
        "source_event_count": event_count(elk_check),
        "alert_count": event_count(alert_check),
        "gap_type": classify_gap(
            detection_status,
            source_checked,
            source_matched,
            alert_checked,
            alert_matched,
            simulated,
        ),
    }


def recommendation_for(step, classification):
    status = classification["detection_status"]

    if classification["execution_status"] == "simulated":
        return {
            "action": "rerun_real_or_implement_module",
            "reason": "This step did not perform a real validation run, so detection cannot be scored as real evidence.",
        }
    if status == "detected":
        return {
            "action": "keep",
            "reason": "Source telemetry and alert evidence both matched.",
        }
    if status == "logged_only":
        return {
            "action": "tune_or_create_rule",
            "reason": "Source telemetry exists, but no matching alert was found.",
        }
    if status == "missed":
        return {
            "action": "fix_telemetry_then_rule",
            "reason": "Neither source telemetry nor alert evidence matched.",
        }
    if status == "not_checked":
        return {
            "action": "fix_validation_pipeline",
            "reason": "ELK query, connection, or live validation evidence was not available.",
        }
    if status == "execution_failed":
        return {
            "action": "fix_agent_or_execution",
            "reason": "The BAS step did not complete, so detection cannot be validated.",
        }
    if status == "blocked":
        return {
            "action": "review_safety_or_prevention_control",
            "reason": "The step was blocked before normal detection validation completed.",
        }
    return {
        "action": "review_detection_logic",
        "reason": "Alert evidence exists without matching source sample evidence.",
    }


def normalize_list(value):
    return value if isinstance(value, list) else []


def get_step_params(step):
    params = step.get("params") or {}
    return params if isinstance(params, dict) else {}


def step_behavior(step):
    return get_step_params(step).get("behavior") or step.get("behavior")


def step_target_asset(step):
    asset_id = step.get("asset_id") or step.get("target_asset_id")
    if asset_id:
        return str(asset_id).upper()

    execution_host = step.get("execution_host")
    if execution_host:
        return str(execution_host).upper()

    agent_role = step.get("agent_role") or step.get("operation_agent_role")
    return str(agent_role or "-").upper()


def required_condition(step):
    requires = normalize_list(step.get("requires"))
    safety_gates = normalize_list(get_step_params(step).get("safety_gates"))
    parts = []

    if requires:
        parts.append("필수 조건: " + ", ".join(requires))
    if safety_gates:
        parts.append("안전 게이트: " + ", ".join(safety_gates))

    return "; ".join(parts) if parts else "-"


def expected_log(step):
    requires = set(normalize_list(step.get("requires")))
    behavior = step_behavior(step) or ""

    if behavior in ("sb05_ssh_access_check", "jenkins_to_app_ssh"):
        return "Linux auth.log/auditd SSH accepted publickey event"
    if behavior in ("kerberoasting_tgs_request",):
        return "Windows Security 4769 Kerberos TGS 요청"
    if behavior in ("dcsync_replication",):
        return "Windows Security 4662 / 디렉터리 복제 접근 로그"
    if behavior in ("valid_domain_account_remote_logon", "winrm_remote_execution"):
        return "Windows Security 4624/4688 및 Sysmon 프로세스 로그"
    if behavior in ("service_execution",):
        return "서비스 생성/실행 이벤트 및 Sysmon 프로세스 로그"
    if behavior in ("lsass_memory_dump", "rundll32_comsvcs_proxy"):
        return "Sysmon Event ID 10 프로세스 접근 및 Event ID 11 파일 생성"
    if behavior in ("non_application_tcp_connection", "exfiltration_over_c2"):
        return "Sysmon Event ID 3 네트워크 연결"
    if behavior in ("ingress_tool_transfer", "local_data_staging", "masquerading_legitimate_name", "archive_collected_data", "ntds_dump"):
        return "Sysmon 파일/프로세스 로그 및 Windows Security 감사 이벤트"
    if "powershell_logging" in requires or "powershell" in requires:
        return "PowerShell 4104 및 Sysmon 프로세스 로그"
    if "windows_security" in requires or "active_directory" in requires:
        return "Windows Security Log 및 Sysmon 프로세스 로그"
    if "network" in requires:
        return "네트워크 연결 로그"
    if "sysmon" in requires:
        return "Sysmon 프로세스/파일/네트워크 로그"
    return "매핑된 로그 소스의 원본 이벤트"


def risk_level(step):
    delete_impact = delete_action_impact_level(step)
    if delete_impact:
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        raw_risk = str(step.get("risk") or "medium").lower()
        return delete_impact if rank.get(delete_impact, 0) > rank.get(raw_risk, 0) else raw_risk
    if step.get("phase") == "normal":
        return "low"
    return str(step.get("risk") or "medium").lower()


def step_has_delete_action(step):
    return bool(delete_action_impact_level(step))


def delete_action_impact_level(step):
    params = get_step_params(step)
    command_text = json.dumps(
        [
            params.get("commands"),
            params.get("cleanup"),
            step.get("commands"),
            step.get("cleanup"),
            params.get("behavior"),
            step.get("name"),
        ],
        ensure_ascii=False,
        default=str,
    ).lower()
    if not DELETE_ACTION_PATTERN.search(command_text):
        return None

    source_id = str(step.get("source_campaign_id") or step.get("campaign_id") or step.get("target") or "").upper()
    order = step.get("order", params.get("scenario_order"))
    try:
        order = int(order)
    except (TypeError, ValueError):
        pass
    if source_id == "SB-AD" and order == 17:
        return "critical"
    if any(keyword in command_text for keyword in ("lsass", "sam", "credential", "dump", "reg save", "comsvcs")):
        return "high"
    return "medium"


def system_impact(step):
    delete_impact = delete_action_impact_level(step)
    if delete_impact == "critical":
        return "치명 - 공유 폴더 파일 삭제 가능성, 운영환경 금지"
    if delete_impact == "high":
        return "높음 - 민감 임시파일 cleanup, 테스트 환경 권장"
    if delete_impact == "medium":
        return "중간 - BAS 임시/마커 파일 cleanup"
    if step.get("phase") == "normal":
        return "낮음 - 정상 기준 로그"

    risk = risk_level(step)
    behavior = step_behavior(step) or ""
    safety_gates = set(normalize_list(get_step_params(step).get("safety_gates")))
    high_impact_keywords = ("dcsync", "golden_ticket", "ntds", "lsass", "service_execution")

    if any(keyword in behavior for keyword in high_impact_keywords) or "BAS_ENABLE_DOMAIN_COMPROMISE_TESTS" in safety_gates:
        return "높음 - 테스트 환경 권장"
    if risk == "high" or safety_gates:
        return "중간 - 승인 후 실행 권장"
    if risk == "critical":
        return "높음 - 테스트 환경 권장"
    return "낮음 - 안전 검증"


def clamp_percent(value):
    return max(0, min(95, round(value)))


def estimated_impact(step):
    delete_impact = delete_action_impact_level(step)

    if step.get("phase") == "normal" and not delete_impact:
        return {
            "service_impact_percent": 2,
            "network_impact_percent": 1,
            "basis": "normal baseline step",
        }

    risk = risk_level(step)
    params = get_step_params(step)
    behavior = str(step_behavior(step) or "").lower()
    requires = " ".join(normalize_list(step.get("requires"))).lower()
    name = str(step.get("name") or "").lower()
    safety_gates = " ".join(normalize_list(params.get("safety_gates"))).lower()
    combined = f"{behavior} {requires} {name} {safety_gates}"

    domain_compromise = any(keyword in combined for keyword in ("dcsync", "golden", "ntds", "domain_compromise", "krbtgt", "secretsdump"))
    credential_dump = any(keyword in combined for keyword in ("lsass", "credential", "dump", "comsvcs", "sam", "ntds"))
    service_execution = any(keyword in combined for keyword in ("service_execution", "psexec", "service"))
    network_heavy = any(keyword in combined for keyword in ("dos", "scan", "sweep", "flood", "spoof"))
    network_touch = any(keyword in combined for keyword in ("network", "tcp", "c2", "exfiltration", "tool_transfer", "winrm", "remote"))
    gate_count = len(normalize_list(params.get("safety_gates")))

    base_risk_percent = {
        "low": 5,
        "medium": 15,
        "high": 32,
        "critical": 58,
    }.get(risk, 15)
    service_percent = clamp_percent(
        base_risk_percent
        + (18 if domain_compromise else 0)
        + (12 if credential_dump else 0)
        + (16 if service_execution else 0)
        + (20 if network_heavy else 0)
        + (45 if delete_impact == "critical" else 24 if delete_impact == "high" else 10 if delete_impact == "medium" else 0)
        + (6 if gate_count > 1 else 0)
    )
    network_percent = clamp_percent(
        (62 if network_heavy else 22 if network_touch else 3)
        + (8 if risk == "critical" else 5 if risk == "high" else 0)
    )

    return {
        "service_impact_percent": service_percent,
        "network_impact_percent": network_percent,
        "basis": "삭제 동작 영향도 세분화 / risk/behavior/requires/safety_gates 기반 추정" if delete_impact else "risk/behavior/requires/safety_gates 기반 추정",
    }


def detection_gap_reason(step):
    detection_status = step.get("detection_status")
    gap_type = step.get("gap_type")
    source_status = step.get("source_status")
    alert_status = step.get("alert_status")

    if detection_status == "missed":
        if gap_type == "no_telemetry" or (source_status == "not_matched" and alert_status == "not_matched"):
            return "원본 로그와 탐지 알림이 모두 확인되지 않았습니다. 로그 수집 경로, 인덱스 매핑, 센서 설치 상태를 먼저 확인해야 합니다."
        return "탐지 증거가 확인되지 않았습니다. ELK 쿼리 범위와 로그 수집 상태를 재검증해야 합니다."
    if detection_status == "logged_only":
        return "원본 로그는 남았지만 매칭되는 탐지 알림이 발생하지 않았습니다. 룰 조건이 없거나 너무 좁거나 비활성 상태일 가능성이 있습니다."
    if detection_status == "alert_without_source_sample":
        return "탐지 알림은 있으나 원본 로그 샘플과 연결되지 않았습니다. 알림 룰 쿼리와 원본 로그 쿼리의 시간 범위, 필드명, 인덱스 조건을 맞춰야 합니다."
    if detection_status == "not_checked":
        return "검증 쿼리 또는 실시간 증거 확인이 완료되지 않았습니다. ELK 연결, Agent 상태, 실행 모드, 시간 범위를 다시 확인해야 합니다."
    if detection_status == "execution_failed":
        return "BAS 단계가 정상 종료되지 않아 탐지 여부를 판단할 수 없습니다. Agent 실행 권한과 대상 호스트 조건을 먼저 복구해야 합니다."
    if detection_status == "blocked":
        return "안전 게이트 또는 차단 정책 때문에 실행 전 단계에서 멈췄습니다. 실제 탐지 검증 전 승인 조건과 차단 정책을 확인해야 합니다."
    return "추가 분석이 필요한 항목입니다. 원본 로그, 알림 룰, 실행 증거를 함께 확인해야 합니다."


def should_show_gap_analysis(step):
    return bool(step.get("technique_id")) and step.get("detection_status") in GAP_ANALYSIS_STATUSES


def recommended_sensor(step):
    requires = set(normalize_list(step.get("requires")))
    sensors = []

    if "sysmon" in requires:
        sensors.append("Sysmon")
    if "windows_security" in requires or "active_directory" in requires or "kerberos" in requires:
        sensors.append("Windows Security Log")
    if "powershell_logging" in requires or "powershell" in requires:
        sensors.append("PowerShell 4104")
    if "network" in requires:
        sensors.append("Sysmon Network / Suricata or Snort")
    if "winrm" in requires:
        sensors.append("WinRM logs")
    if "aws" in requires:
        sensors.append("CloudTrail / VPC Flow Log / WAF")

    sensors.extend(["Winlogbeat", "Kibana Detection Rule"])
    deduped = []
    for sensor in sensors:
        if sensor not in deduped:
            deduped.append(sensor)
    return ", ".join(deduped)


def coverage_status(detection_status):
    return COVERAGE_STATUS_LABELS.get(detection_status, "검토 필요")


def detection_result_label(detection_status):
    return DETECTION_RESULT_LABELS.get(detection_status, detection_status or "-")


def extract_rule_from_query(query):
    if not query:
        return ""

    rule_id_match = re.search(r'rule_id:"([^"]+)"', query)
    if rule_id_match:
        return rule_id_match.group(1)

    rule_name_match = re.search(r'rule\.name:"([^"]+)"', query)
    if rule_name_match:
        return rule_name_match.group(1)

    return query


def improvement_plan(step, recommendation):
    action = recommendation.get("action") or "review_detection_logic"
    action_label = ACTION_LABELS.get(action, action)
    reason = ACTION_REASONS_KO.get(action) or recommendation.get("reason") or ""
    return f"{action_label}: {reason}" if reason else action_label


def report_detection_result(step):
    return detection_result_label(step.get("detection_status")) if step.get("detection_status") else step.get("detection_result") or "-"


def report_improvement_plan(step):
    recommendation = step.get("recommendation") or {}
    action = recommendation.get("action")
    existing = step.get("improvement_plan")
    if action and (not existing or str(existing).startswith(f"{action}:")):
        return improvement_plan(step, recommendation)
    return existing or "-"


def build_dashboard_fields(step, classification, recommendation, target):
    behavior = step_behavior(step)
    source_query = (step.get("elk_check") or {}).get("query")
    alert_query = get_alert_check(step.get("elk_check") or {}).get("query")
    impact_estimate = estimated_impact(step)

    if target and behavior:
        source_query = source_query or resolve_query(target, behavior)[0]
        alert_query = alert_query or resolve_alert_query(target, behavior)[0]

    rule = extract_rule(get_alert_check(step.get("elk_check") or {}))
    detection_rule = rule.get("name") or rule.get("rule_id") or extract_rule_from_query(alert_query) or "-"

    return {
        "attack_name": step.get("name") or "-",
        "target_asset": step_target_asset(step),
        "required_condition": required_condition(step),
        "expected_log": expected_log(step),
        "detection_rule": detection_rule,
        "detection_result": detection_result_label(classification["detection_status"]),
        "coverage_status": coverage_status(classification["detection_status"]),
        "system_impact": system_impact(step),
        "service_impact_percent": impact_estimate["service_impact_percent"],
        "network_impact_percent": impact_estimate["network_impact_percent"],
        "impact_estimate_basis": impact_estimate["basis"],
        "risk_level": RISK_LABELS.get(risk_level(step), risk_level(step)),
        "recommended_sensor": recommended_sensor(step),
        "missed_reason": detection_gap_reason({
            **step,
            **classification,
        }),
        "improvement_plan": improvement_plan(step, recommendation),
        "resolved_queries": {
            "source": source_query,
            "alert": alert_query,
        },
    }


def classify_step(step, target=None):
    classification = classify_detection_status(step)
    elk_check = step.get("elk_check") or {}
    alert_check = get_alert_check(elk_check)
    recommendation = recommendation_for(step, classification)
    dashboard_fields = build_dashboard_fields(step, classification, recommendation, target or {})
    source_query = elk_check.get("query") or dashboard_fields["resolved_queries"].get("source")
    alert_query = alert_check.get("query") or dashboard_fields["resolved_queries"].get("alert")

    return {
        "order": step.get("order"),
        "phase": step.get("phase"),
        "name": step.get("name"),
        "module": step.get("module"),
        "technique_id": step.get("technique_id"),
        "attack_name": dashboard_fields["attack_name"],
        "target_asset": dashboard_fields["target_asset"],
        "required_condition": dashboard_fields["required_condition"],
        "expected_log": dashboard_fields["expected_log"],
        "detection_rule": dashboard_fields["detection_rule"],
        "detection_result": dashboard_fields["detection_result"],
        "coverage_status": dashboard_fields["coverage_status"],
        "system_impact": dashboard_fields["system_impact"],
        "service_impact_percent": dashboard_fields["service_impact_percent"],
        "network_impact_percent": dashboard_fields["network_impact_percent"],
        "impact_estimate_basis": dashboard_fields["impact_estimate_basis"],
        "risk_level": dashboard_fields["risk_level"],
        "recommended_sensor": dashboard_fields["recommended_sensor"],
        "missed_reason": dashboard_fields["missed_reason"],
        "improvement_plan": dashboard_fields["improvement_plan"],
        "risk": step.get("risk") or "medium",
        "agent_role": step.get("agent_role") or step.get("operation_agent_role"),
        "execution_host": step.get("execution_host"),
        "execution_status": classification["execution_status"],
        "detection_status": classification["detection_status"],
        "source_status": classification["source_status"],
        "alert_status": classification["alert_status"],
        "source_event_count": classification["source_event_count"],
        "alert_count": classification["alert_count"],
        "gap_type": classification["gap_type"],
        "simulation_reason": step.get("simulation_reason"),
        "job_id": step.get("operation_job_id") or step.get("job_id"),
        "execution_id": step.get("operation_execution_id") or step.get("execution_id"),
        "started_at": step.get("started_at"),
        "finished_at": step.get("finished_at"),
        "queries": {
            "source": source_query,
            "alert": alert_query,
        },
        "evidence": {
            "sample_source_events": elk_check.get("sample_events", []),
            "sample_alerts": alert_check.get("sample_events", []),
        },
        "rule": extract_rule(alert_check),
        "recommendation": recommendation,
        "source_message": elk_check.get("message"),
        "alert_message": alert_check.get("message"),
    }


def extract_rule(alert_check):
    samples = (alert_check or {}).get("sample_events") or []
    first_sample = samples[0] if samples else {}
    return {
        "rule_id": first_sample.get("rule_id"),
        "name": first_sample.get("rule"),
        "severity": first_sample.get("severity"),
        "tags": first_sample.get("tags", []),
    }


def status_score(status):
    return {
        "detected": 100,
        "blocked": 80,
        "logged_only": 60,
        "alert_without_source_sample": 50,
        "not_checked": 40,
        "execution_failed": 30,
        "missed": 0,
    }.get(status, 0)


def risk_weight(risk):
    return {
        "low": 1.0,
        "medium": 1.2,
        "high": 1.5,
        "critical": 2.0,
    }.get(str(risk or "medium").lower(), 1.2)


def calculate_metrics(steps):
    attack_steps = [step for step in steps if step.get("technique_id")]
    real_attack_steps = [
        step for step in attack_steps
        if step.get("execution_status") not in ("simulated", "failed", "blocked")
    ]
    executed_steps = [step for step in steps if step.get("execution_status") in ("success", "simulated")]
    failed_steps = [step for step in steps if step.get("execution_status") == "failed"]
    blocked_steps = [step for step in steps if step.get("execution_status") == "blocked"]
    simulated_steps = [step for step in steps if step.get("execution_status") == "simulated"]

    source_matched = [step for step in real_attack_steps if step.get("source_status") == "matched"]
    alert_matched = [step for step in real_attack_steps if step.get("alert_status") == "matched"]
    detected = [step for step in real_attack_steps if step.get("detection_status") == "detected"]
    logged_only = [step for step in attack_steps if step.get("detection_status") == "logged_only"]
    missed = [step for step in attack_steps if step.get("detection_status") == "missed"]
    not_checked = [step for step in attack_steps if step.get("detection_status") == "not_checked"]

    weighted_total = sum(risk_weight(step.get("risk")) for step in real_attack_steps)
    weighted_score = sum(
        status_score(step.get("detection_status")) * risk_weight(step.get("risk"))
        for step in real_attack_steps
    )
    coverage_score = (weighted_score / weighted_total) if weighted_total else 0
    real_count = len(real_attack_steps)
    total_count = len(steps)
    operational_score = len(executed_steps) / total_count if total_count else 0
    telemetry_score = len(source_matched) / real_count if real_count else 0
    alert_score = len(alert_matched) / real_count if real_count else 0
    final_score = (
        coverage_score * 0.55
        + telemetry_score * 100 * 0.15
        + alert_score * 100 * 0.20
        + operational_score * 100 * 0.10
    ) if total_count else 0

    return {
        "final_score": round(final_score),
        "total_steps": total_count,
        "attack_steps": len(attack_steps),
        "real_attack_steps": real_count,
        "executed_steps": len(executed_steps),
        "failed_steps": len(failed_steps),
        "blocked_steps": len(blocked_steps),
        "simulated_steps": len(simulated_steps),
        "execution_rate": round(operational_score, 4),
        "telemetry_coverage": round(telemetry_score, 4),
        "alert_coverage": round(alert_score, 4),
        "detection_coverage": round(len(detected) / real_count, 4) if real_count else 0,
        "logged_only_count": len(logged_only),
        "missed_count": len(missed),
        "not_checked_count": len(not_checked),
        "detected_count": len(detected),
        "critical_gaps": len([
            step for step in attack_steps
            if step.get("risk") in ("high", "critical") and step.get("gap_type")
        ]),
    }


def backlog_priority(step):
    status = step.get("detection_status")
    risk = step.get("risk")

    if status == "missed" and risk in ("high", "critical"):
        return "P0"
    if status in ("missed", "execution_failed"):
        return "P1"
    if status in ("logged_only", "alert_without_source_sample"):
        return "P1" if risk in ("high", "critical") else "P2"
    if status == "not_checked":
        return "P2"
    if status == "blocked":
        return "P3"
    return "P3"


def generate_backlog(steps):
    backlog = []

    for step in steps:
        if not step.get("technique_id"):
            continue
        if step.get("detection_status") == "detected":
            continue

        recommendation = step.get("recommendation", {})
        backlog.append({
            "priority": backlog_priority(step),
            "technique_id": step.get("technique_id"),
            "order": step.get("order"),
            "gap_type": step.get("gap_type") or "review_required",
            "affected_host": step.get("execution_host") or step.get("agent_role") or "",
            "current_rule_id": step.get("rule", {}).get("rule_id") or "",
            "current_rule_name": step.get("rule", {}).get("name") or "",
            "recommended_action": recommendation.get("action"),
            "suggested_query": step.get("queries", {}).get("source") or step.get("queries", {}).get("alert") or "",
            "owner": "SOC",
            "effort": "M" if step.get("detection_status") in ("missed", "execution_failed") else "S",
            "due_hint": "next sprint" if backlog_priority(step) in ("P0", "P1") else "backlog",
            "verification_method": f"Re-run step {step.get('order')}",
        })

    return sorted(backlog, key=lambda item: item["priority"])


def build_recommendations(steps):
    recommendations = []

    for step in steps:
        if not step.get("technique_id"):
            continue
        recommendation = step.get("recommendation", {})
        recommendations.append({
            "order": step.get("order"),
            "technique_id": step.get("technique_id"),
            "detection_status": step.get("detection_status"),
            "gap_type": step.get("gap_type"),
            "action": recommendation.get("action"),
            "reason": recommendation.get("reason"),
        })

    return recommendations


def build_mitre_summary(steps):
    statuses = {
        "techniques_tested": [],
        "detected": [],
        "logged_only": [],
        "missed": [],
        "not_checked": [],
        "blocked": [],
    }

    for step in steps:
        technique_id = step.get("technique_id")
        if not technique_id:
            continue
        statuses["techniques_tested"].append(technique_id)
        status = step.get("detection_status")
        if status in statuses:
            statuses[status].append(technique_id)

    return {
        key: sorted(set(value))
        for key, value in statuses.items()
    }


def build_report(source, source_type):
    source_id = source.get("operation_id") or source.get("execution_id")
    campaign_id = source.get("campaign_id")
    campaign, _ = build_flow_index(campaign_id)
    target = safe_load_target(campaign_id)
    steps = [classify_step(step, target) for step in normalize_source_steps(source)]
    summary = calculate_metrics(steps)
    backlog = generate_backlog(steps)

    report = {
        "report_id": f"report-{source_id}",
        "source_type": source_type,
        "source_id": source_id,
        "operation_id": source.get("operation_id"),
        "execution_id": source.get("execution_id"),
        "campaign_id": campaign_id,
        "campaign_name": source.get("campaign_name") or campaign.get("campaign_name"),
        "generated_at": now_kst(),
        "report_version": REPORT_VERSION,
        "generator_version": GENERATOR_VERSION,
        "summary": summary,
        "scope": {
            "target": campaign_id,
            "started_at": source.get("started_at"),
            "finished_at": source.get("finished_at"),
            "execution_mode": source.get("execution_mode") or source.get("bas_agent", {}).get("mode"),
            "agent_roles": sorted(set(
                step.get("agent_role")
                for step in steps
                if step.get("agent_role")
            )),
        },
        "mitre": build_mitre_summary(steps),
        "steps": steps,
        "asset_control_mapping": build_asset_control_mapping(target, steps),
        "recommendations": build_recommendations(steps),
        "backlog": backlog,
    }

    report["artifact_paths"] = write_report_artifacts(report)
    return report


def build_report_from_run(execution_id):
    path = RUNS_DIR / f"{execution_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Run result not found: {execution_id}")

    return build_report(read_json(path), "run")


def build_report_from_operation(operation_or_id):
    if isinstance(operation_or_id, str):
        path = OPERATIONS_DIR / f"{operation_or_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Operation not found: {operation_or_id}")
        operation = read_json(path)
    else:
        operation = operation_or_id

    return build_report(operation, "operation")


def report_base_path(report):
    source_id = report["source_id"]
    return REPORTS_DIR / source_id


def write_report_artifacts(report):
    base = report_base_path(report)
    artifacts = {
        "json": base.with_suffix(".report.json"),
        "summary": base.with_suffix(".summary.md"),
        "summary_html": base.with_suffix(".summary.html"),
        "technical": base.with_suffix(".technical.md"),
        "coverage": base.with_suffix(".coverage.csv"),
        "backlog": base.with_suffix(".detection-backlog.csv"),
        "navigator": base.with_suffix(".attack-navigator.json"),
    }

    write_json(artifacts["json"], {key: value for key, value in report.items() if key != "artifact_paths"})
    artifacts["summary"].write_text(render_summary_markdown(report), encoding="utf-8")
    artifacts["summary_html"].write_text(render_summary_html(report), encoding="utf-8")
    artifacts["technical"].write_text(render_technical_markdown(report), encoding="utf-8")
    write_coverage_csv(artifacts["coverage"], report.get("steps", []))
    write_backlog_csv(artifacts["backlog"], report.get("backlog", []))
    write_json(artifacts["navigator"], build_navigator_layer(report))

    return {
        key: str(path)
        for key, path in artifacts.items()
    }


def render_summary_markdown(report):
    summary = report["summary"]
    backlog = report.get("backlog", [])
    lines = [
        f"# {report.get('campaign_name') or report.get('campaign_id')} BAS 결과 요약",
        "",
        "## 핵심 지표",
        "",
        "| 지표 | 값 |",
        "| --- | --- |",
        f"| 준비도 점수 | {summary['final_score']}/100 |",
        f"| Real 공격 단계 | {summary['real_attack_steps']} |",
        f"| 탐지 커버리지 | {summary['detection_coverage'] * 100:.0f}% |",
        f"| 로그 커버리지 | {summary['telemetry_coverage'] * 100:.0f}% |",
        f"| 알림 커버리지 | {summary['alert_coverage'] * 100:.0f}% |",
        f"| 로그만 확인 | {summary['logged_only_count']} |",
        f"| 미탐 | {summary['missed_count']} |",
        f"| 확인 필요 | {summary['not_checked_count']} |",
        "",
        "## 우선 개선 백로그",
        "",
    ]

    if backlog:
        for item in backlog:
            action = ACTION_LABELS.get(item.get("recommended_action"), item.get("recommended_action") or "-")
            gap = GAP_LABELS.get(item.get("gap_type"), item.get("gap_type") or "-")
            lines.append(
                f"- {item['priority']} {item['technique_id']} step {item['order']}: "
                f"{gap} -> {action}"
            )
    else:
        lines.append("- 추가 개선 항목이 생성되지 않았습니다.")

    lines.append("")
    return "\n".join(lines)


def tactic_key_for_step(step):
    technique_id = str(step.get("technique_id") or "").strip()
    return TECHNIQUE_TACTICS.get(technique_id, "other")


def build_tactic_coverage(steps):
    grouped = {}
    for step in steps:
        if not step.get("technique_id"):
            continue
        tactic = tactic_key_for_step(step)
        if tactic not in grouped:
            grouped[tactic] = {
                "key": tactic,
                "label": TACTIC_LABELS.get(tactic, tactic),
                "total": 0,
                "log_matched": 0,
                "alert_matched": 0,
                "not_checked": 0,
            }
        row = grouped[tactic]
        row["total"] += 1
        if step.get("source_status") == "matched":
            row["log_matched"] += 1
        if step.get("alert_status") == "matched":
            row["alert_matched"] += 1
        if step.get("source_status") == "not_checked" and step.get("alert_status") == "not_checked":
            row["not_checked"] += 1

    order_index = {key: index for index, key in enumerate(TACTIC_ORDER)}
    return sorted(grouped.values(), key=lambda item: order_index.get(item["key"], 999))


def build_asset_control_mapping(target, steps):
    assets = normalize_list((target or {}).get("assets"))
    control_lookup = {
        control.get("control_id"): control.get("name") or control.get("control_id")
        for control in normalize_list((target or {}).get("security_controls"))
    }
    rows = []

    for asset in assets:
        asset_id = str(asset.get("asset_id") or "").lower()
        asset_names = {
            asset_id,
            str(asset.get("name") or "").lower(),
            str(asset.get("hostname") or "").lower(),
        }
        related_steps = [
            step for step in steps
            if str(step.get("target_asset") or "").lower() in asset_names
            or str(step.get("asset_id") or "").lower() in asset_names
        ]
        statuses = {step.get("detection_status") for step in related_steps}

        if "detected" in statuses:
            coverage = "Covered"
        elif "logged_only" in statuses or "alert_without_source_sample" in statuses:
            coverage = "Partial"
        elif "missed" in statuses:
            coverage = "Gap"
        elif statuses:
            coverage = "검증 필요"
        elif asset.get("log_collection_status") in ("Active", "Detection Backend"):
            coverage = "Planned"
        else:
            coverage = "Manual"

        control_ids = normalize_list(asset.get("controls"))
        controls = [
            control_lookup.get(control_id, control_id)
            for control_id in control_ids
        ]

        rows.append({
            "asset": asset.get("name") or asset.get("asset_id") or "-",
            "role": asset.get("role") or "-",
            "security_control": ", ".join(controls) if controls else "-",
            "log_source": asset.get("log_collection_detail") or asset.get("log_collection_status") or "-",
            "coverage": coverage,
        })

    if rows:
        return rows

    grouped = {}
    for step in steps:
        asset_name = step.get("target_asset") or step.get("execution_host") or step.get("agent_role")
        if not asset_name:
            continue
        key = str(asset_name).lower()
        row = grouped.setdefault(key, {
            "asset": asset_name,
            "role": step.get("agent_role") or "-",
            "security_control": set(),
            "log_source": set(),
            "statuses": set(),
        })
        if step.get("recommended_sensor"):
            row["security_control"].update(part.strip() for part in str(step.get("recommended_sensor")).split(",") if part.strip())
        if step.get("expected_log"):
            row["log_source"].update(part.strip() for part in str(step.get("expected_log")).split(",") if part.strip())
        if step.get("detection_status"):
            row["statuses"].add(step.get("detection_status"))

    fallback_rows = []
    for row in grouped.values():
        statuses = row.pop("statuses")
        if "detected" in statuses:
            coverage = "Covered"
        elif "logged_only" in statuses or "alert_without_source_sample" in statuses:
            coverage = "Partial"
        elif "missed" in statuses:
            coverage = "Gap"
        elif statuses:
            coverage = "검증 필요"
        else:
            coverage = "Manual"

        fallback_rows.append({
            "asset": row["asset"],
            "role": row["role"],
            "security_control": ", ".join(sorted(row["security_control"])) if row["security_control"] else "-",
            "log_source": ", ".join(sorted(row["log_source"])) if row["log_source"] else "-",
            "coverage": coverage,
        })

    if fallback_rows:
        return sorted(fallback_rows, key=lambda row: str(row.get("asset") or ""))

    return rows


def render_summary_html(report):
    summary = report["summary"]
    backlog = report.get("backlog", [])
    score = int(summary.get("final_score", 0))
    score_label = "양호" if score >= 80 else "개선 필요" if score >= 50 else "우선 개선"
    score_class = "good" if score >= 80 else "warn" if score >= 50 else "critical"

    def text(value):
        return escape(str(value if value is not None else "-"))

    def pct(value):
        return f"{float(value or 0) * 100:.0f}%"

    def badge(value, class_name="neutral"):
        return f"<span class=\"badge {class_name}\">{text(value)}</span>"

    def status_class(step):
        return {
            "detected": "good",
            "logged_only": "warn",
            "alert_without_source_sample": "warn",
            "missed": "critical",
            "not_checked": "neutral",
            "blocked": "blocked",
            "execution_failed": "critical",
        }.get(step.get("detection_status"), "neutral")

    def risk_class(step):
        return {
            "low": "good",
            "medium": "warn",
            "high": "critical",
            "critical": "critical",
        }.get(str(step.get("risk") or "").lower(), "neutral")

    def th(ko, en):
        return f"<th><span>{text(ko)}</span><small>{text(en)}</small></th>"

    def stacked_bar(row, matched_key, matched_label, missed_label, class_name):
        total = row.get("total") or 0
        matched = row.get(matched_key) or 0
        matched_percent = round((matched / total) * 100) if total else 0
        missed_percent = max(0, 100 - matched_percent)
        return (
            "<div class=\"stacked-bar-item\">"
            "<div class=\"stacked-bar\">"
            f"<i class=\"not-covered\" style=\"height: {missed_percent}%\" title=\"{text(missed_label)} {total - matched}/{total}\"></i>"
            f"<i class=\"covered {class_name}\" style=\"height: {matched_percent}%\" title=\"{text(matched_label)} {matched}/{total}\"></i>"
            "</div>"
            f"<strong>{matched}/{total}</strong>"
            f"<span>{text(row.get('label'))}</span>"
            "</div>"
        )

    def impact_bar(value):
        percent = max(0, min(100, int(value or 0)))
        return (
            "<div class=\"impact-bar\">"
            f"<i><b style=\"width: {percent}%\"></b></i>"
            f"<strong>{percent}%</strong>"
            "</div>"
        )

    def impact_value(step, field):
        value = step.get(field)
        if value is not None:
            return value
        return estimated_impact(step).get(field, 0)

    metrics = [
        ("준비도 점수", f"{score}/100"),
        ("실행 대상 Technique", summary.get("attack_steps", 0)),
        ("탐지됨", summary.get("detected_count", 0)),
        ("로그만 확인", summary.get("logged_only_count", 0)),
        ("미탐", summary.get("missed_count", 0)),
        ("확인 필요", summary.get("not_checked_count", 0)),
        ("로그 커버리지", pct(summary.get("telemetry_coverage"))),
        ("알림 커버리지", pct(summary.get("alert_coverage"))),
    ]
    metrics_html = "\n".join(
        f"<section class=\"metric\"><span>{text(label)}</span><strong>{text(value)}</strong></section>"
        for label, value in metrics
    )

    tactic_rows = build_tactic_coverage(report.get("steps", []))
    log_chart_html = "\n".join(
        stacked_bar(row, "log_matched", "Logged", "Not Logged", "log")
        for row in tactic_rows
    )
    alert_chart_html = "\n".join(
        stacked_bar(row, "alert_matched", "Alert", "No Alert", "alert")
        for row in tactic_rows
    )
    tactic_chart_html = (
        "<article class=\"tactic-chart\">"
        "<h3>Log Coverage Summary by Tactic</h3>"
        "<div class=\"chart-body\"><div class=\"chart-axis\">"
        "<span>100%</span><span>90%</span><span>80%</span><span>70%</span><span>60%</span>"
        "<span>50%</span><span>40%</span><span>30%</span><span>20%</span><span>10%</span>"
        "</div>"
        f"<div class=\"stacked-chart\">{log_chart_html}</div></div>"
        "<div class=\"chart-legend\"><span class=\"log-dot\">Logged</span><span class=\"miss-dot\">Not Logged</span></div>"
        "</article>"
        "<article class=\"tactic-chart\">"
        "<h3>Actionable Alert Summary by Tactic</h3>"
        "<div class=\"chart-body\"><div class=\"chart-axis\">"
        "<span>100%</span><span>90%</span><span>80%</span><span>70%</span><span>60%</span>"
        "<span>50%</span><span>40%</span><span>30%</span><span>20%</span><span>10%</span>"
        "</div>"
        f"<div class=\"stacked-chart\">{alert_chart_html}</div></div>"
        "<div class=\"chart-legend\"><span class=\"alert-dot\">Alert</span><span class=\"miss-dot\">No Alert</span></div>"
        "</article>"
    )
    if not tactic_chart_html:
        tactic_chart_html = "<p class=\"empty\">전술별 커버리지 데이터를 만들 수 없습니다.</p>"

    impact_steps = sorted(
        [step for step in report.get("steps", []) if step.get("technique_id")],
        key=lambda step: (impact_value(step, "service_impact_percent"), impact_value(step, "network_impact_percent")),
        reverse=True,
    )
    impact_rows = "\n".join(
        "<tr>"
        f"<td><strong>{text(step.get('technique_id'))}</strong><small>{text(step.get('attack_name') or step.get('name'))}</small></td>"
        f"<td>{badge(step.get('risk_level'), risk_class(step))}</td>"
        f"<td>{text(step.get('system_impact'))}</td>"
        f"<td>{impact_bar(impact_value(step, 'service_impact_percent'))}</td>"
        f"<td>{impact_bar(impact_value(step, 'network_impact_percent'))}</td>"
        f"<td>{text(step.get('impact_estimate_basis') or '추정')}</td>"
        "</tr>"
        for step in impact_steps[:8]
    )
    if not impact_rows:
        impact_rows = "<tr><td colspan=\"6\" class=\"empty\">실행 영향도 추정 정보가 없습니다.</td></tr>"

    if backlog:
        backlog_rows = "\n".join(
            "<tr>"
            f"<td><strong>{text(item.get('priority'))}</strong></td>"
            f"<td>{text(item.get('technique_id'))}</td>"
            f"<td>{text(GAP_LABELS.get(item.get('gap_type'), item.get('gap_type') or '-'))}</td>"
            f"<td>{text(ACTION_LABELS.get(item.get('recommended_action'), item.get('recommended_action') or '-'))}</td>"
            f"<td>{text(item.get('verification_method'))}</td>"
            "</tr>"
            for item in backlog
        )
    else:
        backlog_rows = "<tr><td colspan=\"5\" class=\"empty\">추가 개선 항목이 생성되지 않았습니다.</td></tr>"

    meaning_items = []
    if summary.get("missed_count", 0) or summary.get("critical_gaps", 0):
        meaning_items.append("미탐 또는 고위험 공백은 이 공격 경로를 검증 완료로 보기 전에 우선 보완해야 합니다.")
    if summary.get("logged_only_count", 0):
        meaning_items.append("일부 Technique은 로그는 남았지만 알림이 발생하지 않았으므로 탐지 룰 튜닝이 필요합니다.")
    if summary.get("not_checked_count", 0):
        meaning_items.append("일부 검증은 확정되지 않았습니다. ELK 쿼리, Agent 상태, 실행 모드를 다시 확인하세요.")
    if not meaning_items:
        meaning_items.append("이번 실행에서 큰 탐지 공백은 생성되지 않았습니다.")
    meaning_html = "\n".join(f"<li>{text(item)}</li>" for item in meaning_items)

    gap_analysis_steps = [
        step for step in report.get("steps", [])
        if should_show_gap_analysis(step)
    ]
    gap_analysis_rows = "\n".join(
        "<tr>"
        f"<td><strong>{text(step.get('technique_id'))}</strong><small>{text(step.get('attack_name') or step.get('name'))}</small></td>"
        f"<td>{badge(report_detection_result(step), status_class(step))}</td>"
        f"<td>{text(GAP_LABELS.get(step.get('gap_type'), step.get('gap_type') or '검토 필요'))}</td>"
        f"<td>{text(step.get('missed_reason') or detection_gap_reason(step))}</td>"
        f"<td>{text(step.get('recommended_sensor') or recommended_sensor(step) or '-')}</td>"
        f"<td>{text(report_improvement_plan(step))}</td>"
        "</tr>"
        for step in gap_analysis_steps
    )
    if not gap_analysis_rows:
        gap_analysis_rows = "<tr><td colspan=\"6\" class=\"empty\">미탐 또는 부분탐지 항목이 없습니다.</td></tr>"

    coverage_rows = "\n".join(
        f"<tr class=\"row-{status_class(step)}\">"
        f"<td><strong>{text(step.get('technique_id'))}</strong></td>"
        f"<td><strong>{text(step.get('attack_name') or step.get('name'))}</strong></td>"
        f"<td>{text(step.get('target_asset'))}</td>"
        f"<td>{text(step.get('required_condition'))}</td>"
        f"<td>{text(step.get('expected_log'))}</td>"
        f"<td>{text(step.get('detection_rule'))}</td>"
        f"<td>{badge(report_detection_result(step), status_class(step))}</td>"
        f"<td>{badge(step.get('coverage_status'), status_class(step))}</td>"
        f"<td>{text(step.get('system_impact'))}</td>"
        f"<td>{text(str(impact_value(step, 'service_impact_percent')) + '%')}</td>"
        f"<td>{text(str(impact_value(step, 'network_impact_percent')) + '%')}</td>"
        f"<td>{badge(step.get('risk_level'), risk_class(step))}</td>"
        f"<td>{text(step.get('recommended_sensor'))}</td>"
        f"<td>{text(report_improvement_plan(step))}</td>"
        "</tr>"
        for step in report.get("steps", [])
        if step.get("technique_id")
    )
    if not coverage_rows:
        coverage_rows = "<tr><td colspan=\"14\" class=\"empty\">생성된 BAS 커버리지 결과가 없습니다.</td></tr>"

    asset_mapping = report.get("asset_control_mapping") or build_asset_control_mapping(report.get("target"), report.get("steps", []))
    asset_mapping_rows = "\n".join(
        "<tr>"
        f"<td><strong>{text(row.get('asset'))}</strong><small>{text(row.get('role'))}</small></td>"
        f"<td>{text(row.get('security_control'))}</td>"
        f"<td>{text(row.get('log_source'))}</td>"
        f"<td>{badge(row.get('coverage'), 'good' if row.get('coverage') == 'Covered' else 'warn' if row.get('coverage') in ('Partial', '검증 필요') else 'critical' if row.get('coverage') == 'Gap' else 'neutral')}</td>"
        "</tr>"
        for row in asset_mapping
    )
    if not asset_mapping_rows:
        asset_mapping_rows = "<tr><td colspan=\"4\" class=\"empty\">자산/보안 솔루션 매핑 정보가 없습니다.</td></tr>"

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{text(report.get('campaign_name') or report.get('campaign_id'))} BAS 결과 보고서</title>
  <style>
    :root {{
      color: #101820;
      background: #eef2f6;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 32px; }}
    main {{ max-width: 1240px; margin: 0 auto; }}
    header, section.panel {{
      border: 1px solid #d7e0ea;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
    }}
    header {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 220px;
      gap: 24px;
      padding: 30px;
      border-top: 5px solid #2563eb;
    }}
    .eyebrow {{ margin: 0 0 8px; color: #2563eb; font-size: 12px; font-weight: 900; letter-spacing: 0; }}
    h1 {{ margin: 0 0 12px; font-size: 34px; line-height: 1.08; letter-spacing: 0; }}
    h2 {{ margin: 0 0 8px; font-size: 19px; }}
    .section-desc {{ margin: 0 0 16px; }}
    p, li {{ color: #475569; line-height: 1.65; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 10px; color: #64748b; font-size: 13px; }}
    .meta span {{ border: 1px solid #dbe3ec; border-radius: 999px; padding: 7px 10px; background: #f8fafc; }}
    .score {{ display: grid; align-content: center; justify-items: center; border-radius: 10px; padding: 18px; background: #f8fafc; border: 1px solid #dbe3ec; }}
    .score strong {{ font-size: 48px; line-height: 1; }}
    .score span {{ margin-top: 10px; font-weight: 800; }}
    .score.good strong {{ color: #15803d; }}
    .score.warn strong {{ color: #b45309; }}
    .score.critical strong {{ color: #b91c1c; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0; }}
    .metric {{ border: 1px solid #dbe3ec; border-radius: 10px; padding: 14px; background: #f8fafc; }}
    .metric span {{ display: block; color: #64748b; font-size: 12px; font-weight: 800; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 24px; }}
    section.panel {{ margin-top: 18px; padding: 24px; }}
    .impact-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .impact-bar {{ display: grid; grid-template-columns: minmax(92px, 1fr) 42px; gap: 9px; align-items: center; min-width: 160px; }}
    .impact-bar i {{ height: 9px; overflow: hidden; border-radius: 999px; background: #e2e8f0; }}
    .impact-bar i b {{ display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #22c55e, #f59e0b 54%, #ef4444); }}
    .impact-bar strong {{ color: #0f172a; font-size: 12px; font-weight: 900; text-align: right; }}
    .tactic-grid {{ display: grid; gap: 16px; }}
    .tactic-chart {{
      border: 1px solid #dbe3ec;
      border-radius: 10px;
      background: #fbfdff;
      overflow: hidden;
      padding: 16px 16px 12px;
    }}
    .tactic-chart h3 {{ margin: 0 0 12px; color: #1d4ed8; font-size: 16px; text-align: center; }}
    .chart-body {{ display: grid; grid-template-columns: 42px minmax(0, 1fr); gap: 8px; align-items: start; }}
    .chart-axis {{
      display: grid;
      grid-template-rows: repeat(10, 16px);
      height: 160px;
      padding-top: 1px;
      color: #1d4ed8;
      font-size: 10px;
      font-weight: 800;
      text-align: right;
    }}
    .stacked-chart {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(56px, 1fr));
      align-items: end;
      column-gap: 7px;
      min-height: 214px;
      padding: 8px 0 0;
      background-image: linear-gradient(to top, #bfdbfe 1px, transparent 1px);
      background-size: 100% 16px;
      border-bottom: 2px solid #cbd5e1;
    }}
    .stacked-bar-item {{ display: grid; grid-template-rows: 160px 18px minmax(34px, auto); justify-items: center; gap: 5px; min-width: 0; }}
    .stacked-bar {{
      align-self: end;
      display: flex;
      flex-direction: column;
      justify-content: flex-end;
      width: 32px;
      height: 160px;
      overflow: hidden;
      background: #e2e8f0;
      border: 1px solid #dbe3ec;
    }}
    .stacked-bar i {{ display: block; width: 100%; min-height: 0; }}
    .stacked-bar .covered.log {{ background: #f97316; }}
    .stacked-bar .covered.alert {{ background: #f97316; }}
    .stacked-bar .not-covered {{ background: #334155; }}
    .stacked-bar-item strong {{ color: #334155; font-size: 11px; }}
    .stacked-bar-item span {{ color: #1d4ed8; font-size: 10px; font-weight: 800; line-height: 1.15; text-align: center; word-break: keep-all; }}
    .chart-legend {{ display: flex; justify-content: center; gap: 16px; margin-top: 10px; color: #334155; font-size: 11px; font-weight: 900; }}
    .chart-legend span::before {{ content: ""; display: inline-block; width: 8px; height: 8px; margin-right: 5px; border-radius: 2px; vertical-align: -1px; }}
    .chart-legend .log-dot::before,
    .chart-legend .alert-dot::before {{ background: #f97316; }}
    .chart-legend .miss-dot::before {{ background: #334155; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e2e8f0; padding: 12px; text-align: left; vertical-align: top; }}
    th {{ color: #475569; background: #f8fafc; font-size: 12px; position: sticky; top: 0; z-index: 1; }}
    th span, th small {{ display: block; }}
    th span {{ color: #0f172a; font-size: 12px; font-weight: 900; }}
    th small {{ margin-top: 3px; color: #64748b; font-size: 10px; font-weight: 800; }}
    td {{ background: #fff; }}
    tbody tr.row-good td:first-child {{ border-left: 4px solid #16a34a; }}
    tbody tr.row-warn td:first-child {{ border-left: 4px solid #d97706; }}
    tbody tr.row-critical td:first-child {{ border-left: 4px solid #dc2626; }}
    tbody tr.row-blocked td:first-child {{ border-left: 4px solid #64748b; }}
    .table-wrap {{ overflow-x: auto; border: 1px solid #e2e8f0; border-radius: 10px; }}
    .coverage-table {{ min-width: 1900px; }}
    .asset-control-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .gap-analysis-table {{ min-width: 1180px; }}
    .gap-analysis-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }}
    .badge.good {{ color: #166534; background: #dcfce7; }}
    .badge.warn {{ color: #92400e; background: #fef3c7; }}
    .badge.critical {{ color: #991b1b; background: #fee2e2; }}
    .badge.blocked, .badge.neutral {{ color: #334155; background: #e2e8f0; }}
    .empty {{ color: #64748b; text-align: center; }}
    @media (max-width: 820px) {{
      body {{ padding: 16px; }}
      header {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .chart-body {{ grid-template-columns: 36px minmax(0, 1fr); }}
      .stacked-chart {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p class="eyebrow">BAS 탐지 커버리지 검증 보고서</p>
        <h1>{text(report.get('campaign_name') or report.get('campaign_id'))} 실행 결과</h1>
        <p>이 보고서는 공격 성공 여부보다 로그 수집, 탐지 룰, 커버리지 공백, 시스템 영향도, 개선 방향을 기준으로 BAS 실행 결과를 정리합니다.</p>
        <div class="meta">
          <span>Report {text(report.get('report_id'))}</span>
          <span>대상 {text(report.get('campaign_id'))}</span>
          <span>생성 시각 {text(report.get('generated_at'))}</span>
        </div>
      </div>
      <div class="score {score_class}">
        <strong>{score}</strong>
        <span>{text(score_label)}</span>
      </div>
    </header>
    <section class="panel">
      <h2>핵심 지표</h2>
      <p class="section-desc">탐지 체계가 실제 로그와 알림까지 이어졌는지 요약한 값입니다.</p>
      <div class="grid">{metrics_html}</div>
    </section>
    <section class="panel">
      <h2>실행 영향도 추정</h2>
      <p class="section-desc">공격 실행 전에 기업이 운영 서비스에 줄 수 있는 장애/다운 가능성과 네트워크 지연 가능성을 확인할 수 있도록 risk, behavior, requires, safety gate 기준으로 산정한 추정값입니다. 실제 계측값이 아니라 실행 승인 판단을 돕는 보수적 지표입니다.</p>
      <div class="table-wrap">
        <table class="impact-table">
          <thead>
            <tr>
              {th("테크닉", "Technique")}
              {th("위험도", "Risk")}
              {th("시스템 영향도", "System Impact")}
              {th("장애/다운 추정", "Service Impact")}
              {th("네트워크 지연 추정", "Network Impact")}
              {th("산정 기준", "Basis")}
            </tr>
          </thead>
          <tbody>{impact_rows}</tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>전술별 로그/알림 커버리지</h2>
      <p class="section-desc">NetSPI BAS 샘플 레포트처럼 tactic 단위로 로그 수집과 알림 발생 여부를 먼저 볼 수 있게 배치했습니다.</p>
      <div class="tactic-grid">{tactic_chart_html}</div>
    </section>
    <section class="panel">
      <h2>자산/보안 솔루션 매핑</h2>
      <p class="section-desc">우리 환경의 어떤 보안 자산으로 각 공격 흐름을 볼 수 있는지 정리했습니다. 실제 솔루션이 많지 않아도 현재 보유한 로그 소스와 탐지 백엔드를 기준으로 표시합니다.</p>
      <div class="table-wrap">
        <table class="asset-control-table">
          <thead>
            <tr>
              {th("자산", "Asset")}
              {th("보안 솔루션", "Security Control")}
              {th("로그 소스", "Log Source")}
              {th("커버리지", "Coverage")}
            </tr>
          </thead>
          <tbody>{asset_mapping_rows}</tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>해석</h2>
      <ul>{meaning_html}</ul>
    </section>
    <section class="panel">
      <h2>미탐 원인 및 필요 센서</h2>
      <p class="section-desc">미탐, 부분탐지, 검증 미완료 항목을 따로 모아 왜 잡히지 않았는지와 어떤 로그/센서가 필요한지 정리했습니다. 기업 보안팀이 룰 개선 또는 센서 보강 우선순위를 잡는 데 쓰는 표입니다.</p>
      <div class="table-wrap">
        <table class="gap-analysis-table">
          <thead>
            <tr>
              {th("테크닉", "Technique")}
              {th("탐지 결과", "Detection Result")}
              {th("공백 유형", "Gap Type")}
              {th("왜 안 잡혔는지", "Why It Was Missed")}
              {th("필요 센서", "Required Sensor")}
              {th("개선 계획", "Improvement Plan")}
            </tr>
          </thead>
          <tbody>{gap_analysis_rows}</tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>BAS 상세 결과표</h2>
      <p class="section-desc">멘토링 피드백 기준의 필수 항목을 Technique 단위로 정리했습니다. 룰 이름, 센서명, 쿼리 식별자는 원문을 유지합니다.</p>
      <div class="table-wrap">
        <table class="coverage-table">
          <thead>
            <tr>
              {th("테크닉 ID", "Technique ID")}
              {th("공격명", "Attack Name")}
              {th("대상 자산", "Target Asset")}
              {th("필수 조건", "Required Condition")}
              {th("기대 로그", "Expected Log")}
              {th("탐지 룰", "Detection Rule")}
              {th("탐지 결과", "Detection Result")}
              {th("커버리지 상태", "Coverage Status")}
              {th("시스템 영향도", "System Impact")}
              {th("장애/다운 추정", "Service Impact")}
              {th("네트워크 지연 추정", "Network Impact")}
              {th("위험도", "Risk Level")}
              {th("권장 센서", "Recommended Sensor")}
              {th("개선 계획", "Improvement Plan")}
            </tr>
          </thead>
          <tbody>{coverage_rows}</tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>개선 백로그</h2>
      <table>
        <thead>
          <tr>
            {th("우선순위", "Priority")}
            {th("Technique", "Technique")}
            {th("공백 유형", "Gap")}
            {th("권장 조치", "Action")}
            {th("검증 방법", "Verify")}
          </tr>
        </thead>
        <tbody>{backlog_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def render_technical_markdown(report):
    def cell(value):
        return str(value if value is not None else "-").replace("|", "\\|").replace("\n", " ")

    lines = [
        f"# {report.get('campaign_name') or report.get('campaign_id')} BAS 상세 탐지 보고서",
        "",
        "## BAS 상세 결과표",
        "",
        "| 테크닉 ID | 공격명 | 대상 자산 | 필수 조건 | 기대 로그 | 탐지 룰 | 탐지 결과 | 커버리지 상태 | 시스템 영향도 | 장애/다운 추정 | 네트워크 지연 추정 | 위험도 | 권장 센서 | 개선 계획 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for step in report.get("steps", []):
        lines.append(
            f"| {cell(step.get('technique_id') or '-')} | {cell(step.get('attack_name') or step.get('name') or '-')} | "
            f"{cell(step.get('target_asset') or '-')} | {cell(step.get('required_condition') or '-')} | "
            f"{cell(step.get('expected_log') or '-')} | {cell(step.get('detection_rule') or '-')} | "
            f"{cell(report_detection_result(step))} | "
            f"{cell(step.get('coverage_status') or '-')} | {cell(step.get('system_impact') or '-')} | "
            f"{cell(str(step.get('service_impact_percent', 0)) + '%')} | "
            f"{cell(str(step.get('network_impact_percent', 0)) + '%')} | "
            f"{cell(step.get('risk_level') or step.get('risk') or '-')} | {cell(step.get('recommended_sensor') or '-')} | "
            f"{cell(report_improvement_plan(step))} |"
        )

    gap_steps = [step for step in report.get("steps", []) if should_show_gap_analysis(step)]
    lines.extend([
        "",
        "## 미탐 원인 및 필요 센서",
        "",
        "| Technique | 탐지 결과 | 공백 유형 | 왜 안 잡혔는지 | 필요 센서 | 개선 계획 |",
        "| --- | --- | --- | --- | --- | --- |",
    ])

    if gap_steps:
        for step in gap_steps:
            gap = step.get("gap_type") or "-"
            lines.append(
                f"| {cell(step.get('technique_id') or '-')} | "
                f"{cell(report_detection_result(step))} | "
                f"{cell(GAP_LABELS.get(gap, gap))} | "
                f"{cell(step.get('missed_reason') or detection_gap_reason(step))} | "
                f"{cell(step.get('recommended_sensor') or recommended_sensor(step) or '-')} | "
                f"{cell(report_improvement_plan(step))} |"
            )
    else:
        lines.append("| - | - | - | 미탐 또는 부분탐지 항목이 없습니다. | - | - |")

    lines.extend([
        "",
        "## 단계별 진단",
        "",
        "| 순서 | Technique | 실행 | 원본 로그 | 알림 | 탐지 | 공백 유형 | 조치 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])

    for step in report.get("steps", []):
        action = step.get("recommendation", {}).get("action") or ""
        gap = step.get("gap_type") or "-"
        lines.append(
            f"| {cell(step.get('order'))} | {cell(step.get('technique_id') or '-')} | "
            f"{cell(EXECUTION_STATUS_LABELS.get(step.get('execution_status'), step.get('execution_status')))} | {cell(step.get('source_status'))} | "
            f"{cell(step.get('alert_status'))} | {cell(DETECTION_RESULT_LABELS.get(step.get('detection_status'), step.get('detection_status')))} | "
            f"{cell(GAP_LABELS.get(gap, gap))} | {cell(ACTION_LABELS.get(action, action))} |"
        )

    lines.extend(["", "## 쿼리 증거", ""])
    for step in report.get("steps", []):
        if not step.get("technique_id"):
            continue
        lines.extend([
            f"### Step {step.get('order')} {step.get('technique_id')} {step.get('name')}",
            "",
            f"- 탐지 상태: {DETECTION_RESULT_LABELS.get(step.get('detection_status'), step.get('detection_status'))}",
            f"- 원본 이벤트 수: {step.get('source_event_count')}",
            f"- 알림 수: {step.get('alert_count')}",
            f"- Source query: `{step.get('queries', {}).get('source') or ''}`",
            f"- Alert query: `{step.get('queries', {}).get('alert') or ''}`",
            "",
        ])

    return "\n".join(lines)


def write_backlog_csv(path, backlog):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "priority",
        "technique_id",
        "order",
        "gap_type",
        "affected_host",
        "current_rule_id",
        "current_rule_name",
        "recommended_action",
        "suggested_query",
        "owner",
        "effort",
        "due_hint",
        "verification_method",
    ]

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for item in backlog:
            writer.writerow({field: item.get(field, "") for field in fields})


def write_coverage_csv(path, steps):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "technique_id",
        "attack_name",
        "target_asset",
        "required_condition",
        "expected_log",
        "detection_rule",
        "detection_result",
        "coverage_status",
        "system_impact",
        "service_impact_percent",
        "network_impact_percent",
        "risk_level",
        "recommended_sensor",
        "missed_reason",
        "improvement_plan",
    ]

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for step in steps:
            if not step.get("technique_id"):
                continue
            row = {field: step.get(field, "") for field in fields}
            row["detection_result"] = report_detection_result(step)
            row["missed_reason"] = step.get("missed_reason") or detection_gap_reason(step)
            row["improvement_plan"] = report_improvement_plan(step)
            writer.writerow(row)


def build_navigator_layer(report):
    colors = {
        "detected": "#16a34a",
        "logged_only": "#f59e0b",
        "missed": "#dc2626",
        "not_checked": "#94a3b8",
        "blocked": "#2563eb",
        "execution_failed": "#991b1b",
        "alert_without_source_sample": "#eab308",
    }

    techniques = []
    for step in report.get("steps", []):
        technique_id = step.get("technique_id")
        if not technique_id:
            continue
        status = step.get("detection_status")
        techniques.append({
            "techniqueID": technique_id,
            "score": status_score(status),
            "color": colors.get(status, "#94a3b8"),
            "comment": f"{status}. Source={step.get('source_status')}, Alert={step.get('alert_status')}.",
        })

    return {
        "name": f"{report.get('campaign_id')} BAS Detection Coverage",
        "versions": {
            "attack": "15",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"Generated from {report.get('source_id')} at {report.get('generated_at')}.",
        "techniques": techniques,
    }

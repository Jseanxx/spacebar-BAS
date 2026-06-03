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
    "baseline": "기준선",
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
    "baseline": "baseline",
    "기준선": "baseline",
}

COVERAGE_STATUS_LABELS = {
    "detected": "커버됨",
    "logged_only": "부분 커버",
    "alert_without_source_sample": "부분 커버",
    "missed": "공백",
    "not_checked": "확인 필요",
    "blocked": "차단",
    "execution_failed": "실행 실패",
    "baseline": "기준선",
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
    "baseline_only": "기준선 유지",
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
    "baseline_only": "정상 기준선 단계이므로 공격 탐지 점수에서 제외됩니다.",
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
    "T1133": "initial_access",
    "T1190": "initial_access",
    "T1195.002": "initial_access",
    "T1046": "discovery",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1482": "discovery",
    "T1059.004": "execution",
    "T1505.003": "persistence",
    "T1053.005": "persistence",
    "T1021.002": "lateral_movement",
    "T1550.002": "lateral_movement",
    "T1620": "defense_evasion",
    "T1592": "discovery",
    "T1078": "persistence",
    "T1552.004": "credential_access",
    "T1213.006": "collection",
    "T1048.002": "exfiltration",
    "T1613": "discovery",
    "T1552.007": "credential_access",
    "T1609": "collection",
    "T1610": "execution",
    "T1098.006": "persistence",
    "T1567.002": "exfiltration",
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

    if is_normal_step(step):
        return {
            "execution_status": execution_status,
            "detection_status": "baseline",
            "source_status": "not_scored",
            "alert_status": "not_scored",
            "source_event_count": event_count(step.get("elk_check") or {}),
            "alert_count": event_count(get_alert_check(step.get("elk_check") or {})),
            "gap_type": None,
        }

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

    if status == "baseline":
        return {
            "action": "baseline_only",
            "reason": "Normal baseline step is retained for context but excluded from attack detection scoring.",
        }
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


def is_normal_step(step):
    return str((step or {}).get("phase") or "").lower() == "normal"


def calculate_metrics(steps):
    scored_steps = [step for step in steps if not is_normal_step(step)]
    attack_steps = [step for step in scored_steps if step.get("technique_id")]
    real_attack_steps = [
        step for step in attack_steps
        if step.get("execution_status") not in ("simulated", "failed", "blocked")
    ]
    executed_steps = [step for step in attack_steps if step.get("execution_status") in ("success", "simulated")]
    failed_steps = [step for step in attack_steps if step.get("execution_status") == "failed"]
    blocked_steps = [step for step in attack_steps if step.get("execution_status") == "blocked"]
    simulated_steps = [step for step in attack_steps if step.get("execution_status") == "simulated"]

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
    total_count = len(attack_steps)
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
        "baseline_steps": len(steps) - len(scored_steps),
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
        if is_normal_step(step):
            continue
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
        if is_normal_step(step):
            continue
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
        if is_normal_step(step):
            continue
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

    def flow_status_key(step):
        if is_normal_step(step) or step.get("detection_status") == "baseline":
            return "baseline"
        status = step.get("detection_status") or "not_checked"
        if status == "alert_without_source_sample":
            return "logged_only"
        if status not in ("detected", "logged_only", "missed", "not_checked", "blocked", "execution_failed"):
            return "not_checked"
        return status

    def flow_status_label(step):
        return DETECTION_RESULT_LABELS.get(flow_status_key(step), "확인 필요")

    def aggregate_status(statuses):
        status_set = set(statuses)
        for status in ("detected", "logged_only", "missed", "execution_failed", "blocked", "not_checked"):
            if status in status_set:
                return status
        if "baseline" in status_set:
            return "baseline"
        return "not_checked"

    def matrix_status_class(status):
        return {
            "detected": "detected",
            "logged_only": "partial",
            "alert_without_source_sample": "partial",
            "missed": "missed",
            "execution_failed": "missed",
            "blocked": "blocked",
            "not_checked": "unchecked",
            "baseline": "baseline",
        }.get(status, "unchecked")

    def short_name(step):
        return step.get("attack_name") or step.get("name") or step.get("technique_id") or "-"

    flow_steps = [
        step for step in sorted(report.get("steps", []), key=lambda item: item.get("order") or 9999)
        if step.get("technique_id") or is_normal_step(step)
    ]
    repeated_counts = {}
    for step in flow_steps:
        key = step.get("technique_id") or step.get("attack_name") or step.get("name")
        if key:
            repeated_counts[key] = repeated_counts.get(key, 0) + 1
    flow_groups = []
    for step in flow_steps[:18]:
        group_key = "baseline" if is_normal_step(step) else tactic_key_for_step(step)
        if not flow_groups or flow_groups[-1]["key"] != group_key:
            flow_groups.append({
                "key": group_key,
                "label": "정상 기준" if group_key == "baseline" else TACTIC_LABELS.get(group_key, group_key),
                "steps": [],
            })
        flow_groups[-1]["steps"].append(step)

    def flow_status_counts(steps):
        counts = {}
        for item in steps:
            status = flow_status_key(item)
            counts[status] = counts.get(status, 0) + 1
        return counts

    def flow_status_summary(steps):
        counts = flow_status_counts(steps)
        labels = [
            ("detected", "탐지"),
            ("logged_only", "부분"),
            ("missed", "미탐"),
            ("execution_failed", "실패"),
            ("blocked", "차단"),
            ("not_checked", "확인 필요"),
            ("baseline", "정상"),
        ]
        return "\n".join(
            f"<span class=\"flow-status-pill {matrix_status_class(status)}\">{text(label)} {text(counts[status])}</span>"
            for status, label in labels
            if counts.get(status)
        )

    def flow_asset_chips(steps):
        assets = []
        seen = set()
        for item in steps:
            asset = item.get("target_asset") or item.get("asset") or item.get("host")
            if asset and asset not in seen:
                seen.add(asset)
                assets.append(asset)
        if not assets:
            return "<span>대상 자산 미지정</span>"
        chips = [f"<span>{text(asset)}</span>" for asset in assets[:3]]
        if len(assets) > 3:
            chips.append(f"<span>+{len(assets) - 3}</span>")
        return "\n".join(chips)

    flow_html = "\n".join(
        "<section class=\"flow-stage stage-{stage_status} {stage_offset}\">"
        "<div class=\"flow-step-dot\">{stage_no}</div>"
        "<div class=\"flow-card\">"
        "<header><div><strong>{stage_label}</strong><small>Step {order_range} · {step_count}개 이벤트</small></div></header>"
        "<p class=\"flow-route\">{stage_note}</p>"
        "<div class=\"flow-assets\">{assets}</div>"
        "<div class=\"flow-status-strip\">{status_summary}</div>"
        "<div class=\"technique-chips\"><b>Technique</b>{techniques}</div>"
        "</div>"
        "</section>".format(
            stage_status=matrix_status_class(aggregate_status([flow_status_key(item) for item in group["steps"]])),
            stage_offset="flow-lower" if index % 2 else "flow-upper",
            stage_no=text(f"{index + 1:02d}"),
            stage_label=text(group["label"]),
            step_count=text(len(group["steps"])),
            order_range=text(
                f"{group['steps'][0].get('order') or '-'}~{group['steps'][-1].get('order') or '-'}"
                if len(group["steps"]) > 1
                else group["steps"][0].get("order") or "-"
            ),
            stage_note=text(
                "정상 로그 기준선을 먼저 확보합니다."
                if group["key"] == "baseline"
                else f"{group['label']} 단계에서 대상 자산으로 검증 흐름이 이동합니다."
            ),
            assets=flow_asset_chips(group["steps"]),
            status_summary=flow_status_summary(group["steps"]),
            techniques="\n".join(
                f"<span>{text(step.get('technique_id') or 'Normal')}</span>"
                for step in group["steps"][:5]
            ) + (
                f"<span>+{len(group['steps']) - 5}</span>"
                if len(group["steps"]) > 5 else ""
            ),
        )
        for index, group in enumerate(flow_groups)
    )
    if not flow_html:
        flow_html = "<p class=\"empty\">표시할 공격 흐름 데이터가 없습니다.</p>"

    flow_legend_html = """
      <span class="legend-item detected">탐지 성공</span>
      <span class="legend-item partial">로그만/부분 확인</span>
      <span class="legend-item missed">미탐 또는 실행 실패</span>
      <span class="legend-item blocked">차단/게이트</span>
      <span class="legend-item unchecked">확인 필요</span>
      <span class="legend-item baseline">정상 기준 로그</span>
    """

    attack_steps_for_matrix = [
        step for step in report.get("steps", [])
        if step.get("technique_id") and not is_normal_step(step)
    ]
    technique_summary = {}
    for step in attack_steps_for_matrix:
        technique_id = step.get("technique_id")
        row = technique_summary.setdefault(technique_id, {
            "technique_id": technique_id,
            "name": short_name(step),
            "tactic": tactic_key_for_step(step),
            "statuses": [],
            "count": 0,
        })
        row["statuses"].append(step.get("detection_status") or "not_checked")
        row["count"] += 1

    grouped_techniques = {key: [] for key in TACTIC_ORDER}
    for item in technique_summary.values():
        item["status"] = aggregate_status(item["statuses"])
        grouped_techniques.setdefault(item["tactic"], []).append(item)

    mitre_columns = []
    for tactic in TACTIC_ORDER:
        items = sorted(grouped_techniques.get(tactic, []), key=lambda item: item["technique_id"])
        if not items:
            continue
        cells = "\n".join(
            "<span class=\"ttp-cell {status}\" title=\"{title}\">"
            "<strong>{technique}</strong><small>{count_label}</small>"
            "</span>".format(
                status=matrix_status_class(item["status"]),
                title=text(f"{item['name']} · {DETECTION_RESULT_LABELS.get(item['status'], item['status'])}"),
                technique=text(item["technique_id"]),
                count_label=text(f"{item['count']}회" if item["count"] > 1 else DETECTION_RESULT_LABELS.get(item["status"], item["status"])),
            )
            for item in items
        )
        mitre_columns.append(
            "<section class=\"mitre-column\">"
            f"<h3>{text(TACTIC_LABELS.get(tactic, tactic))}</h3>"
            f"{cells}"
            "</section>"
        )
    mitre_matrix_html = "\n".join(mitre_columns) or "<p class=\"empty\">MITRE ATT&CK 매트릭스 데이터가 없습니다.</p>"

    total_attack_count = summary.get("attack_steps", 0) or len(attack_steps_for_matrix)
    detected_or_blocked = sum(
        1 for step in attack_steps_for_matrix
        if step.get("detection_status") in ("detected", "blocked")
    )
    matrix_ratio_html = (
        "<div class=\"matrix-ratio\">"
        f"<strong>{text(detected_or_blocked)} / {text(total_attack_count)}</strong>"
        "<span>전체 공격 Technique 대비 탐지/차단 확인 수</span>"
        "</div>"
    )

    explanation_cards_html = "\n".join([
        "<article><strong>공격 흐름 우선</strong><p>숫자보다 먼저 어떤 Technique이 어떤 순서와 상태로 검증됐는지 보여줍니다.</p></article>",
        "<article><strong>색상 의미 고정</strong><p>초록은 탐지, 노랑은 부분 확인, 빨강은 미탐/실패, 파랑은 차단, 회색은 확인 필요입니다.</p></article>",
        "<article><strong>정상/공격 구분</strong><p>Normal 단계는 정상 기준 로그로 분리하고, 공격 커버리지 점수에는 공격 Technique만 반영합니다.</p></article>",
        "<article><strong>개선 증거</strong><p>로그가 없던 항목은 센서 보강, 알림이 없던 항목은 탐지 룰 튜닝 대상으로 분리합니다.</p></article>",
    ])

    appendix_rows = "\n".join([
        f"<tr><td><strong>원본 BAS 실행 결과</strong></td><td>분류 전/후 실행 결과 JSON</td><td><a href=\"/reports/{text(report.get('report_id'))}\">Report JSON</a></td></tr>",
        "<tr><td><strong>Flow 상세 설명</strong></td><td>Technique별 상세 실행/탐지 근거를 사람이 읽는 Markdown으로 정리</td><td><a href=\"technical.md\">technical.md</a></td></tr>",
        "<tr><td><strong>커버리지 매핑표</strong></td><td>Technique, 로그, 알림, 개선 계획을 스프레드시트로 분석하기 위한 CSV</td><td><a href=\"coverage.csv\">coverage.csv</a></td></tr>",
        "<tr><td><strong>탐지 개선 백로그</strong></td><td>미탐/부분탐지 개선 작업 목록을 스프레드시트로 관리하기 위한 CSV</td><td><a href=\"backlog.csv\">backlog.csv</a></td></tr>",
        "<tr><td><strong>MITRE Navigator Layer</strong></td><td>ATT&CK Navigator에 업로드하는 기계 판독용 JSON</td><td><a href=\"navigator.json\">navigator.json</a></td></tr>",
    ])

    metrics = [
        ("준비도 점수", f"{score}/100", "score"),
        ("실행 대상 Technique", summary.get("attack_steps", 0), "total"),
        ("탐지됨", summary.get("detected_count", 0), "detected"),
        ("차단/게이트", sum(1 for step in attack_steps_for_matrix if step.get("detection_status") == "blocked"), "blocked"),
        ("로그만 확인", summary.get("logged_only_count", 0), "partial"),
        ("미탐", summary.get("missed_count", 0), "missed"),
        ("확인 필요", summary.get("not_checked_count", 0), "unchecked"),
        ("로그 커버리지", pct(summary.get("telemetry_coverage")), "log"),
        ("알림 커버리지", pct(summary.get("alert_coverage")), "alert"),
    ]
    metrics_html = "\n".join(
        f"<section class=\"metric metric-{class_name}\"><span>{text(label)}</span><strong>{text(value)}</strong></section>"
        for label, value, class_name in metrics
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
        f"<td>{text(step.get('expected_log'))}</td>"
        f"<td>{text(step.get('detection_rule'))}</td>"
        f"<td>{badge(report_detection_result(step), status_class(step))}</td>"
        f"<td>{badge(step.get('coverage_status'), status_class(step))}</td>"
        f"<td>{text(step.get('system_impact'))}</td>"
        f"<td>{badge(step.get('risk_level'), risk_class(step))}</td>"
        f"<td>{text(step.get('recommended_sensor'))}</td>"
        f"<td>{text(report_improvement_plan(step))}</td>"
        "</tr>"
        for step in report.get("steps", [])
        if step.get("technique_id")
    )
    if not coverage_rows:
        coverage_rows = "<tr><td colspan=\"11\" class=\"empty\">생성된 BAS 커버리지 결과가 없습니다.</td></tr>"

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
      color: #111827;
      background: #f3f6f9;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px;
      background: #f3f6f9;
    }}
    main {{ max-width: 1320px; margin: 0 auto; }}
    header, section.panel {{
      border: 1px solid #d9e2ec;
      border-radius: 10px;
      background: #fff;
      box-shadow: 0 14px 34px rgba(15, 23, 42, 0.06);
    }}
    header {{
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 170px;
      gap: 22px;
      padding: 26px 28px;
      color: #0f172a;
      border-top: 5px solid #0f766e;
      background:
        linear-gradient(90deg, rgba(15, 118, 110, 0.08), transparent 48%),
        #fff;
    }}
    header::after {{
      content: "";
      position: absolute;
      right: 28px;
      bottom: 0;
      width: 180px;
      height: 4px;
      background: linear-gradient(90deg, #0f766e, #2563eb);
    }}
    header > * {{ position: relative; z-index: 1; }}
    .eyebrow {{ margin: 0 0 8px; color: #0f766e; font-size: 12px; font-weight: 900; letter-spacing: 0; }}
    h1 {{ max-width: 840px; margin: 0 0 10px; font-size: 29px; line-height: 1.16; letter-spacing: 0; }}
    h2 {{ margin: 0 0 8px; font-size: 18px; color: #0f172a; }}
    .section-desc {{ margin: 0 0 16px; color: #64748b; }}
    p, li {{ color: #475569; line-height: 1.68; }}
    header p {{ max-width: 820px; color: #475569; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 10px; color: #64748b; font-size: 13px; }}
    .meta span {{ border: 1px solid #dbe4ee; border-radius: 999px; padding: 7px 11px; background: #f8fafc; color: #475569; }}
    .score {{ display: grid; align-content: center; justify-items: center; border-radius: 9px; padding: 16px; background: #0f172a; color: #f8fafc; }}
    .score strong {{ font-size: 44px; line-height: 1; }}
    .score span {{ margin-top: 10px; color: #cbd5e1; font-weight: 900; }}
    .score.good strong {{ color: #15803d; }}
    .score.warn strong {{ color: #b45309; }}
    .score.critical strong {{ color: #b91c1c; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 18px 0 0; }}
    .metric {{
      position: relative;
      overflow: hidden;
      border: 1px solid #dbe4ee;
      border-radius: 9px;
      padding: 15px;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
    }}
    .metric::before {{ content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: #64748b; }}
    .metric-score::before {{ background: #0f172a; }}
    .metric-total::before {{ background: #64748b; }}
    .metric-detected::before {{ background: #16a34a; }}
    .metric-blocked::before {{ background: #2563eb; }}
    .metric-partial::before,
    .metric-log::before,
    .metric-alert::before {{ background: #f59e0b; }}
    .metric-missed::before {{ background: #dc2626; }}
    .metric-unchecked::before {{ background: #94a3b8; }}
    .metric span {{ display: block; color: #64748b; font-size: 11px; font-weight: 900; }}
    .metric strong {{ display: block; margin-top: 8px; color: #0f172a; font-size: 25px; line-height: 1; }}
    section.panel {{ margin-top: 18px; padding: 24px; }}
    section.panel h2 {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    section.panel h2::before {{
      content: "";
      width: 7px;
      height: 24px;
      border-radius: 999px;
      background: #2563eb;
    }}
    .summary-list {{
      border: 1px solid #e2e8f0;
      border-radius: 9px;
      padding: 14px 18px 14px 34px;
      background: #f8fafc;
    }}
    .summary-list li + li {{ margin-top: 8px; }}
    .flow-layout {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
      align-items: start;
    }}
    .flow-track {{
      display: flex;
      gap: 34px;
      overflow-x: auto;
      min-height: 360px;
      padding: 18px 14px 28px;
      position: relative;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      background:
        radial-gradient(circle at 1px 1px, rgba(148, 163, 184, 0.22) 1px, transparent 0) 0 0/22px 22px,
        linear-gradient(180deg, #ffffff, #f8fafc);
    }}
    .flow-track::before {{
      content: "";
      position: absolute;
      left: 38px;
      right: 38px;
      top: 156px;
      height: 2px;
      background: linear-gradient(90deg, rgba(37, 99, 235, 0), rgba(37, 99, 235, 0.32), rgba(15, 118, 110, 0.28), rgba(37, 99, 235, 0));
    }}
    .flow-stage {{
      position: relative;
      z-index: 1;
      flex: 0 0 292px;
      padding-top: 30px;
    }}
    .flow-stage.flow-lower {{
      margin-top: 78px;
    }}
    .flow-stage:not(:last-child)::after {{
      content: "";
      position: absolute;
      top: 93px;
      right: -36px;
      width: 36px;
      height: 2px;
      background: rgba(71, 85, 105, 0.42);
      transform: rotate(18deg);
      transform-origin: left center;
    }}
    .flow-stage.flow-lower:not(:last-child)::after {{
      top: 54px;
      transform: rotate(-18deg);
    }}
    .flow-stage:not(:last-child)::before {{
      content: "";
      position: absolute;
      top: 100px;
      right: -38px;
      width: 0;
      height: 0;
      border-top: 5px solid transparent;
      border-bottom: 5px solid transparent;
      border-left: 8px solid rgba(71, 85, 105, 0.52);
      transform: rotate(18deg);
    }}
    .flow-stage.flow-lower:not(:last-child)::before {{
      top: 47px;
      transform: rotate(-18deg);
    }}
    .flow-step-dot {{
      position: absolute;
      top: 0;
      left: 18px;
      display: grid;
      place-items: center;
      width: 38px;
      height: 38px;
      border-radius: 999px;
      background: #0f172a;
      color: #fff;
      font-size: 12px;
      font-weight: 950;
      box-shadow: 0 10px 22px rgba(15, 23, 42, 0.18);
    }}
    .flow-card {{
      min-height: 190px;
      border: 1px solid #dbe4ee;
      border-top-width: 6px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: 0 16px 34px rgba(15, 23, 42, 0.08);
      overflow: hidden;
    }}
    .flow-stage header {{
      padding: 17px 18px 12px;
      border-bottom: 1px solid #e2e8f0;
    }}
    .flow-stage header strong,
    .flow-stage header small {{ display: block; }}
    .flow-stage header strong {{ color: #0f172a; font-size: 17px; letter-spacing: 0; }}
    .flow-stage header small {{ margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 900; }}
    .flow-route {{
      margin: 0;
      padding: 13px 18px 0;
      color: #334155;
      font-size: 13px;
      line-height: 1.45;
      font-weight: 800;
    }}
    .flow-assets {{
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      padding: 12px 18px 0;
    }}
    .flow-assets span {{
      border: 1px solid #dbe4ee;
      border-radius: 999px;
      padding: 5px 9px;
      background: #f8fafc;
      color: #334155;
      font-size: 11px;
      font-weight: 900;
    }}
    .flow-status-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      padding: 12px 18px 0;
    }}
    .flow-status-pill {{
      border-radius: 999px;
      padding: 5px 9px;
      font-size: 11px;
      font-weight: 950;
    }}
    .technique-chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      padding: 12px 18px 18px;
    }}
    .technique-chips b {{
      margin-right: 2px;
      color: #64748b;
      font-size: 10px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .technique-chips span {{
      border-radius: 7px;
      padding: 5px 8px;
      background: #eef2ff;
      color: #3730a3;
      font-size: 11px;
      font-weight: 950;
    }}
    .stage-detected .flow-card {{ border-top-color: #16a34a; }}
    .stage-partial .flow-card {{ border-top-color: #f59e0b; }}
    .stage-missed .flow-card {{ border-top-color: #dc2626; }}
    .stage-blocked .flow-card {{ border-top-color: #2563eb; }}
    .stage-unchecked .flow-card {{ border-top-color: #94a3b8; }}
    .stage-baseline .flow-card {{ border-top-color: #0f766e; }}
    .legend-item.detected::before, .ttp-cell.detected, .badge.detected, .flow-status-pill.detected {{ background: #dcfce7; color: #166534; }}
    .legend-item.partial::before, .ttp-cell.partial, .badge.partial, .flow-status-pill.partial {{ background: #fef3c7; color: #92400e; }}
    .legend-item.missed::before, .ttp-cell.missed, .badge.missed, .flow-status-pill.missed {{ background: #fee2e2; color: #991b1b; }}
    .legend-item.blocked::before, .ttp-cell.blocked, .badge.blocked, .flow-status-pill.blocked {{ background: #dbeafe; color: #1d4ed8; }}
    .legend-item.unchecked::before, .ttp-cell.unchecked, .badge.unchecked, .flow-status-pill.unchecked {{ background: #e2e8f0; color: #334155; }}
    .legend-item.baseline::before, .badge.baseline, .flow-status-pill.baseline {{ background: #ccfbf1; color: #0f766e; }}
    .legend-box {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      align-items: center;
      border: 1px solid #dbe4ee;
      border-radius: 10px;
      padding: 14px;
      background: #f8fafc;
    }}
    .legend-box strong {{ color: #0f172a; font-size: 13px; margin-right: 6px; }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
      color: #475569;
      font-size: 12px;
      font-weight: 900;
    }}
    .legend-item::before {{
      content: "";
      width: 13px;
      height: 13px;
      border-radius: 4px;
      border: 1px solid rgba(15, 23, 42, 0.08);
    }}
    .explain-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .explain-grid article {{
      border: 1px solid #dbe4ee;
      border-radius: 10px;
      padding: 15px;
      background: #f8fafc;
    }}
    .explain-grid strong {{ display: block; color: #0f172a; margin-bottom: 6px; }}
    .explain-grid p {{ margin: 0; color: #64748b; font-size: 13px; }}
    .matrix-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 16px;
    }}
    .matrix-ratio {{
      min-width: 210px;
      border: 1px solid #dbe4ee;
      border-radius: 10px;
      padding: 12px 14px;
      background: #f8fafc;
      text-align: right;
    }}
    .matrix-ratio strong {{ display: block; color: #0f172a; font-size: 24px; }}
    .matrix-ratio span {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 900; }}
    .mitre-board {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(154px, 1fr));
      gap: 10px;
    }}
    .mitre-column {{
      border: 1px solid #dbe4ee;
      border-radius: 10px;
      background: #fff;
      overflow: hidden;
    }}
    .mitre-column h3 {{
      margin: 0;
      padding: 10px 11px;
      background: #f1f5f9;
      color: #334155;
      font-size: 12px;
      line-height: 1.25;
    }}
    .ttp-cell {{
      display: block;
      margin: 8px;
      border-radius: 8px;
      padding: 9px 10px;
      border: 1px solid rgba(15, 23, 42, 0.08);
    }}
    .ttp-cell strong, .ttp-cell small {{ display: block; }}
    .ttp-cell strong {{ font-size: 13px; }}
    .ttp-cell small {{ margin-top: 4px; font-size: 10px; font-weight: 900; }}
    .impact-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .impact-bar {{ display: grid; grid-template-columns: minmax(92px, 1fr) 42px; gap: 9px; align-items: center; min-width: 160px; }}
    .impact-bar i {{ height: 9px; overflow: hidden; border-radius: 999px; background: #e2e8f0; }}
    .impact-bar i b {{ display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #22c55e, #f59e0b 54%, #ef4444); }}
    .impact-bar strong {{ color: #0f172a; font-size: 12px; font-weight: 900; text-align: right; }}
    .tactic-grid {{ display: grid; gap: 16px; }}
    .tactic-chart {{
      border: 1px solid #dbe4ee;
      border-radius: 10px;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
      overflow: hidden;
      padding: 18px 18px 14px;
    }}
    .tactic-chart h3 {{ margin: 0 0 12px; color: #0f172a; font-size: 16px; text-align: center; }}
    .chart-body {{ display: grid; grid-template-columns: 44px minmax(0, 1fr); gap: 10px; align-items: start; }}
    .chart-axis {{
      display: grid;
      grid-template-rows: repeat(10, 16px);
      height: 160px;
      padding-top: 1px;
      color: #64748b;
      font-size: 10px;
      font-weight: 800;
      text-align: right;
    }}
    .stacked-chart {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(56px, 1fr));
      align-items: end;
      column-gap: 9px;
      min-height: 214px;
      padding: 8px 0 0;
      background-image: linear-gradient(to top, #dbeafe 1px, transparent 1px);
      background-size: 100% 16px;
      border-bottom: 2px solid #cbd5e1;
    }}
    .stacked-bar-item {{ display: grid; grid-template-rows: 160px 18px minmax(34px, auto); justify-items: center; gap: 5px; min-width: 0; }}
    .stacked-bar {{
      align-self: end;
      display: flex;
      flex-direction: column;
      justify-content: flex-end;
      width: 36px;
      height: 160px;
      overflow: hidden;
      background: #e2e8f0;
      border: 1px solid #dbe4ee;
      border-radius: 3px 3px 0 0;
    }}
    .stacked-bar i {{ display: block; width: 100%; min-height: 0; }}
    .stacked-bar .covered.log {{ background: #f97316; }}
    .stacked-bar .covered.alert {{ background: #0ea5e9; }}
    .stacked-bar .not-covered {{ background: #334155; }}
    .stacked-bar-item strong {{ color: #334155; font-size: 11px; }}
    .stacked-bar-item span {{ color: #334155; font-size: 10px; font-weight: 900; line-height: 1.15; text-align: center; word-break: keep-all; }}
    .chart-legend {{ display: flex; justify-content: center; gap: 16px; margin-top: 10px; color: #334155; font-size: 11px; font-weight: 900; }}
    .chart-legend span::before {{ content: ""; display: inline-block; width: 8px; height: 8px; margin-right: 5px; border-radius: 2px; vertical-align: -1px; }}
    .chart-legend .log-dot::before {{ background: #f97316; }}
    .chart-legend .alert-dot::before {{ background: #0ea5e9; }}
    .chart-legend .miss-dot::before {{ background: #334155; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e2e8f0; padding: 12px 13px; text-align: left; vertical-align: top; }}
    th {{ color: #475569; background: #f1f5f9; font-size: 12px; position: sticky; top: 0; z-index: 1; }}
    th span, th small {{ display: block; }}
    th span {{ color: #0f172a; font-size: 12px; font-weight: 900; }}
    th small {{ margin-top: 3px; color: #64748b; font-size: 10px; font-weight: 800; }}
    td {{ background: #fff; }}
    tbody tr:nth-child(even) td {{ background: #fbfdff; }}
    tbody tr:hover td {{ background: #f8fafc; }}
    tbody tr.row-good td:first-child {{ border-left: 4px solid #16a34a; }}
    tbody tr.row-warn td:first-child {{ border-left: 4px solid #d97706; }}
    tbody tr.row-critical td:first-child {{ border-left: 4px solid #dc2626; }}
    tbody tr.row-blocked td:first-child {{ border-left: 4px solid #64748b; }}
    .table-wrap {{ overflow-x: auto; border: 1px solid #dbe4ee; border-radius: 10px; background: #fff; }}
    .report-shell {{ display: grid; grid-template-columns: 210px minmax(0, 1fr); gap: 18px; margin-top: 18px; align-items: start; }}
    .report-nav {{
      position: sticky;
      top: 18px;
      display: grid;
      gap: 7px;
      padding: 13px;
      border: 1px solid #d9e2ec;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: 0 18px 44px rgba(15, 23, 42, 0.07);
    }}
    .report-nav span {{ padding: 4px 6px 8px; color: #64748b; font-size: 11px; font-weight: 900; text-transform: uppercase; }}
    .report-nav button {{
      width: 100%;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 12px 13px;
      background: transparent;
      color: #334155;
      font: inherit;
      font-size: 13px;
      font-weight: 900;
      text-align: left;
      cursor: pointer;
    }}
    .report-nav button:hover,
    .report-nav button.active {{ border-color: #2563eb; background: #0f172a; color: #f8fafc; }}
    .report-content {{ min-width: 0; }}
    .report-block {{ display: none; margin-top: 0; }}
    .report-block.active {{ display: block; }}
    .report-block > .panel:first-child {{ margin-top: 0; }}
    .coverage-table {{ min-width: 1450px; }}
    .asset-control-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .gap-analysis-table {{ min-width: 1180px; }}
    .gap-analysis-table td:first-child small {{ display: block; margin-top: 4px; color: #64748b; font-size: 11px; font-weight: 800; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }}
    .badge.good {{ color: #166534; background: #dcfce7; }}
    .badge.warn {{ color: #92400e; background: #fef3c7; }}
    .badge.critical {{ color: #991b1b; background: #fee2e2; }}
    .badge.detected {{ color: #166534; background: #dcfce7; }}
    .badge.partial {{ color: #92400e; background: #fef3c7; }}
    .badge.missed {{ color: #991b1b; background: #fee2e2; }}
    .badge.blocked {{ color: #1d4ed8; background: #dbeafe; }}
    .badge.baseline {{ color: #0f766e; background: #ccfbf1; }}
    .badge.unchecked,
    .badge.neutral {{ color: #334155; background: #e2e8f0; }}
    .empty {{ color: #64748b; text-align: center; }}
    @media (max-width: 820px) {{
      body {{ padding: 16px; }}
      header {{ grid-template-columns: 1fr; padding: 24px; }}
      h1 {{ font-size: 28px; }}
      .report-shell {{ grid-template-columns: 1fr; }}
      .report-nav {{ position: static; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .flow-layout {{ grid-template-columns: 1fr; }}
      .explain-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .matrix-head {{ display: grid; }}
      .matrix-ratio {{ text-align: left; }}
      .chart-body {{ grid-template-columns: 36px minmax(0, 1fr); }}
      .stacked-chart {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 520px) {{
      body {{ padding: 12px; }}
      header {{ padding: 22px; }}
      h1 {{ font-size: 26px; line-height: 1.16; }}
      section.panel {{ padding: 18px; }}
      .grid {{ grid-template-columns: 1fr; }}
      .explain-grid {{ grid-template-columns: 1fr; }}
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
    <div class="report-shell">
      <aside class="report-nav" aria-label="Report sections">
        <span>Report View</span>
        <button type="button" class="active" data-target="summary">한눈에 보기</button>
        <button type="button" data-target="detection">탐지 결과</button>
        <button type="button" data-target="improvement">개선 방향</button>
        <button type="button" data-target="appendix">부록</button>
      </aside>
      <div class="report-content">
        <div class="report-block active" data-section="summary">
          <section class="panel">
            <h2>공격 흐름 / Flow</h2>
            <p class="section-desc">실행 Technique의 흐름을 먼저 보여주고, 색상은 탐지 결과와 실행 상태의 의미에만 사용합니다.</p>
            <div class="flow-layout">
              <div class="flow-track">{flow_html}</div>
              <aside class="legend-box">
                <strong>색상 의미</strong>
                {flow_legend_html}
              </aside>
            </div>
          </section>
          <section class="panel">
            <h2>핵심 지표</h2>
            <p class="section-desc">탐지 체계가 실제 로그와 알림까지 이어졌는지 요약한 값입니다.</p>
            <div class="grid">{metrics_html}</div>
          </section>
          <section class="panel">
            <h2>지표 설명</h2>
            <p class="section-desc">정상 데이터와 공격 데이터를 분리하고, 로그 수집과 알림 발생을 따로 판단합니다.</p>
            <div class="explain-grid">{explanation_cards_html}</div>
            <ul class="summary-list">{meaning_html}</ul>
          </section>
          <section class="panel">
            <h2>커버리지 결과</h2>
            <p class="section-desc">MITRE tactic 단위로 로그 수집 여부와 실제 알림 발생 여부를 분리해 보여줍니다.</p>
            <div class="tactic-grid">{tactic_chart_html}</div>
          </section>
          <section class="panel">
            <div class="matrix-head">
              <div>
                <h2>MITRE ATT&CK / TTP 매트릭스</h2>
                <p class="section-desc">이번 실행에 포함된 Technique만 tactic별로 묶고, 수행 결과를 색상으로 표시합니다.</p>
              </div>
              {matrix_ratio_html}
            </div>
            <div class="mitre-board">{mitre_matrix_html}</div>
          </section>
        </div>
        <div class="report-block" data-section="detection">
          <section class="panel">
            <h2>미탐 원인 및 필요 센서</h2>
            <p class="section-desc">미탐, 부분탐지, 검증 미완료 항목만 모아 왜 안 잡혔는지와 어떤 센서가 필요한지 보여줍니다.</p>
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
            <p class="section-desc">Technique별로 기대 로그, 탐지 룰, 탐지 결과, 영향도, 개선 방향만 남긴 발표용 결과표입니다.</p>
            <div class="table-wrap">
              <table class="coverage-table">
                <thead>
                  <tr>
                    {th("테크닉 ID", "Technique ID")}
                    {th("공격명", "Attack Name")}
                    {th("대상 자산", "Target Asset")}
                    {th("기대 로그", "Expected Log")}
                    {th("탐지 룰", "Detection Rule")}
                    {th("탐지 결과", "Detection Result")}
                    {th("커버리지 상태", "Coverage Status")}
                    {th("시스템 영향도", "System Impact")}
                    {th("위험도", "Risk Level")}
                    {th("권장 센서", "Recommended Sensor")}
                    {th("개선 계획", "Improvement Plan")}
                  </tr>
                </thead>
                <tbody>{coverage_rows}</tbody>
              </table>
            </div>
          </section>
        </div>
        <div class="report-block" data-section="improvement">
          <section class="panel">
            <h2>자산/보안 솔루션 매핑</h2>
            <p class="section-desc">현재 환경의 자산, 보안 솔루션, 로그 소스가 어떤 공격 흐름을 볼 수 있는지 요약합니다.</p>
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
        </div>
        <div class="report-block" data-section="appendix">
          <section class="panel">
            <h2>원본 파일 링크</h2>
            <p class="section-desc">아래 파일들은 사람이 바로 읽기보다 검증, 재현, 스프레드시트 분석, ATT&CK Navigator 업로드를 위한 원본 자료입니다.</p>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    {th("자료", "Artifact")}
                    {th("내용", "Description")}
                    {th("링크", "Link")}
                  </tr>
                </thead>
                <tbody>{appendix_rows}</tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  </main>
  <script>
    const reportButtons = document.querySelectorAll(".report-nav button");
    const reportBlocks = document.querySelectorAll(".report-block");
    function activateReportSection(id) {{
      reportButtons.forEach((button) => button.classList.toggle("active", button.dataset.target === id));
      reportBlocks.forEach((block) => block.classList.toggle("active", block.dataset.section === id));
    }}
    reportButtons.forEach((button) => {{
      button.addEventListener("click", () => activateReportSection(button.dataset.target));
    }});
  </script>
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

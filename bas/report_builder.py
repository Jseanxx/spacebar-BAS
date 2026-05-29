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
REPORT_VERSION = "0.1"
GENERATOR_VERSION = "sb-ad-report-builder-0.1"


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

    if execution_status == "blocked":
        detection_status = "blocked"
    elif execution_status == "failed":
        detection_status = "execution_failed"
    elif simulated:
        detection_status = "not_checked"
    elif not source_checked and not alert_checked:
        detection_status = "not_checked"
    elif source_matched and alert_matched:
        detection_status = "detected"
    elif source_matched and not alert_matched:
        detection_status = "logged_only"
    elif not source_matched and alert_matched:
        detection_status = "alert_without_source_sample"
    else:
        detection_status = "missed"

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
        parts.append(", ".join(requires))
    if safety_gates:
        parts.append("Safety gates: " + ", ".join(safety_gates))

    return "; ".join(parts) if parts else "-"


def expected_log(step):
    requires = set(normalize_list(step.get("requires")))
    behavior = step_behavior(step) or ""

    if behavior in ("kerberoasting_tgs_request",):
        return "Windows Security 4769 Kerberos TGS request"
    if behavior in ("dcsync_replication",):
        return "Windows Security 4662 / directory replication access"
    if behavior in ("valid_domain_account_remote_logon", "winrm_remote_execution"):
        return "Windows Security 4624/4688 and Sysmon process telemetry"
    if behavior in ("service_execution",):
        return "Service creation/execution event and Sysmon process telemetry"
    if behavior in ("lsass_memory_dump", "rundll32_comsvcs_proxy"):
        return "Sysmon Event ID 10 process access and Event ID 11 file creation"
    if behavior in ("non_application_tcp_connection", "exfiltration_over_c2"):
        return "Sysmon Event ID 3 network connection"
    if behavior in ("ingress_tool_transfer", "local_data_staging", "masquerading_legitimate_name", "archive_collected_data", "ntds_dump"):
        return "Sysmon file/process telemetry and Windows Security audit events"
    if "powershell_logging" in requires or "powershell" in requires:
        return "PowerShell 4104 and Sysmon process telemetry"
    if "windows_security" in requires or "active_directory" in requires:
        return "Windows Security Log and Sysmon process telemetry"
    if "network" in requires:
        return "Network connection telemetry"
    if "sysmon" in requires:
        return "Sysmon process/file/network telemetry"
    return "Source telemetry from the mapped log source"


def risk_level(step):
    return str(step.get("risk") or "medium").lower()


def system_impact(step):
    risk = risk_level(step)
    behavior = step_behavior(step) or ""
    safety_gates = set(normalize_list(get_step_params(step).get("safety_gates")))
    high_impact_keywords = ("dcsync", "golden_ticket", "ntds", "lsass", "service_execution")

    if any(keyword in behavior for keyword in high_impact_keywords) or "BAS_ENABLE_DOMAIN_COMPROMISE_TESTS" in safety_gates:
        return "High - test environment only"
    if risk == "high" or safety_gates:
        return "Medium - approval recommended"
    if risk == "critical":
        return "High - test environment only"
    return "Low - safe validation"


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
    return {
        "detected": "Covered",
        "logged_only": "Partial",
        "alert_without_source_sample": "Partial",
        "missed": "Gap",
        "not_checked": "Not checked",
        "blocked": "Blocked",
        "execution_failed": "Execution failed",
    }.get(detection_status, "Review")


def detection_result_label(detection_status):
    return {
        "detected": "Detected",
        "logged_only": "Logged only",
        "alert_without_source_sample": "Alert only",
        "missed": "Missed",
        "not_checked": "Not checked",
        "blocked": "Blocked",
        "execution_failed": "Execution failed",
    }.get(detection_status, detection_status or "-")


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
    reason = recommendation.get("reason") or ""
    return f"{action}: {reason}" if reason else action


def build_dashboard_fields(step, classification, recommendation, target):
    behavior = step_behavior(step)
    source_query = (step.get("elk_check") or {}).get("query")
    alert_query = get_alert_check(step.get("elk_check") or {}).get("query")

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
        "risk_level": risk_level(step).title(),
        "recommended_sensor": recommended_sensor(step),
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
        "risk_level": dashboard_fields["risk_level"],
        "recommended_sensor": dashboard_fields["recommended_sensor"],
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
    top_gaps = backlog[:5]
    lines = [
        f"# {report.get('campaign_name') or report.get('campaign_id')} BAS Summary",
        "",
        "## Key Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Final score | {summary['final_score']}/100 |",
        f"| Real attack steps | {summary['real_attack_steps']} |",
        f"| Detection coverage | {summary['detection_coverage'] * 100:.0f}% |",
        f"| Telemetry coverage | {summary['telemetry_coverage'] * 100:.0f}% |",
        f"| Alert coverage | {summary['alert_coverage'] * 100:.0f}% |",
        f"| Logged only | {summary['logged_only_count']} |",
        f"| Missed | {summary['missed_count']} |",
        f"| Not checked | {summary['not_checked_count']} |",
        "",
        "## Top Remediation Backlog",
        "",
    ]

    if top_gaps:
        for item in top_gaps:
            lines.append(
                f"- {item['priority']} {item['technique_id']} step {item['order']}: "
                f"{item['gap_type']} -> {item['recommended_action']}"
            )
    else:
        lines.append("- No remediation backlog item was generated.")

    lines.append("")
    return "\n".join(lines)


def render_summary_html(report):
    summary = report["summary"]
    backlog = report.get("backlog", [])
    score = int(summary.get("final_score", 0))
    score_label = "Good" if score >= 80 else "Needs improvement" if score >= 50 else "High priority"
    score_class = "good" if score >= 80 else "warn" if score >= 50 else "critical"

    def text(value):
        return escape(str(value if value is not None else "-"))

    def pct(value):
        return f"{float(value or 0) * 100:.0f}%"

    metrics = [
        ("Readiness score", f"{score}/100"),
        ("Attack techniques", summary.get("attack_steps", 0)),
        ("Detected", summary.get("detected_count", 0)),
        ("Logged only", summary.get("logged_only_count", 0)),
        ("Missed", summary.get("missed_count", 0)),
        ("Not checked", summary.get("not_checked_count", 0)),
        ("Telemetry coverage", pct(summary.get("telemetry_coverage"))),
        ("Alert coverage", pct(summary.get("alert_coverage"))),
    ]
    metrics_html = "\n".join(
        f"<section class=\"metric\"><span>{text(label)}</span><strong>{text(value)}</strong></section>"
        for label, value in metrics
    )

    if backlog:
        backlog_rows = "\n".join(
            "<tr>"
            f"<td><strong>{text(item.get('priority'))}</strong></td>"
            f"<td>{text(item.get('technique_id'))}</td>"
            f"<td>{text(item.get('gap_type'))}</td>"
            f"<td>{text(item.get('recommended_action'))}</td>"
            f"<td>{text(item.get('verification_method'))}</td>"
            "</tr>"
            for item in backlog[:8]
        )
    else:
        backlog_rows = "<tr><td colspan=\"5\" class=\"empty\">No remediation backlog item was generated.</td></tr>"

    meaning_items = []
    if summary.get("missed_count", 0) or summary.get("critical_gaps", 0):
        meaning_items.append("Missed or high-risk gaps should be handled before this path is treated as validated.")
    if summary.get("logged_only_count", 0):
        meaning_items.append("Some techniques produced telemetry but no matching alert, so detection rule tuning is recommended.")
    if summary.get("not_checked_count", 0):
        meaning_items.append("Some checks were inconclusive. Review ELK query execution, agent status, or simulation mode.")
    if not meaning_items:
        meaning_items.append("No major detection backlog was generated from this run.")
    meaning_html = "\n".join(f"<li>{text(item)}</li>" for item in meaning_items)
    coverage_rows = "\n".join(
        "<tr>"
        f"<td>{text(step.get('technique_id'))}</td>"
        f"<td>{text(step.get('attack_name') or step.get('name'))}</td>"
        f"<td>{text(step.get('target_asset'))}</td>"
        f"<td>{text(step.get('required_condition'))}</td>"
        f"<td>{text(step.get('expected_log'))}</td>"
        f"<td>{text(step.get('detection_rule'))}</td>"
        f"<td>{text(step.get('detection_result'))}</td>"
        f"<td>{text(step.get('coverage_status'))}</td>"
        f"<td>{text(step.get('system_impact'))}</td>"
        f"<td>{text(step.get('risk_level'))}</td>"
        f"<td>{text(step.get('recommended_sensor'))}</td>"
        f"<td>{text(step.get('improvement_plan'))}</td>"
        "</tr>"
        for step in report.get("steps", [])
        if step.get("technique_id")
    )
    if not coverage_rows:
        coverage_rows = "<tr><td colspan=\"12\" class=\"empty\">No BAS coverage result was generated.</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{text(report.get('campaign_name') or report.get('campaign_id'))} BAS Summary</title>
  <style>
    :root {{
      color: #101820;
      background: #eef3f7;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    body {{ margin: 0; padding: 32px; }}
    main {{ max-width: 1120px; margin: 0 auto; }}
    header, section.panel {{
      border: 1px solid #d7e0ea;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
    }}
    header {{ display: grid; grid-template-columns: minmax(0, 1fr) 220px; gap: 24px; padding: 30px; }}
    h1 {{ margin: 0 0 12px; font-size: 34px; line-height: 1.08; letter-spacing: 0; }}
    h2 {{ margin: 0 0 16px; font-size: 19px; }}
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
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e2e8f0; padding: 11px; text-align: left; vertical-align: top; }}
    th {{ color: #475569; background: #f8fafc; font-size: 12px; }}
    .table-wrap {{ overflow-x: auto; }}
    .coverage-table {{ min-width: 1480px; }}
    .empty {{ color: #64748b; text-align: center; }}
    @media (max-width: 820px) {{
      body {{ padding: 16px; }}
      header {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>{text(report.get('campaign_name') or report.get('campaign_id'))} BAS Executive Summary</h1>
        <p>This report summarizes detection readiness, telemetry evidence, alert coverage, and the next remediation actions from the BAS run.</p>
        <div class="meta">
          <span>Report {text(report.get('report_id'))}</span>
          <span>Target {text(report.get('campaign_id'))}</span>
          <span>Generated {text(report.get('generated_at'))}</span>
        </div>
      </div>
      <div class="score {score_class}">
        <strong>{score}</strong>
        <span>{text(score_label)}</span>
      </div>
    </header>
    <section class="panel">
      <h2>Key Metrics</h2>
      <div class="grid">{metrics_html}</div>
    </section>
    <section class="panel">
      <h2>What This Means</h2>
      <ul>{meaning_html}</ul>
    </section>
    <section class="panel">
      <h2>BAS Coverage Result Table</h2>
      <div class="table-wrap">
        <table class="coverage-table">
          <thead>
            <tr>
              <th>Technique ID</th><th>Attack Name</th><th>Target Asset</th><th>Required Condition</th>
              <th>Expected Log</th><th>Detection Rule</th><th>Detection Result</th><th>Coverage Status</th>
              <th>System Impact</th><th>Risk Level</th><th>Recommended Sensor</th><th>Improvement Plan</th>
            </tr>
          </thead>
          <tbody>{coverage_rows}</tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>Recommended Remediation</h2>
      <table>
        <thead>
          <tr><th>Priority</th><th>Technique</th><th>Gap</th><th>Action</th><th>Verify</th></tr>
        </thead>
        <tbody>{backlog_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def render_technical_markdown(report):
    lines = [
        f"# {report.get('campaign_name') or report.get('campaign_id')} Technical Detection Report",
        "",
        "## BAS Coverage Result Table",
        "",
        "| Technique ID | Attack Name | Target Asset | Required Condition | Expected Log | Detection Rule | Detection Result | Coverage Status | System Impact | Risk Level | Recommended Sensor | Improvement Plan |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for step in report.get("steps", []):
        lines.append(
            f"| {step.get('technique_id') or '-'} | {step.get('attack_name') or step.get('name') or '-'} | "
            f"{step.get('target_asset') or '-'} | {step.get('required_condition') or '-'} | "
            f"{step.get('expected_log') or '-'} | {step.get('detection_rule') or '-'} | "
            f"{step.get('detection_result') or step.get('detection_status') or '-'} | "
            f"{step.get('coverage_status') or '-'} | {step.get('system_impact') or '-'} | "
            f"{step.get('risk_level') or step.get('risk') or '-'} | {step.get('recommended_sensor') or '-'} | "
            f"{step.get('improvement_plan') or step.get('recommendation', {}).get('action') or '-'} |"
        )

    lines.extend([
        "",
        "## Step Diagnostics",
        "",
        "| Order | Technique | Execution | Source Log | Alert | Detection | Gap | Action |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])

    for step in report.get("steps", []):
        action = step.get("recommendation", {}).get("action") or ""
        lines.append(
            f"| {step.get('order')} | {step.get('technique_id') or '-'} | "
            f"{step.get('execution_status')} | {step.get('source_status')} | "
            f"{step.get('alert_status')} | {step.get('detection_status')} | "
            f"{step.get('gap_type') or '-'} | {action} |"
        )

    lines.extend(["", "## Query Evidence", ""])
    for step in report.get("steps", []):
        if not step.get("technique_id"):
            continue
        lines.extend([
            f"### Step {step.get('order')} {step.get('technique_id')} {step.get('name')}",
            "",
            f"- Detection status: {step.get('detection_status')}",
            f"- Source events: {step.get('source_event_count')}",
            f"- Alerts: {step.get('alert_count')}",
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
        "risk_level",
        "recommended_sensor",
        "improvement_plan",
    ]

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for step in steps:
            if not step.get("technique_id"):
                continue
            writer.writerow({field: step.get(field, "") for field in fields})


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

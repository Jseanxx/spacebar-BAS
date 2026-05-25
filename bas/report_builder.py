from __future__ import annotations

import csv
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from bas.loader import load_campaign


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


def classify_step(step):
    classification = classify_detection_status(step)
    elk_check = step.get("elk_check") or {}
    alert_check = get_alert_check(elk_check)
    recommendation = recommendation_for(step, classification)

    return {
        "order": step.get("order"),
        "phase": step.get("phase"),
        "name": step.get("name"),
        "module": step.get("module"),
        "technique_id": step.get("technique_id"),
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
            "source": elk_check.get("query"),
            "alert": alert_check.get("query"),
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
    steps = [classify_step(step) for step in normalize_source_steps(source)]
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
        "technical": base.with_suffix(".technical.md"),
        "backlog": base.with_suffix(".detection-backlog.csv"),
        "navigator": base.with_suffix(".attack-navigator.json"),
    }

    write_json(artifacts["json"], {key: value for key, value in report.items() if key != "artifact_paths"})
    artifacts["summary"].write_text(render_summary_markdown(report), encoding="utf-8")
    artifacts["technical"].write_text(render_technical_markdown(report), encoding="utf-8")
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


def render_technical_markdown(report):
    lines = [
        f"# {report.get('campaign_name') or report.get('campaign_id')} Technical Detection Report",
        "",
        "## Step Results",
        "",
        "| Order | Technique | Execution | Source Log | Alert | Detection | Gap | Action |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

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

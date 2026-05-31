import json
import os
from datetime import datetime, timezone
from urllib import error, request

from modules.attack import sb_ad_technique


DEFAULT_SOURCE_CAMPAIGN_ID = "SB-07"
DEFAULT_BAS_CAMPAIGN_ID = "SB-AV"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def first_scalar(*values):
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def resolve_agent_role(params):
    commands = params.get("commands") or []
    for command in commands:
        role = command.get("agent_role")
        if role:
            return role
    return params.get("agent_role") or os.environ.get("BAS_AGENT_ROLE") or "unknown"


def resolve_host_context(target, params):
    context = sb_ad_technique.flatten_context(target, params)
    agent_role = resolve_agent_role(params)
    hosts = target.get("hosts") or {}

    hostname_by_role = {
        "bastion": hosts.get("bastion"),
        "pms": hosts.get("pms"),
        "win01": hosts.get("win01"),
        "dc01": hosts.get("dc01"),
        "soc01": hosts.get("soc01"),
    }
    ip_by_role = {
        "bastion": hosts.get("bastion_private_ip"),
        "pms": hosts.get("pms_private_ip"),
        "win01": hosts.get("win01_private_ip"),
        "dc01": hosts.get("dc01_private_ip"),
        "soc01": hosts.get("soc01_private_ip"),
    }

    return {
        "context": context,
        "agent_role": agent_role,
        "hostname": first_scalar(hostname_by_role.get(agent_role), params.get("execution_host"), agent_role),
        "host_ip": first_scalar(ip_by_role.get(agent_role), params.get("source_ip")),
    }


def infer_stage(action, params):
    if params.get("hanguel_stage"):
        return params.get("hanguel_stage")
    if action in ("pms_patch_downloaded", "pms_patch_executed"):
        return "supply_chain" if action == "pms_patch_downloaded" else "execution"
    if action in ("system_user_context", "system_ipconfig", "domain_controller_discovery", "dc_srv_dns_lookup", "dc_port_probe_445", "dc_port_probe_5985"):
        return "discovery"
    if action in ("dc_cred_xml_discovered", "dc_cred_xml_imported"):
        return "credential_access"
    if action in ("dc_winrm_whoami", "dc_c_admin_share_access"):
        return "lateral_movement"
    if action in ("loader_execution_log_found", "loader_file_artifact_found", "loader_powershell_event_found", "manual_mapping_inferred_marker"):
        return "defense_evasion"
    if action == "sysmon_lsass_process_access":
        return "credential_access"
    if action in ("auth_material_reuse_validation", "pass_the_hash_attempt_emulated"):
        return "lateral_movement"
    return params.get("phase") or "telemetry"


def infer_risk_score(action, params):
    if params.get("hanguel_risk_score") is not None:
        return params.get("hanguel_risk_score")
    if action in ("dc_winrm_whoami", "dc_c_admin_share_access"):
        return 85
    if action in ("dc_cred_xml_imported", "pms_patch_executed"):
        return 80
    if action in ("sysmon_lsass_process_access", "pass_the_hash_attempt_emulated"):
        return 85
    if action in ("loader_execution_log_found", "loader_file_artifact_found", "loader_powershell_event_found", "manual_mapping_inferred_marker", "auth_material_reuse_validation"):
        return 75
    if action in ("dc_cred_xml_discovered",):
        return 70
    if action == "pms_patch_downloaded":
        return 55
    if action in ("domain_controller_discovery", "dc_srv_dns_lookup", "dc_port_probe_445", "dc_port_probe_5985"):
        return 45
    if action in ("system_user_context", "system_ipconfig"):
        return 35

    risk = str(params.get("risk") or "").lower()
    return {
        "critical": 90,
        "high": 75,
        "medium": 55,
        "low": 35,
    }.get(risk, 30)


def infer_classification(action, params):
    if params.get("hanguel_classification"):
        return params.get("hanguel_classification")
    if action and action.startswith("normal_"):
        return "normal"
    if action in (
        "pms_patch_executed",
        "dc_cred_xml_imported",
        "dc_winrm_whoami",
        "dc_c_admin_share_access",
        "loader_execution_log_found",
        "loader_file_artifact_found",
        "loader_powershell_event_found",
        "manual_mapping_inferred_marker",
        "sysmon_lsass_process_access",
        "auth_material_reuse_validation",
        "pass_the_hash_attempt_emulated",
    ):
        return "attack"
    return "suspicious"


def severity_from_score(score):
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 30
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "informational"


def build_technique(params):
    technique_id = params.get("technique_id")
    if not technique_id:
        return []
    return [{
        "id": technique_id,
        "name": params.get("technique_name") or params.get("name") or params.get("behavior"),
    }]


def build_hanguel_event(target, params, command_result=None, action=None):
    host_context = resolve_host_context(target, params)
    context = host_context["context"]
    operation_id = params.get("_operation_id")
    step_order = params.get("_step_order") or params.get("scenario_order")
    marker = sb_ad_technique.get_execution_marker(context)
    action = action or params.get("hanguel_event_action") or params.get("behavior")
    classification = infer_classification(action, params)
    risk_score = infer_risk_score(action, params)
    stage = infer_stage(action, params)
    campaign_id = params.get("source_campaign_id") or DEFAULT_SOURCE_CAMPAIGN_ID
    campaign_name = params.get("source_campaign_name") or "OZZY PMS Chain"
    log_source_name = params.get("hanguel_log_source_name") or "SB-07 BAS Emulation Event"

    event = {
        "@timestamp": utc_now(),
        "observer": {
            "name": host_context["hostname"],
            "type": "sb07-emulation",
        },
        "campaign": {
            "id": campaign_id,
            "name": campaign_name,
        },
        "operation": {
            "id": operation_id,
        },
        "bas": {
            "campaign_id": params.get("bas_campaign_id") or DEFAULT_BAS_CAMPAIGN_ID,
            "operation_id": operation_id,
            "step_order": step_order,
            "behavior": params.get("behavior"),
            "marker": marker,
        },
        "labels": {
            "spacebar_campaign": params.get("bas_campaign_id") or DEFAULT_BAS_CAMPAIGN_ID,
            "spacebar_operation": operation_id,
            "spacebar_step": str(step_order) if step_order is not None else None,
            "spacebar_marker": marker,
        },
        "run": {
            "id": operation_id or marker,
        },
        "spacebar": {
            "bas": {
                "campaign_id": params.get("bas_campaign_id") or DEFAULT_BAS_CAMPAIGN_ID,
                "operation_id": operation_id,
                "step_order": step_order,
                "behavior": params.get("behavior"),
                "marker": marker,
            }
        },
        "log": {
            "id": params.get("hanguel_log_id") or "SPACEBAR-BAS",
            "source": {
                "name": log_source_name,
            },
        },
        "event": {
            "module": "hanguel_ad",
            "kind": "event" if classification == "normal" else "alert",
            "category": "host",
            "type": ["info"],
            "action": action,
            "dataset": "hanguel.ad_agent",
            "severity": severity_from_score(risk_score),
        },
        "host": {
            "name": host_context["hostname"],
            "domain": (target.get("ad") or {}).get("domain"),
            "ip": [host_context["host_ip"]] if host_context["host_ip"] else [],
        },
        "agent": {
            "type": "spacebar-bas-agent",
            "role": host_context["agent_role"],
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": build_technique(params),
        },
        "hanguel": {
            "classification": classification,
            "risk_score": risk_score,
            "detection_stage": stage,
            "source": "sb07-emulation",
            "log_source_id": params.get("hanguel_log_id") or "SPACEBAR-BAS",
            "test_runner": True,
        },
        "data": {
            "simulation": bool(params.get("simulation", True)),
            "operation_id": operation_id,
            "step_order": step_order,
            "spacebar_marker": marker,
            "password_logged": False,
        },
        "message": params.get("description") or f"SB-AV BAS event: {action}",
    }

    if command_result:
        stdout_preview = str(command_result.get("stdout") or "")[:3500]
        stderr_preview = str(command_result.get("stderr") or "")[:1500]
        event["process"] = {
            "command_line": command_result.get("command"),
            "exit_code": command_result.get("returncode"),
        }
        event["data"].update({
            "command": command_result.get("command"),
            "exit_code": command_result.get("returncode"),
            "output": stdout_preview,
        })
        if stderr_preview:
            event["data"]["stderr"] = stderr_preview
        if stdout_preview:
            event["bas"]["stdout_preview"] = stdout_preview[:500]
        if stderr_preview:
            event["bas"]["stderr_preview"] = stderr_preview[:500]

    return event


def resolve_logstash_url(target):
    return (
        os.environ.get("BAS_AV_LOGSTASH_URL")
        or (target.get("operation_defaults") or {}).get("logstash_http_url")
    )


def post_event(url, event):
    payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        url=url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=int(os.environ.get("BAS_AV_EVENT_TIMEOUT", "5") or "5")) as response:
        body = response.read().decode("utf-8", errors="replace")
        return {
            "ok": 200 <= response.status < 300,
            "status": response.status,
            "body": body[:500],
        }


def emit_hanguel_events(target, params, base_result):
    url = resolve_logstash_url(target)
    actions = params.get("hanguel_event_actions") or [params.get("hanguel_event_action") or params.get("behavior")]
    command_results = base_result.get("command_results") or []
    command_result = command_results[0] if command_results else None
    events = [
        build_hanguel_event(target, params, command_result=command_result, action=action)
        for action in actions
        if action
    ]

    if not url:
        return {
            "configured": False,
            "message": "BAS_AV_LOGSTASH_URL is not configured.",
            "would_emit": events,
        }

    posted = []
    for event in events:
        try:
            posted.append({
                "event_action": event.get("event", {}).get("action"),
                **post_event(url, event),
            })
        except error.URLError as exc:
            posted.append({
                "event_action": event.get("event", {}).get("action"),
                "ok": False,
                "error": str(exc),
            })
        except Exception as exc:
            posted.append({
                "event_action": event.get("event", {}).get("action"),
                "ok": False,
                "error": str(exc),
            })

    return {
        "configured": True,
        "url": url,
        "posted": posted,
    }


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "sb_av_hanguel_chain")
    execution_mode = params.get("_execution_mode", "simulation")

    if params.get("deferred"):
        return {
            "behavior": behavior,
            "evidence_key": behavior,
            "technique_id": params.get("technique_id"),
            "description": params.get("description"),
            "execution_host": params.get("execution_host"),
            "risk": params.get("risk", "high"),
            "status": "blocked",
            "execution_mode": execution_mode,
            "deferred": True,
            "safety_gates": params.get("safety_gates", []),
            "message": "SB-AV high-risk technique is deferred until gate, cleanup, and rollback are finalized.",
        }

    base_result = sb_ad_technique.run(target=target, params=params)
    base_result["campaign_family"] = "SB-AV"
    base_result["message"] = base_result.get("message", "").replace("SB-AD", "SB-AV")
    base_result["expected_log"] = {
        "index": (target.get("elk") or {}).get("index"),
        "alert_index": (target.get("elk") or {}).get("alert_index"),
        "log_id": params.get("hanguel_log_id"),
        "event_action": params.get("hanguel_event_action"),
        "event_actions": params.get("hanguel_event_actions"),
        "rule_ids": params.get("expected_rule_ids", []),
    }

    if execution_mode != "real":
        base_result["hanguel_event_emission"] = {
            "configured": False,
            "message": "Simulation mode. Event was not posted.",
            "would_emit": [
                build_hanguel_event(target, params, action=action)
                for action in (params.get("hanguel_event_actions") or [params.get("hanguel_event_action") or behavior])
                if action
            ],
        }
        return base_result

    if base_result.get("status") in ("success", "manual_required"):
        base_result["hanguel_event_emission"] = emit_hanguel_events(target, params, base_result)

    return base_result

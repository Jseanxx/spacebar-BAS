import argparse
import base64
import json
import os
from pathlib import Path
from urllib import error, request

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGET_PATH = PROJECT_ROOT / "targets" / "SB-AD.yaml"


RULES = [
    ("user_execution_malicious_file", "T1204.002", "User Execution Malicious File", "medium", 47),
    ("windows_command_shell", "T1059.003", "Windows Command Shell", "medium", 47),
    ("non_application_tcp_connection", "T1095", "Non Application Layer Protocol", "medium", 47),
    ("domain_account_discovery", "T1087.002", "Domain Account Discovery", "low", 21),
    ("remote_system_discovery", "T1018", "Remote System Discovery", "low", 21),
    ("system_owner_user_discovery", "T1033", "System Owner User Discovery", "low", 21),
    ("network_share_discovery", "T1135", "Network Share Discovery", "medium", 47),
    ("permission_groups_discovery", "T1069", "Permission Groups Discovery", "medium", 47),
    ("kerberoasting_tgs_request", "T1558.003", "Kerberoasting", "high", 73),
    ("winrm_remote_execution", "T1021.006", "WinRM Remote Execution", "high", 73),
    ("powershell_over_winrm", "T1059.001", "PowerShell Over WinRM", "high", 73),
    ("ingress_tool_transfer", "T1105", "Ingress Tool Transfer", "medium", 47),
    ("lsass_memory_dump", "T1003.001", "LSASS Memory Dump", "critical", 90),
    ("rundll32_comsvcs_proxy", "T1218.011", "Rundll32 Comsvcs MiniDump", "high", 73),
    ("local_data_staging", "T1074.001", "Local Data Staging", "high", 73),
    ("exfiltration_over_c2", "T1041", "Exfiltration Over C2 Channel", "high", 73),
    ("masquerading_legitimate_name", "T1036.005", "Masquerading", "medium", 47),
    ("archive_collected_data", "T1560.001", "Archive Collected Data", "medium", 47),
    ("dcsync_replication", "T1003.006", "DCSync", "critical", 90),
    ("golden_ticket_service_ticket", "T1558.001", "Golden Ticket", "critical", 90),
    ("valid_domain_account_remote_logon", "T1078.002", "Valid Domain Account Remote Logon", "high", 73),
    ("service_execution", "T1569.002", "Service Execution", "critical", 90),
    ("ntds_dump", "T1003.003", "NTDS Dump", "critical", 90),
]


ACTIVE_BEHAVIORS = {
    "local_data_staging",
    "exfiltration_over_c2",
    "dcsync_replication",
}


MANUAL_RULE_BEHAVIORS = {
    "winrm_remote_execution",
    "powershell_over_winrm",
    "ingress_tool_transfer",
    "lsass_memory_dump",
}


SCENARIO_ORDERS = {
    "winrm_remote_execution": 10,
    "powershell_over_winrm": 11,
    "ingress_tool_transfer": 12,
    "lsass_memory_dump": 13,
    "local_data_staging": 15,
    "exfiltration_over_c2": 16,
    "dcsync_replication": 19,
    "golden_ticket_service_ticket": 20,
    "valid_domain_account_remote_logon": 21,
    "service_execution": 22,
}


def load_target():
    with TARGET_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def slug(value):
    return (
        value.lower()
        .replace(".", "-")
        .replace("_", "-")
        .replace(" ", "-")
    )


def build_rule(target, behavior, technique_id, title, severity, risk_score):
    query = target["log_queries"][behavior]
    scenario_order = SCENARIO_ORDERS.get(behavior)
    rule_name = f"{scenario_order}.{technique_id}" if scenario_order else technique_id

    return {
        "rule_id": f"sb-ad-{slug(technique_id)}-{slug(behavior)}",
        "name": rule_name,
        "description": (
            f"Spacebar AWS AD lab detection rule for {technique_id} - {title}. "
            "Generated from the SB-AD BAS campaign and Notion detection notes."
        ),
        "severity": severity,
        "risk_score": risk_score,
        "type": "query",
        "language": "kuery",
        "query": query,
        "index": [target.get("elk", {}).get("index", "winlogbeat-*")],
        "interval": "10m",
        "from": "now-660s",
        "enabled": True,
        "tags": [
            "SB-AD",
            "Spacebar",
            "BAS",
            "AWS-AD-Lab",
            technique_id,
            behavior,
            "source:notion",
        ],
    }


class KibanaClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        token = f"{username}:{password}".encode("utf-8")
        self.auth = f"Basic {base64.b64encode(token).decode('ascii')}"

    def request(self, method, path, payload=None):
        body = None
        headers = {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": self.auth,
        }

        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        req = request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with request.urlopen(req, timeout=20) as response:
                text = response.read().decode("utf-8")
                return response.status, json.loads(text) if text else {}
        except error.HTTPError as exc:
            text = exc.read().decode("utf-8")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"message": text}
            return exc.code, payload

    def upsert_rule(self, rule):
        status, existing = self.request(
            "GET",
            f"/api/detection_engine/rules?rule_id={rule['rule_id']}",
        )

        if status == 200 and existing.get("id"):
            update_payload = dict(rule)
            update_status, update_body = self.request(
                "PUT",
                "/api/detection_engine/rules",
                update_payload,
            )
            return "updated", update_status, update_body

        create_status, create_body = self.request(
            "POST",
            "/api/detection_engine/rules",
            rule,
        )
        return "created", create_status, create_body


def main():
    parser = argparse.ArgumentParser(description="Create or update SB-AD Kibana detection rules.")
    parser.add_argument("--dry-run", action="store_true", help="Print rule payloads without calling Kibana.")
    args = parser.parse_args()

    target = load_target()
    rules = [
        build_rule(target, *rule_config)
        for rule_config in RULES
        if rule_config[0] in ACTIVE_BEHAVIORS
        and rule_config[0] not in MANUAL_RULE_BEHAVIORS
    ]

    if args.dry_run:
        print(json.dumps(rules, indent=2, ensure_ascii=False))
        return

    base_url = os.environ.get("KIBANA_URL")
    username = os.environ.get("KIBANA_USERNAME")
    password = os.environ.get("KIBANA_PASSWORD")

    if not all([base_url, username, password]):
        raise SystemExit("KIBANA_URL, KIBANA_USERNAME, and KIBANA_PASSWORD are required.")

    client = KibanaClient(base_url, username, password)

    for rule in rules:
        action, status, body = client.upsert_rule(rule)
        ok = 200 <= status < 300
        print(json.dumps({
            "ok": ok,
            "action": action,
            "status": status,
            "rule_id": rule["rule_id"],
            "name": rule["name"],
            "response_id": body.get("id"),
            "message": body.get("message"),
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()

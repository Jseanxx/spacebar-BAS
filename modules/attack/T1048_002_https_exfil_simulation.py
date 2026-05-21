import shlex
import subprocess
from datetime import datetime, timezone


def _build_ssh_command(target, params):
    app = target.get("app", {})
    host = app.get("host")
    user = params.get("username") or app.get("ssh_user")
    key_path = app.get("ssh_key_path")
    remote_command = _build_remote_command(params)

    return [
        "ssh",
        "-i",
        key_path,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        f"{user}@{host}",
        remote_command,
    ]


def _build_remote_command(params):
    destination_url = params.get("destination_url", "https://example.com/")
    marker = params.get("marker") or f"SB01_BAS_T1048_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    user_agent = f"Spacebar-BAS/{marker}"

    quoted_destination_url = shlex.quote(destination_url)
    quoted_user_agent = shlex.quote(user_agent)

    return (
        "command -v curl >/dev/null 2>&1 && "
        f"curl -sS -o /dev/null --max-time 10 "
        f"-A {quoted_user_agent} "
        f"-w 'https_outbound_http=%{{http_code}} bytes=%{{size_download}}\\n' "
        f"{quoted_destination_url}"
    )


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "aws_vpc_app_outbound_443")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")
    ssh_command = _build_ssh_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated outbound HTTPS exfiltration validation without sensitive data",
            "behavior": behavior,
            "evidence_key": evidence_key,
            "commands": [
                {
                    "command": " ".join(ssh_command),
                    "returncode": 0,
                    "stdout": "https_outbound_http=200 bytes=0",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "Outbound HTTPS flow only",
                "No sensitive payload is uploaded",
            ],
        }

    completed = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=int(params.get("timeout", 20)),
    )

    return {
        "status": "success" if completed.returncode == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "Outbound HTTPS exfiltration validation executed without sensitive data",
        "behavior": behavior,
        "evidence_key": evidence_key,
        "commands": [
            {
                "command": " ".join(ssh_command),
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        ],
        "artifacts": [
            "Outbound HTTPS flow only",
            "No sensitive payload is uploaded",
        ],
    }

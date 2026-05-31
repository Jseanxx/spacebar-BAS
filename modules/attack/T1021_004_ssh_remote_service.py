import os
import socket
import subprocess


def connection_config(target):
    return target.get("ssh") or target.get("app", {})


def build_ssh_command(target, params):
    config = connection_config(target)
    host = params.get("host") or config.get("host") or config.get("ssh_host")
    user = params.get("username") or config.get("ssh_user")
    key_path = params.get("ssh_key_path") or config.get("ssh_key_path")
    port = params.get("port") or config.get("ssh_port") or 22
    command = params.get("command", "hostname")

    if not host:
        raise ValueError("SSH host is not configured for this target")
    if not user:
        raise ValueError("SSH username is not configured for this target")

    ssh_command = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        "-p",
        str(port),
    ]

    if key_path:
        ssh_command.extend(["-i", key_path])

    ssh_command.extend([
        f"{user}@{host}",
        command,
    ])

    return ssh_command


def should_use_local_agent_control(target, params):
    if not params.get("allow_local_agent_control"):
        return False

    config = connection_config(target)
    expected_role = params.get("expected_agent_role") or config.get("agent_role") or "campaign_agent"
    current_role = os.environ.get("BAS_AGENT_ROLE") or "campaign_agent"
    if expected_role and current_role != expected_role:
        return False

    local_hostnames = params.get("local_hostnames") or config.get("local_hostnames") or []
    if isinstance(local_hostnames, str):
        local_hostnames = [local_hostnames]

    current_hostname = socket.gethostname().lower()
    normalized_hosts = [str(item).lower() for item in local_hostnames if item]
    if any(host in current_hostname or current_hostname in host for host in normalized_hosts):
        return True

    key_path = params.get("ssh_key_path") or config.get("ssh_key_path")
    fallback_enabled = params.get("fallback_to_local_agent_control", True)
    return bool(fallback_enabled and key_path and not os.path.exists(str(key_path)))


def run_local_control_check(params):
    command = params.get("local_command") or params.get("command") or "hostname"
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=int(params.get("timeout_seconds") or 15),
    )

    return completed


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "jenkins_to_app_ssh")
    execution_mode = params.get("_execution_mode", "simulation")

    if execution_mode == "simulation":
        ssh_command = build_ssh_command(target, params)
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": params.get("simulation_message") or "Simulated SSH remote service access using configured key",
            "behavior": behavior,
            "evidence_key": behavior,
            "commands": [
                {
                    "command": " ".join(ssh_command),
                    "returncode": 0,
                    "stdout": params.get("simulation_stdout") or "ssh-access-check",
                    "stderr": "",
                }
            ],
            "artifacts": [
                params.get("simulation_artifact") or "/var/log/auth.log: Accepted publickey for configured SSH user",
            ],
        }

    if should_use_local_agent_control(target, params):
        completed = run_local_control_check(params)
        command_label = params.get("local_command") or params.get("command") or "hostname"
        mode = "local_agent_control"
        message = "BAS Agent already controls the target host; local control check executed"
    else:
        ssh_command = build_ssh_command(target, params)
        completed = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=int(params.get("timeout_seconds") or 15),
        )
        command_label = " ".join(ssh_command)
        mode = "ssh"
        message = params.get("success_message") or "SSH remote service access executed"

    return {
        "status": "success" if completed.returncode == 0 else "failed",
        "execution_mode": execution_mode,
        "message": message,
        "behavior": behavior,
        "evidence_key": behavior,
        "connection_mode": mode,
        "commands": [
            {
                "command": command_label,
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        ],
    }

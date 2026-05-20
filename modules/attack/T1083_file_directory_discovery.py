import shlex
import subprocess


def build_remote_command(params):
    base_path = params.get("base_path", "/opt/spacebar-booking")
    max_depth = int(params.get("max_depth", 2))
    safe_base_path = shlex.quote(base_path)

    return (
        f"ls -la {safe_base_path} && "
        f"find {safe_base_path} -maxdepth {max_depth} -type f "
        "\\( -name '.env' -o -name 'docker-compose.yml' -o -name '*config*' \\) "
        "-printf '%p\\n'"
    )


def build_ssh_command(target, params):
    app = target.get("app", {})
    host = app.get("host")
    user = params.get("username") or app.get("ssh_user")
    key_path = app.get("ssh_key_path")

    return [
        "ssh",
        "-i",
        key_path,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        f"{user}@{host}",
        build_remote_command(params),
    ]


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "app_directory_discovery")
    execution_mode = params.get("_execution_mode", "simulation")
    base_path = params.get("base_path", "/opt/spacebar-booking")
    ssh_command = build_ssh_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated App directory and config file discovery",
            "behavior": behavior,
            "evidence_key": behavior,
            "target_path": base_path,
            "commands": [
                {
                    "command": " ".join(ssh_command),
                    "returncode": 0,
                    "stdout": (
                        f"{base_path}\n"
                        f"{base_path}/docker-compose.yml\n"
                        f"{base_path}/.env"
                    ),
                    "stderr": "",
                }
            ],
            "artifacts": [
                "/var/log/audit/audit.log: key=sb01_app_path_read",
                f"auditd PATH name={base_path}",
            ],
        }

    completed = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=20,
    )

    return {
        "status": "success" if completed.returncode == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "App directory discovery executed",
        "behavior": behavior,
        "evidence_key": behavior,
        "target_path": base_path,
        "commands": [
            {
                "command": " ".join(ssh_command),
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        ],
    }

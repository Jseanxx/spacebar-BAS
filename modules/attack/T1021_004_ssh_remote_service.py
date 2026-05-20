import subprocess


def build_ssh_command(target, params):
    app = target.get("app", {})
    host = app.get("host")
    user = params.get("username") or app.get("ssh_user")
    key_path = app.get("ssh_key_path")
    command = params.get("command", "hostname")

    return [
        "ssh",
        "-i",
        key_path,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        f"{user}@{host}",
        command,
    ]


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "jenkins_to_app_ssh")
    execution_mode = params.get("_execution_mode", "simulation")
    ssh_command = build_ssh_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated Jenkins to App SSH using deploy key",
            "behavior": behavior,
            "evidence_key": behavior,
            "commands": [
                {
                    "command": " ".join(ssh_command),
                    "returncode": 0,
                    "stdout": "ip-172-31-4-70",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "/var/log/auth.log: Accepted publickey for deploy from Jenkins private IP",
            ],
        }

    completed = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=15,
    )

    return {
        "status": "success" if completed.returncode == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "Jenkins to App SSH executed",
        "behavior": behavior,
        "evidence_key": behavior,
        "commands": [
            {
                "command": " ".join(ssh_command),
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        ],
    }

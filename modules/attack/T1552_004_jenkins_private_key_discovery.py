import shlex
import subprocess


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


def _build_command(target, params):
    jenkins = target.get("jenkins", {})
    base_paths = params.get("base_paths") or jenkins.get("home_paths")
    if not base_paths:
        base_paths = [
            params.get("base_path") or jenkins.get("home_path", "/var/jenkins_home"),
            "/var/lib/docker/volumes/jenkins_jenkins_home/_data",
        ]
    max_depth = int(params.get("max_depth", 5))
    quoted_base_paths = " ".join(shlex.quote(path) for path in base_paths)

    return (
        "for base in " + quoted_base_paths + "; do "
        "[ -d \"$base\" ] || continue; "
        f"find \"$base\" -maxdepth {max_depth} -type f "
        "\\( -name '*.pem' -o -name 'id_rsa*' -o -name '*private*key*' \\) "
        "-printf 'path=%p mode=%m size=%s\\n' 2>/dev/null; "
        "done | head -30"
    )


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "jenkins_private_key_discovery")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")
    command = _build_command(target, params)

    if execution_mode == "simulation":
        return {
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated Jenkins private key path discovery",
            "behavior": behavior,
            "evidence_key": evidence_key,
            "commands": [
                {
                    "command": command,
                    "returncode": 0,
                    "stdout": "path=/var/jenkins_home/.ssh/sb01-app-deploy-key mode=600 size=1679",
                    "stderr": "",
                }
            ],
            "artifacts": [
                "Private key path metadata only; key material is not printed",
            ],
        }

    result = _run_command(command, timeout=int(params.get("timeout", 20)))

    return {
        "status": "success" if result["returncode"] == 0 else "failed",
        "execution_mode": execution_mode,
        "message": "Jenkins private key path discovery executed",
        "behavior": behavior,
        "evidence_key": evidence_key,
        "commands": [result],
        "artifacts": [
            "Private key candidate paths listed without reading key contents",
        ],
    }

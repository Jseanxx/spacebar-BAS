def run(target, params=None):
    params = params or {}

    behavior = params.get("behavior", "sb01_log_evidence")
    evidence_key = params.get("evidence_key", behavior)
    execution_mode = params.get("_execution_mode", "simulation")

    commands = params.get("commands") or []
    artifacts = params.get("artifacts") or []

    return {
        "status": "success",
        "simulated": True,
        "execution_mode": execution_mode,
        "message": params.get("message", "SB-01 log evidence validation simulated"),
        "behavior": behavior,
        "evidence_key": evidence_key,
        "commands": [
            {
                "command": command,
                "returncode": 0,
                "stdout": params.get("stdout", "simulated"),
                "stderr": "",
            }
            for command in commands
        ],
        "artifacts": artifacts,
        "notes": params.get("notes", []),
    }

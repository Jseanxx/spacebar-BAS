import base64
import binascii
import json
import subprocess


def run_command(command, timeout=20):
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return {
        "command": " ".join(command),
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def decode_secret_values(secret_payload):
    decoded_secrets = []

    for item in secret_payload.get("items", []):
        decoded_values = {}

        for key, value in (item.get("data") or {}).items():
            try:
                decoded_values[key] = base64.b64decode(value).decode("utf-8", errors="replace")
            except (binascii.Error, TypeError, ValueError):
                decoded_values[key] = "<decode failed>"

        decoded_secrets.append({
            "name": item.get("metadata", {}).get("name", "unknown"),
            "namespace": item.get("metadata", {}).get("namespace", "unknown"),
            "type": item.get("type", "unknown"),
            "decoded_values": decoded_values,
        })

    return decoded_secrets


def run(target, params=None):
    params = params or {}

    behavior = params.get("behavior", "kube_secret_access")
    namespace = params.get("namespace") or target.get("primary_namespace")
    resource = params.get("resource", "secrets")
    execution_mode = params.get("_execution_mode", "simulation")

    if execution_mode != "real":
        return {
            "status": "success",
            "message": "prod-platform secret access simulated",
            "behavior": behavior,
            "evidence_key": behavior,
            "execution_mode": execution_mode,
            "namespace": namespace,
            "resource": resource,
            "simulated": True,
        }

    commands = [
        ["kubectl", "get", resource, "-n", namespace],
        ["kubectl", "get", resource, "-n", namespace, "-o", "json"],
    ]

    command_results = [
        run_command(command)
        for command in commands
    ]

    failed_commands = [
        result for result in command_results
        if result["returncode"] != 0
    ]

    decoded_secrets = []
    parse_error = None
    read_result = command_results[-1]

    if read_result["returncode"] == 0 and read_result["stdout"]:
        try:
            secret_payload = json.loads(read_result["stdout"])
            decoded_secrets = decode_secret_values(secret_payload)
            read_result["stdout"] = (
                f"Read and decoded {len(decoded_secrets)} Kubernetes secret object(s). "
                "Decoded values are stored in module_result.secrets."
            )
        except json.JSONDecodeError as exc:
            parse_error = str(exc)

    return {
        "status": "failed" if failed_commands or parse_error else "success",
        "message": "Kubernetes secret values read with kubectl",
        "behavior": behavior,
        "evidence_key": behavior,
        "execution_mode": execution_mode,
        "namespace": namespace,
        "resource": resource,
        "technique_id": "T1552.007",
        "commands": command_results,
        "secret_count": len(decoded_secrets),
        "secrets": decoded_secrets,
        "parse_error": parse_error,
    }

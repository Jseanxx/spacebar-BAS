import os
import platform
import re
import subprocess


SENSITIVE_WORDS = ("PASSWORD", "HASH", "AES", "NTLM", "SECRET", "KEY", "TOKEN")


def flatten_context(target, params):
    context = {}

    def add_mapping(mapping):
        if not isinstance(mapping, dict):
            return
        for key, value in mapping.items():
            if isinstance(value, (str, int, float, bool)):
                context[key] = value

    for section in ("hosts", "ad", "accounts", "paths", "tools", "operation_defaults"):
        add_mapping(target.get(section, {}))

    add_mapping(params)
    return context


def render_template(value, context):
    if not isinstance(value, str):
        return value

    rendered = value
    for key, item in context.items():
        rendered = rendered.replace("{{ " + key + " }}", str(item))
        rendered = rendered.replace("{{" + key + "}}", str(item))
    return rendered


def redact(value):
    if not isinstance(value, str):
        return value

    redacted = value
    for key, item in os.environ.items():
        if not item:
            continue
        if any(word in key.upper() for word in SENSITIVE_WORDS):
            redacted = redacted.replace(item, "<redacted>")

    redacted = re.sub(
        r"(?i)(password|hash|aeskey|nthash|ntlm|secret|token)\s*[:=]\s*[^ \r\n;]+",
        r"\1=<redacted>",
        redacted,
    )
    return redacted


def current_platform():
    if platform.system().lower().startswith("win"):
        return "windows"
    return "linux"


def build_command(command, shell_name):
    if shell_name == "powershell":
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]

    if shell_name == "cmd":
        return ["cmd", "/c", command]

    if shell_name == "bash":
        return ["bash", "-lc", command]

    return command


def should_block_for_safety(params):
    missing = []

    for gate in params.get("safety_gates", []) or []:
        if os.environ.get(gate) != "1":
            missing.append(gate)

    return missing


def command_is_for_this_agent(command_spec):
    required_role = command_spec.get("agent_role")
    if not required_role:
        return True, None

    current_role = os.environ.get("BAS_AGENT_ROLE")
    if current_role == required_role:
        return True, None

    return False, {
        "required_agent_role": required_role,
        "current_agent_role": current_role,
    }


def run_local_command(command_spec, context):
    command = render_template(command_spec.get("command", ""), context)
    shell_name = command_spec.get("shell", "powershell" if current_platform() == "windows" else "bash")
    timeout = int(command_spec.get("timeout", 30))
    argv = build_command(command, shell_name)

    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=isinstance(argv, str),
    )

    return {
        "name": command_spec.get("name"),
        "executor": "local",
        "agent_role": command_spec.get("agent_role"),
        "platform": command_spec.get("platform", "any"),
        "shell": shell_name,
        "command": redact(command),
        "returncode": completed.returncode,
        "stdout": redact(completed.stdout.strip()),
        "stderr": redact(completed.stderr.strip()),
    }


def summarize_commands(commands, context):
    rendered = []

    for command_spec in commands:
        copied = dict(command_spec)
        copied["command"] = redact(render_template(copied.get("command", ""), context))
        rendered.append(copied)

    return rendered


def run(target, params=None):
    params = params or {}
    behavior = params.get("behavior", "sb_ad_technique")
    execution_mode = params.get("_execution_mode", "simulation")
    commands = params.get("commands", [])
    context = flatten_context(target, params)

    base_result = {
        "behavior": behavior,
        "evidence_key": behavior,
        "technique_id": params.get("technique_id"),
        "description": params.get("description"),
        "execution_host": params.get("execution_host"),
        "risk": params.get("risk", "medium"),
        "commands": summarize_commands(commands, context),
        "safety_gates": params.get("safety_gates", []),
    }

    if execution_mode != "real":
        return {
            **base_result,
            "status": "success",
            "simulated": True,
            "execution_mode": execution_mode,
            "message": "Simulated SB-AD technique. No command was executed.",
        }

    missing_gates = should_block_for_safety(params)
    if missing_gates:
        return {
            **base_result,
            "status": "blocked",
            "execution_mode": execution_mode,
            "message": "Real execution blocked by missing safety gates.",
            "missing_safety_gates": missing_gates,
        }

    results = []
    skipped = []
    local_platform = current_platform()

    for command_spec in commands:
        executor = command_spec.get("executor", "manual")
        command_platform = command_spec.get("platform", "any")

        if executor != "local":
            skipped.append({
                "name": command_spec.get("name"),
                "reason": "manual_command",
                "command": redact(render_template(command_spec.get("command", ""), context)),
            })
            continue

        if command_platform not in ("any", local_platform):
            skipped.append({
                "name": command_spec.get("name"),
                "reason": "platform_mismatch",
                "required_platform": command_platform,
                "current_platform": local_platform,
            })
            continue

        role_ok, role_context = command_is_for_this_agent(command_spec)
        if not role_ok:
            skipped.append({
                "name": command_spec.get("name"),
                "reason": "agent_role_mismatch",
                **role_context,
            })
            continue

        try:
            results.append(run_local_command(command_spec, context))
        except Exception as exc:
            results.append({
                "name": command_spec.get("name"),
                "executor": "local",
                "agent_role": command_spec.get("agent_role"),
                "status": "failed",
                "error": str(exc),
            })

    executed_count = len(results)
    failed_count = len([item for item in results if item.get("returncode", 0) != 0 or item.get("status") == "failed"])

    if executed_count == 0:
        status = "manual_required" if skipped else "success"
    else:
        status = "failed" if failed_count else "success"

    return {
        **base_result,
        "status": status,
        "execution_mode": execution_mode,
        "message": "SB-AD technique real-mode evaluation completed.",
        "executed_count": executed_count,
        "skipped": skipped,
        "command_results": results,
    }

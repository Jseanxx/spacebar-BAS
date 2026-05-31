import os
import platform
import re
import subprocess
import time
import uuid
from pathlib import Path


SENSITIVE_WORDS = ("PASSWORD", "HASH", "AES", "NTLM", "SECRET", "KEY", "TOKEN")
MARKER_ENV_NAME = "SPACEBAR_BAS_MARKER"


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


def powershell_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def get_execution_marker(context):
    marker = context.get("_execution_marker")
    if marker:
        return str(marker)
    operation_id = context.get("_operation_id")
    step_order = context.get("_step_order")
    if operation_id and step_order is not None:
        return f"{operation_id}-step-{step_order}"
    return None


def marker_token(marker):
    if not marker:
        return None
    return f"SPACEBAR_BAS_MARKER={marker}"


def sanitize_task_component(value):
    return re.sub(r"[^A-Za-z0-9_-]", "-", str(value or ""))[:80].strip("-")


def build_task_id(context):
    marker = sanitize_task_component(get_execution_marker(context))
    if marker:
        return f"SpacebarBAS-{marker[:48]}-{uuid.uuid4().hex[:6]}"
    return f"SpacebarBAS-{uuid.uuid4().hex[:10]}"


def inject_execution_marker(command, shell_name, context):
    marker = get_execution_marker(context)
    token = marker_token(marker)
    if not token:
        return command, None

    if shell_name == "powershell":
        prefix = (
            f"$env:{MARKER_ENV_NAME} = {powershell_string(marker)}; "
            f"Write-Output {powershell_string(token)} | Out-Null; "
        )
        return f"{prefix}{command}", token

    if shell_name == "cmd":
        return f"echo {token} > NUL & {command}", token

    if shell_name == "bash":
        quoted_marker = "'" + str(marker).replace("'", "'\"'\"'") + "'"
        quoted_token = "'" + str(token).replace("'", "'\"'\"'") + "'"
        prefix = (
            f"export {MARKER_ENV_NAME}={quoted_marker}; "
            f"printf '%s\\n' {quoted_token} >> /tmp/spacebar-bas-markers.log; "
        )
        return f"{prefix}{command}", token

    return command, token


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
    command, marker = inject_execution_marker(command, shell_name, context)
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
        "execution_marker": marker,
        "command": redact(command),
        "returncode": completed.returncode,
        "stdout": redact(completed.stdout.strip()),
        "stderr": redact(completed.stderr.strip()),
    }


def run_windows_scheduled_user_command(command_spec, context):
    if current_platform() != "windows":
        raise RuntimeError("windows_scheduled_user executor is only supported on Windows agents.")

    shell_name = command_spec.get("shell", "powershell")
    command = render_template(command_spec.get("command", ""), context)
    command, marker = inject_execution_marker(command, shell_name, context)
    timeout = int(command_spec.get("timeout", 30))
    post_run_wait = int(command_spec.get("post_run_wait", 5))
    user_name = render_template(command_spec.get("run_as_user", ""), context)
    password_env = command_spec.get("password_env", "BAS_EMPLOYEE_PASSWORD")
    password = os.environ.get(password_env)

    if not user_name:
        raise RuntimeError("run_as_user is required for windows_scheduled_user executor.")

    if not password:
        raise RuntimeError(f"{password_env} is missing for windows_scheduled_user executor.")

    task_id = build_task_id(context)
    task_dir = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SpacebarBAS" / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)

    payload_suffix = ".cmd" if shell_name == "cmd" else ".ps1"
    payload_path = task_dir / f"{task_id}-payload{payload_suffix}"
    wrapper_path = task_dir / f"{task_id}.cmd"
    stdout_path = task_dir / f"{task_id}.stdout.txt"
    stderr_path = task_dir / f"{task_id}.stderr.txt"

    if shell_name == "cmd":
        payload_path.write_text(
            "@echo off\r\n"
            f"{command}\r\n"
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
        wrapper_path.write_text(
            "@echo off\r\n"
            f'call "{payload_path}" > "{stdout_path}" 2> "{stderr_path}"\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    elif shell_name == "powershell":
        payload_path.write_text(
            "$ErrorActionPreference = \"Stop\"\r\n"
            f"{command}\r\n"
            "if ($global:LASTEXITCODE -is [int]) { exit $global:LASTEXITCODE }\r\n",
            encoding="utf-8-sig",
        )
        wrapper_path.write_text(
            "@echo off\r\n"
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{payload_path}" > "{stdout_path}" 2> "{stderr_path}"\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
    else:
        raise RuntimeError(f"Unsupported scheduled user shell: {shell_name}")

    task_action = f'cmd.exe /c "{wrapper_path}"'
    create_command = [
        "schtasks",
        "/Create",
        "/TN",
        task_id,
        "/SC",
        "ONCE",
        "/ST",
        "23:59",
        "/TR",
        task_action,
        "/RU",
        user_name,
        "/RP",
        password,
        "/RL",
        "LIMITED",
        "/F",
    ]
    run_command = ["schtasks", "/Run", "/TN", task_id]
    query_command = ["schtasks", "/Query", "/TN", task_id, "/V", "/FO", "LIST"]
    delete_command = ["schtasks", "/Delete", "/TN", task_id, "/F"]

    create_result = subprocess.run(create_command, capture_output=True, text=True, timeout=30)
    run_result = None
    query_result = None
    delete_result = None
    last_task_result = None
    command_stdout = ""
    command_stderr = ""

    try:
        if create_result.returncode == 0:
            run_result = subprocess.run(run_command, capture_output=True, text=True, timeout=30)
            started_at = time.time()
            while True:
                time.sleep(post_run_wait)
                query_result = subprocess.run(query_command, capture_output=True, text=True, timeout=30)
                if query_result.returncode == 0:
                    match = re.search(r"Last Result:\s*([^\r\n]+)", query_result.stdout)
                    if not match:
                        match = re.search(r"Last Task Result:\s*([^\r\n]+)", query_result.stdout)
                    if match:
                        last_task_result = match.group(1).strip()

                    status_match = re.search(r"Status:\s*([^\r\n]+)", query_result.stdout)
                    status_text = status_match.group(1).strip().lower() if status_match else ""
                    if status_text and "running" not in status_text:
                        break

                    if last_task_result in ("0", "0x0"):
                        break

                if time.time() - started_at >= timeout:
                    last_task_result = last_task_result or "timeout"
                    break

            if stdout_path.exists():
                command_stdout = stdout_path.read_text(encoding="utf-8", errors="replace").strip()
            if stderr_path.exists():
                command_stderr = stderr_path.read_text(encoding="utf-8", errors="replace").strip()
    finally:
        delete_result = subprocess.run(delete_command, capture_output=True, text=True, timeout=30)
        for path in (payload_path, wrapper_path, stdout_path, stderr_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

    command_failed = create_result.returncode != 0 or (run_result is not None and run_result.returncode != 0)
    if last_task_result not in (None, "0", "0x0"):
        command_failed = True

    stdout_parts = [
        command_stdout,
        create_result.stdout.strip(),
        run_result.stdout.strip() if run_result else "",
        query_result.stdout.strip() if query_result else "",
        delete_result.stdout.strip() if delete_result else "",
    ]
    stderr_parts = [
        command_stderr,
        create_result.stderr.strip(),
        run_result.stderr.strip() if run_result else "",
        query_result.stderr.strip() if query_result else "",
        delete_result.stderr.strip() if delete_result else "",
    ]

    return {
        "name": command_spec.get("name"),
        "executor": "windows_scheduled_user",
        "agent_role": command_spec.get("agent_role"),
        "platform": command_spec.get("platform", "windows"),
        "shell": shell_name,
        "run_as_user": user_name,
        "password_env": password_env,
        "task_name": task_id,
        "execution_marker": marker,
        "command": redact(command),
        "returncode": 1 if command_failed else 0,
        "last_task_result": last_task_result,
        "stdout": redact("\n".join(part for part in stdout_parts if part)),
        "stderr": redact("\n".join(part for part in stderr_parts if part)),
    }


def run_windows_credential_process_command(command_spec, context):
    if current_platform() != "windows":
        raise RuntimeError("windows_credential_process executor is only supported on Windows agents.")

    shell_name = command_spec.get("shell", "powershell")
    command = render_template(command_spec.get("command", ""), context)
    command, marker = inject_execution_marker(command, shell_name, context)
    timeout = int(command_spec.get("timeout", 30))
    user_name = render_template(command_spec.get("run_as_user", ""), context)
    password_env = command_spec.get("password_env", "BAS_EMPLOYEE_PASSWORD")
    password = os.environ.get(password_env)

    if not user_name:
        raise RuntimeError("run_as_user is required for windows_credential_process executor.")

    if not password:
        raise RuntimeError(f"{password_env} is missing for windows_credential_process executor.")

    task_id = build_task_id(context)
    task_dir = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SpacebarBAS" / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)

    payload_suffix = ".cmd" if shell_name == "cmd" else ".ps1"
    payload_path = task_dir / f"{task_id}-payload{payload_suffix}"
    launcher_path = task_dir / f"{task_id}-launcher.ps1"
    stdout_path = task_dir / f"{task_id}.stdout.txt"
    stderr_path = task_dir / f"{task_id}.stderr.txt"

    if shell_name == "cmd":
        payload_path.write_text(
            "@echo off\r\n"
            f"{command}\r\n"
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
        file_path = "cmd.exe"
        quoted_payload = powershell_string(f'"{payload_path}"')
        argument_list = f"@('/c', {quoted_payload})"
    elif shell_name == "powershell":
        payload_path.write_text(
            "$ErrorActionPreference = \"Stop\"\r\n"
            f"{command}\r\n"
            "if ($global:LASTEXITCODE -is [int]) { exit $global:LASTEXITCODE }\r\n",
            encoding="utf-8-sig",
        )
        file_path = "powershell.exe"
        argument_list = (
            "@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "
            f"{powershell_string(str(payload_path))})"
        )
    else:
        raise RuntimeError(f"Unsupported credential process shell: {shell_name}")

    launcher_path.write_text(
        "$ErrorActionPreference = \"Stop\"\r\n"
        f"$sec = ConvertTo-SecureString $env:{password_env} -AsPlainText -Force\r\n"
        f"$cred = New-Object System.Management.Automation.PSCredential({powershell_string(user_name)}, $sec)\r\n"
        "$startInfo = @{\r\n"
        f"  FilePath = {powershell_string(file_path)}\r\n"
        f"  ArgumentList = {argument_list}\r\n"
        "  Credential = $cred\r\n"
        "  LoadUserProfile = $true\r\n"
        "  Wait = $true\r\n"
        "  PassThru = $true\r\n"
        f"  RedirectStandardOutput = {powershell_string(str(stdout_path))}\r\n"
        f"  RedirectStandardError = {powershell_string(str(stderr_path))}\r\n"
        "}\r\n"
        "$process = Start-Process @startInfo\r\n"
        "exit $process.ExitCode\r\n",
        encoding="utf-8-sig",
    )

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(launcher_path),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    command_stdout = stdout_path.read_text(encoding="utf-8", errors="replace").strip() if stdout_path.exists() else ""
    command_stderr = stderr_path.read_text(encoding="utf-8", errors="replace").strip() if stderr_path.exists() else ""

    for path in (payload_path, launcher_path, stdout_path, stderr_path):
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

    stdout_parts = [
        command_stdout,
        completed.stdout.strip(),
    ]
    stderr_parts = [
        command_stderr,
        completed.stderr.strip(),
    ]

    return {
        "name": command_spec.get("name"),
        "executor": "windows_credential_process",
        "agent_role": command_spec.get("agent_role"),
        "platform": command_spec.get("platform", "windows"),
        "shell": shell_name,
        "run_as_user": user_name,
        "password_env": password_env,
        "execution_marker": marker,
        "command": redact(command),
        "returncode": completed.returncode,
        "stdout": redact("\n".join(part for part in stdout_parts if part)),
        "stderr": redact("\n".join(part for part in stderr_parts if part)),
    }


def summarize_commands(commands, context):
    rendered = []

    for command_spec in commands:
        copied = dict(command_spec)
        shell_name = copied.get("shell", "powershell" if current_platform() == "windows" else "bash")
        rendered_command = render_template(copied.get("command", ""), context)
        copied["execution_marker"] = marker_token(get_execution_marker(context))
        copied["command"] = redact(inject_execution_marker(rendered_command, shell_name, context)[0])
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
        "runtime_context": {
            key: params.get(key)
            for key in ("_operation_id", "_job_id", "_execution_marker", "_step_order")
            if params.get(key) is not None
        },
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

        if executor not in ("local", "windows_scheduled_user", "windows_credential_process"):
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
            if executor == "windows_scheduled_user":
                results.append(run_windows_scheduled_user_command(command_spec, context))
            elif executor == "windows_credential_process":
                results.append(run_windows_credential_process_command(command_spec, context))
            else:
                results.append(run_local_command(command_spec, context))
        except Exception as exc:
            results.append({
                "name": command_spec.get("name"),
                "executor": executor,
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

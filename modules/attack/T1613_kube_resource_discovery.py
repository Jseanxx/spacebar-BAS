import subprocess


def run_command(command, timeout=20):
    """
    shell=True를 쓰지 않고 kubectl 조회 명령을 실행합니다.
    T1613 real 모드는 삭제/변경 없는 get 명령만 사용합니다.
    """

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


def run(target, params=None):
    params = params or {}

    behavior = params.get("behavior", "kube_resource_discovery")
    namespace = params.get("namespace") or target.get("primary_namespace")
    execution_mode = params.get("_execution_mode", "simulation")

    if execution_mode != "real":
        return {
            "status": "success",
            "message": "Kubernetes resource discovery simulated",
            "behavior": behavior,
            "evidence_key": behavior,
            "execution_mode": execution_mode,
            "namespace": namespace,
            "resources": ["namespaces", "pods", "deployments", "services", "ingresses"],
        }

    commands = [
        ["kubectl", "get", "namespaces"],
        ["kubectl", "get", "pods", "-n", namespace],
        ["kubectl", "get", "services", "-n", namespace],
        ["kubectl", "get", "deployments", "-n", namespace],
        ["kubectl", "get", "ingresses", "-n", namespace],
    ]

    command_results = [
        run_command(command)
        for command in commands
    ]

    failed_commands = [
        result for result in command_results
        if result["returncode"] != 0
    ]

    return {
        "status": "failed" if failed_commands else "success",
        "message": "Kubernetes resource discovery executed with kubectl",
        "behavior": behavior,
        "evidence_key": behavior,
        "execution_mode": execution_mode,
        "namespace": namespace,
        "technique_id": "T1613",
        "commands": command_results,
    }
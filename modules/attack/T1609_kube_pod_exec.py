def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "orders-api pod command execution simulated",
        "behavior": params.get("behavior", "kube_pod_exec"),
        "evidence_key": params.get("behavior", "kube_pod_exec"),
        "namespace": params.get("namespace"),
        "pod_selector": params.get("pod_selector")
    }

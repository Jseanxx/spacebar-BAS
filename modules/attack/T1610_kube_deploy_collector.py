def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "sb05 collector pod deployment simulated",
        "behavior": params.get("behavior", "kube_deploy_collector"),
        "evidence_key": params.get("behavior", "kube_deploy_collector"),
        "namespace": params.get("namespace"),
        "pod_name": params.get("pod_name")
    }

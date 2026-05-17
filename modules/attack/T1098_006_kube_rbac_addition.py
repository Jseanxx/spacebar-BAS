def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "service account and rolebinding creation simulated",
        "behavior": params.get("behavior", "kube_rbac_addition"),
        "evidence_key": params.get("behavior", "kube_rbac_addition"),
        "namespace": params.get("namespace"),
        "service_account": params.get("service_account")
    }

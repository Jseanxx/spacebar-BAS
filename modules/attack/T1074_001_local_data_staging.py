def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "local data staging simulated",
        "behavior": params.get("behavior", "local_data_staging"),
        "evidence_key": params.get("behavior", "local_data_staging"),
        "staging_dir": params.get("staging_dir")
    }

def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "archive staged data simulated",
        "behavior": params.get("behavior", "archive_staged_data"),
        "evidence_key": params.get("behavior", "archive_staged_data"),
        "archive_name": params.get("archive_name")
    }

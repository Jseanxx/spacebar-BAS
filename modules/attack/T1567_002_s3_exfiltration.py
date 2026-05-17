def run(target, params=None):
    params = params or {}

    return {
        "status": "success",
        "message": "S3 exfiltration simulated",
        "behavior": params.get("behavior", "s3_exfiltration"),
        "evidence_key": params.get("behavior", "s3_exfiltration"),
        "destination": params.get("destination")
    }

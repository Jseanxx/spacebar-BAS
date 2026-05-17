# 어떤 쿼리로 확인해야 하는지 붙여주는 스텁
# 현재는 아직 ELK 조회 X 

def check_elk(target, evidence_key):
    elk_config = target.get("elk", {})
    queries = target.get("log_queries", {})

    query = queries.get(evidence_key)

    if not elk_config.get("enabled", False):
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "query": query,
            "message": "ELK check is disabled."
        }

    return {
        "checked": True,
        "matched": False,
        "event_count": 0,
        "query": query,
        "message": "Real ELK client is not implemented yet."
    }

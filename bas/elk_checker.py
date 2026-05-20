# 어떤 쿼리로 확인해야 하는지 붙여주는 스텁
# 현재는 아직 ELK 조회 X 

def check_elk(target, evidence_key):
    elk_config = target.get("elk", {})
    queries = target.get("log_queries", {})

    query = queries.get(evidence_key)
    index = elk_config.get("index")

    if not elk_config.get("enabled", False):
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": "ELK check is disabled. Query is ready, but no live Elasticsearch check was performed."
        }

    return {
        "checked": True,
        "matched": False,
        "event_count": 0,
        "index": index,
        "query": query,
        "sample_events": [],
        "message": "Real ELK client is not implemented yet."
    }

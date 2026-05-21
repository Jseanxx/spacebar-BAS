import base64
import json
import os
import urllib.error
import urllib.request


DEFAULT_ELK_URL = "http://127.0.0.1:9200"


def normalize_query(query):
    if not query:
        return query

    return (
        query
        .replace(" and ", " AND ")
        .replace(" or ", " OR ")
        .replace(" not ", " NOT ")
    )


def build_auth_header(username, password):
    if not username or not password:
        return None

    token = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(token).decode('ascii')}"


def search_elasticsearch(elk_url, index, query, username=None, password=None):
    payload = {
        "size": 3,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date",
                }
            }
        ],
        "query": {
            "query_string": {
                "query": normalize_query(query),
                "analyze_wildcard": True,
            }
        },
    }

    request = urllib.request.Request(
        f"{elk_url.rstrip('/')}/{index}/_search",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    auth_header = build_auth_header(username, password)
    if auth_header:
        request.add_header("Authorization", auth_header)

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def format_sample_events(hits):
    samples = []

    for hit in hits:
        source = hit.get("_source", {})
        samples.append({
            "@timestamp": source.get("@timestamp"),
            "host": source.get("host", {}).get("name"),
            "agent": source.get("agent", {}).get("name"),
            "event": source.get("event", {}).get("action") or source.get("verb"),
            "resource": source.get("objectRef", {}).get("resource"),
            "namespace": source.get("objectRef", {}).get("namespace"),
            "requestURI": source.get("requestURI"),
            "user": source.get("user", {}).get("username"),
        })

    return samples


def check_elk(target, evidence_key):
    elk_config = target.get("elk", {})
    queries = target.get("log_queries", {})

    query = queries.get(evidence_key)
    index = elk_config.get("index", "logs-*")

    if not elk_config.get("enabled", False):
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": "ELK check is disabled. Query is ready, but no live Elasticsearch check was performed.",
        }

    if not query:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": f"No ELK query configured for evidence key: {evidence_key}",
        }

    elk_url = os.environ.get("BAS_ELK_URL", DEFAULT_ELK_URL)
    username = os.environ.get("BAS_ELK_USERNAME")
    password = os.environ.get("BAS_ELK_PASSWORD")

    try:
        result = search_elasticsearch(elk_url, index, query, username, password)
        hits = result.get("hits", {})
        total = hits.get("total", {})
        event_count = total.get("value", 0) if isinstance(total, dict) else total

        return {
            "checked": True,
            "matched": event_count > 0,
            "event_count": event_count,
            "index": index,
            "query": query,
            "sample_events": format_sample_events(hits.get("hits", [])),
            "message": f"Elasticsearch live check completed against {elk_url}.",
        }
    except Exception as exc:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": f"Elasticsearch live check failed: {exc}",
        }

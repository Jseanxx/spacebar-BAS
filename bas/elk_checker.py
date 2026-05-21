import json
import urllib.error
import urllib.request


DEFAULT_LOOKBACK = "now-15m"
DEFAULT_SAMPLE_SIZE = 3


def _get_nested_value(data, dotted_key):
    current = data

    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def _compact_event(source):
    fields = [
        "@timestamp",
        "host.name",
        "log.file.path",
        "message",
        "event.module",
        "event.action",
        "event.dataset",
        "process.executable",
        "process.args",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.bytes",
        "network.transport",
        "auditd.log.record_type",
        "auditd.log.key",
        "auditd.log.name",
        "auditd.log.sequence",
    ]

    compacted = {}

    for field in fields:
        value = _get_nested_value(source, field) if "." in field else source.get(field)

        if value not in (None, "", [], {}):
            compacted[field] = value

    return compacted


def _normalize_query(query):
    if not query:
        return None

    return (
        query
        .replace(" and ", " AND ")
        .replace(" or ", " OR ")
        .replace(" not ", " NOT ")
    )


def _search_elasticsearch(elk_config, query):
    url = elk_config.get("url", "http://localhost:9200").rstrip("/")
    index = elk_config.get("index", "filebeat-*")
    lookback = elk_config.get("lookback", DEFAULT_LOOKBACK)
    sample_size = int(elk_config.get("sample_size", DEFAULT_SAMPLE_SIZE))

    body = {
        "size": sample_size,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": lookback
                            }
                        }
                    },
                    {
                        "query_string": {
                            "query": query
                        }
                    }
                ]
            }
        }
    }

    request = urllib.request.Request(
        url=f"{url}/{index}/_search",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    timeout = int(elk_config.get("timeout_seconds", 10))

    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    total = payload.get("hits", {}).get("total", {})

    if isinstance(total, dict):
        event_count = total.get("value", 0)
    else:
        event_count = total or 0

    sample_events = [
        _compact_event(hit.get("_source", {}))
        for hit in payload.get("hits", {}).get("hits", [])
    ]

    return {
        "event_count": event_count,
        "sample_events": sample_events,
    }


def check_elk(target, evidence_key):
    elk_config = target.get("elk", {})
    queries = target.get("log_queries", {})

    query = _normalize_query(queries.get(evidence_key))
    index = elk_config.get("index", "filebeat-*")

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

    if not query:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": None,
            "sample_events": [],
            "message": f"No ELK query found for evidence_key={evidence_key}."
        }

    try:
        search_result = _search_elasticsearch(elk_config, query)
        event_count = search_result["event_count"]

        return {
            "checked": True,
            "matched": event_count > 0,
            "event_count": event_count,
            "index": index,
            "query": query,
            "sample_events": search_result["sample_events"],
            "message": (
                f"Matched {event_count} event(s) in Elasticsearch."
                if event_count > 0
                else "No matching Elasticsearch events found in the configured lookback window."
            )
        }

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": f"Elasticsearch HTTP error {exc.code}: {error_body[:500]}"
        }

    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "sample_events": [],
            "message": f"Elasticsearch check failed: {exc}"
        }

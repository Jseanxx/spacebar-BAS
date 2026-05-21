import base64
import json
import urllib.error
import urllib.request


DEFAULT_ELK_URL = "http://127.0.0.1:9200"
DEFAULT_LOOKBACK = "now-15m"
DEFAULT_SAMPLE_SIZE = 3


def get_dataset(target, key):
    return target.get("elk", {}).get("datasets", {}).get(key)


def has_capability(target, capability):
    return capability in set(target.get("capabilities", []))


def build_dataset_query(target, dataset_key, body):
    dataset = get_dataset(target, dataset_key)
    if not dataset:
        return None

    return f'data_stream.dataset:"{dataset}" AND ({body})'


def build_auto_query(target, evidence_key):
    """
    target의 로그 소스 메타데이터로 탐지 쿼리를 자동 생성합니다.

    target.log_queries에 정확한 query가 있으면 resolve_query가 그 값을 우선 사용하고,
    없을 때만 이 fallback이 동작합니다.
    """

    if evidence_key == "kube_resource_discovery":
        return build_dataset_query(
            target,
            "kubernetes_audit",
            'objectRef.resource:"namespaces" OR objectRef.resource:"pods" OR objectRef.resource:"deployments" OR objectRef.resource:"services" OR objectRef.resource:"ingresses"',
        )

    if evidence_key == "kube_secret_access":
        return build_dataset_query(target, "kubernetes_audit", 'objectRef.resource:"secrets"')

    if evidence_key == "kube_pod_exec":
        return build_dataset_query(target, "kubernetes_audit", "requestURI:*exec*")

    if evidence_key == "kube_deploy_collector":
        return build_dataset_query(target, "kubernetes_audit", 'objectRef.resource:"pods"')

    if evidence_key == "kube_rbac_addition":
        return build_dataset_query(
            target,
            "kubernetes_audit",
            'objectRef.resource:"serviceaccounts" OR objectRef.resource:"roles" OR objectRef.resource:"rolebindings"',
        )

    if evidence_key == "local_data_staging":
        return build_dataset_query(target, "attacker_auditd", "file.path:*stage* OR file.path:*sb05_stage*")

    if evidence_key == "archive_staged_data":
        return build_dataset_query(target, "attacker_auditd", 'process.name:"zip" OR process.name:"tar"')

    if evidence_key == "s3_exfiltration":
        return build_dataset_query(target, "aws_cloudtrail", 'eventSource:"s3.amazonaws.com"')

    if evidence_key == "jenkins_to_app_ssh" and has_capability(target, "auth_log"):
        app = target.get("app", {})
        host = app.get("host")
        user = app.get("ssh_user", "deploy")
        host_clause = f' AND message:"{host}"' if host else ""
        return f'message:"Accepted publickey for {user}"{host_clause}'

    if evidence_key == "app_directory_discovery" and has_capability(target, "auditd"):
        app_path = target.get("app", {}).get("base_path", "/opt/spacebar-booking")
        return f'event.module:"auditd" AND event.original:"{app_path}"'

    return None


def resolve_query(target, evidence_key):
    queries = target.get("log_queries", {})
    configured_query = queries.get(evidence_key)

    if configured_query:
        return configured_query, "configured"

    generated_query = build_auto_query(target, evidence_key)
    if generated_query:
        return generated_query, "generated"

    return None, "missing"


def normalize_query(query):
    if not query:
        return None

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
        "objectRef.resource",
        "objectRef.namespace",
        "verb",
        "user.username",
    ]

    compacted = {}

    for field in fields:
        value = _get_nested_value(source, field) if "." in field else source.get(field)

        if value not in (None, "", [], {}):
            compacted[field] = value

    return compacted


def search_elasticsearch(elk_config, query):
    url = elk_config.get("url", DEFAULT_ELK_URL).rstrip("/")
    index = elk_config.get("index", "logs-*")
    lookback = elk_config.get("lookback", DEFAULT_LOOKBACK)
    sample_size = int(elk_config.get("sample_size", DEFAULT_SAMPLE_SIZE))
    username = elk_config.get("username")
    password = elk_config.get("password")

    payload = {
        "size": sample_size,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "date",
                }
            }
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": lookback,
                            }
                        }
                    },
                    {
                        "query_string": {
                            "query": normalize_query(query),
                            "analyze_wildcard": True,
                        }
                    },
                ]
            }
        },
    }

    headers = {
        "Content-Type": "application/json",
    }

    auth_header = build_auth_header(username, password)
    if auth_header:
        headers["Authorization"] = auth_header

    request = urllib.request.Request(
        url=f"{url}/{index}/_search",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    timeout = int(elk_config.get("timeout_seconds", 10))

    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))

    hits = result.get("hits", {})
    total = hits.get("total", {})
    event_count = total.get("value", 0) if isinstance(total, dict) else total or 0
    sample_events = [
        _compact_event(hit.get("_source", {}))
        for hit in hits.get("hits", [])
    ]

    return {
        "event_count": event_count,
        "sample_events": sample_events,
    }


def check_elk(target, evidence_key):
    elk_config = target.get("elk", {})
    index = elk_config.get("index", "logs-*")
    query, query_source = resolve_query(target, evidence_key)

    if not elk_config.get("enabled", False):
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "query_source": query_source,
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
            "query_source": query_source,
            "sample_events": [],
            "message": f"No ELK query configured for evidence key: {evidence_key}",
        }

    try:
        result = search_elasticsearch(elk_config, query)
        return {
            "checked": True,
            "matched": result["event_count"] > 0,
            "event_count": result["event_count"],
            "index": index,
            "query": query,
            "query_source": query_source,
            "sample_events": result["sample_events"],
            "message": f"Elasticsearch live check completed against {elk_config.get('url', DEFAULT_ELK_URL)}.",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "query_source": query_source,
            "sample_events": [],
            "message": f"Elasticsearch live check failed: {exc}",
        }

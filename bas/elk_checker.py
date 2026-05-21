import base64
import json
import os
import urllib.error
import urllib.request


DEFAULT_ELK_URL = "http://127.0.0.1:9200"


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

    정확한 환경별 query가 target.log_queries에 있으면 그 값을 우선 사용하고,
    없을 때만 이 fallback을 사용합니다.
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

    query, query_source = resolve_query(target, evidence_key)
    index = elk_config.get("index", "logs-*")

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
            "query_source": query_source,
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
            "query_source": query_source,
            "sample_events": [],
            "message": f"Elasticsearch live check failed: {exc}",
        }

import base64
from datetime import datetime, timedelta
import json
import os
import urllib.error
import urllib.request


DEFAULT_ELK_URL = "http://127.0.0.1:9200"
DEFAULT_LOOKBACK_MINUTES = 120


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


def resolve_alert_query(target, evidence_key):
    queries = target.get("alert_queries", {})
    configured_query = queries.get(evidence_key)

    if configured_query:
        return configured_query, "configured"

    rule_prefix = target.get("elk", {}).get("alert_rule_prefix")
    if rule_prefix and evidence_key:
        return (
            f'campaign.id:"SB-07" AND '
            f'(rule.id:"{rule_prefix}*" OR hanguel.rule_id:"{rule_prefix}*" OR '
            f'alert.rule_id:"{rule_prefix}*" OR detection.rule_id:"{rule_prefix}*" OR '
            f'kibana.alert.rule.name:"{rule_prefix}*")'
        ), "generated"

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


def parse_iso_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def build_time_filter(time_window=None):
    if time_window:
        started_at = parse_iso_datetime(time_window.get("started_at"))
        finished_at = parse_iso_datetime(time_window.get("finished_at"))
        before_seconds = int(os.environ.get("BAS_ELK_WINDOW_BEFORE_SECONDS", "30") or "30")
        after_seconds = int(os.environ.get("BAS_ELK_WINDOW_AFTER_SECONDS", "300") or "300")

        if started_at:
            bounds = {
                "gte": (started_at - timedelta(seconds=max(0, before_seconds))).isoformat(),
            }
            if finished_at:
                bounds["lte"] = (finished_at + timedelta(seconds=max(0, after_seconds))).isoformat()
            else:
                bounds["lte"] = "now"

            return {
                "range": {
                    "@timestamp": bounds,
                }
            }

    raw_minutes = os.environ.get("BAS_ELK_LOOKBACK_MINUTES", str(DEFAULT_LOOKBACK_MINUTES))

    try:
        minutes = int(raw_minutes)
    except (TypeError, ValueError):
        minutes = DEFAULT_LOOKBACK_MINUTES

    if minutes <= 0:
        return None

    return {
        "range": {
            "@timestamp": {
                "gte": f"now-{minutes}m",
                "lte": "now",
            }
        }
    }


def search_elasticsearch(elk_url, index, query, username=None, password=None, time_window=None):
    filters = [
        {
            "query_string": {
                "query": normalize_query(query),
                "analyze_wildcard": True,
            }
        }
    ]

    time_filter = build_time_filter(time_window=time_window)
    if time_filter:
        filters.append(time_filter)

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
            "bool": {
                "filter": filters,
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
        event = source.get("event") if isinstance(source.get("event"), dict) else {}
        agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
        host = source.get("host") if isinstance(source.get("host"), dict) else {}
        rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
        hanguel = source.get("hanguel") if isinstance(source.get("hanguel"), dict) else {}
        alert = source.get("alert") if isinstance(source.get("alert"), dict) else {}
        detection = source.get("detection") if isinstance(source.get("detection"), dict) else {}
        kibana = source.get("kibana") if isinstance(source.get("kibana"), dict) else {}
        winlog_root = source.get("winlog") if isinstance(source.get("winlog"), dict) else {}
        winlog = winlog_root.get("event_data") if isinstance(winlog_root.get("event_data"), dict) else {}
        object_ref = source.get("objectRef") if isinstance(source.get("objectRef"), dict) else {}
        user = source.get("user") if isinstance(source.get("user"), dict) else {}
        kibana_alert = kibana.get("alert") if isinstance(kibana.get("alert"), dict) else {}
        kibana_rule = kibana_alert.get("rule") if isinstance(kibana_alert.get("rule"), dict) else {}
        samples.append({
            "@timestamp": source.get("@timestamp"),
            "host": host.get("name"),
            "agent": agent.get("name"),
            "event": event.get("action") or source.get("verb"),
            "event_code": event.get("code"),
            "rule": (
                rule.get("id")
                or rule.get("name")
                or hanguel.get("rule_id")
                or alert.get("rule_id")
                or detection.get("rule_id")
                or kibana_rule.get("name")
            ),
            "resource": object_ref.get("resource"),
            "namespace": object_ref.get("namespace"),
            "requestURI": source.get("requestURI"),
            "user": user.get("username"),
            "image": winlog.get("Image") or winlog.get("NewProcessName") or winlog.get("SourceImage"),
            "command_line": winlog.get("CommandLine") or winlog.get("ProcessCommandLine"),
            "target": winlog.get("TargetImage") or winlog.get("TargetFilename"),
        })

    return samples


def run_live_check(elk_config, index, query, query_source, execution_context=None, time_window=None):
    if not query:
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "query_source": query_source,
            "sample_events": [],
            "message": "No query configured.",
        }

    elk_url = elk_config.get("url") or os.environ.get("BAS_ELK_URL", DEFAULT_ELK_URL)
    username = (
        elk_config.get("username")
        or os.environ.get(elk_config.get("username_env", ""))
        or os.environ.get("BAS_ELK_USERNAME")
    )
    password = (
        elk_config.get("password")
        or os.environ.get(elk_config.get("password_env", ""))
        or os.environ.get("BAS_ELK_PASSWORD")
    )

    try:
        result = search_elasticsearch(elk_url, index, query, username, password, time_window=time_window)
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
            "execution_context": execution_context or {},
            "time_window": time_window or {},
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
            "execution_context": execution_context or {},
            "time_window": time_window or {},
            "sample_events": [],
            "message": f"Elasticsearch live check failed: {exc}",
        }


def check_elk(target, evidence_key, execution_context=None):
    elk_config = target.get("elk", {})
    execution_context = execution_context or {}
    time_window = execution_context.get("time_window") or {}

    query, query_source = resolve_query(target, evidence_key)
    index = elk_config.get("index", "logs-*")
    alert_query, alert_query_source = resolve_alert_query(target, evidence_key)
    alert_index = elk_config.get("alert_index", ".alerts-security.alerts-default")

    if not elk_config.get("enabled", False):
        return {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": index,
            "query": query,
            "query_source": query_source,
            "alert_check": {
                "checked": False,
                "matched": None,
                "event_count": None,
                "index": alert_index,
                "query": alert_query,
                "query_source": alert_query_source,
                "sample_events": [],
                "message": "ELK check is disabled.",
            },
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
            "alert_check": {
                "checked": False,
                "matched": None,
                "event_count": None,
                "index": alert_index,
                "query": alert_query,
                "query_source": alert_query_source,
                "sample_events": [],
                "message": "Source query is missing, alert query was not executed.",
            },
            "sample_events": [],
            "message": f"No ELK query configured for evidence key: {evidence_key}",
        }

    source_check = run_live_check(
        elk_config,
        index,
        query,
        query_source,
        execution_context=execution_context,
        time_window=time_window,
    )

    execution_marker = execution_context.get("execution_marker")
    if execution_marker:
        escaped_marker = str(execution_marker).replace('"', '\\"')
        marker_query = (
            f'spacebar.bas.marker:"{escaped_marker}" OR '
            f'bas.marker:"{escaped_marker}" OR '
            f'labels.spacebar_marker:"{escaped_marker}" OR '
            f'"SPACEBAR_BAS_MARKER={escaped_marker}" OR '
            f'"{escaped_marker}"'
        )
        source_check["marker_check"] = run_live_check(
            elk_config,
            index,
            marker_query,
            "execution_marker",
            execution_context=execution_context,
            time_window=time_window,
        )

    if alert_query:
        source_check["alert_check"] = run_live_check(
            elk_config,
            alert_index,
            alert_query,
            alert_query_source,
            execution_context=execution_context,
            time_window=time_window,
        )
    else:
        source_check["alert_check"] = {
            "checked": False,
            "matched": None,
            "event_count": None,
            "index": alert_index,
            "query": alert_query,
            "query_source": alert_query_source,
            "sample_events": [],
            "message": f"No alert query configured for evidence key: {evidence_key}",
        }

    return source_check

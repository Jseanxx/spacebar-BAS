from pathlib import Path
import argparse
import os
import sys
import json
import time
import urllib.error
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

from bas.controller import run_campaign

def parse_simple_yaml(path):
    """
    BasAgent 설정 파일을 읽는 최소 YAML 파서입니다.

    현재 config.yaml은 key: value 형태만 사용하므로 외부 yaml 패키지 없이 처리합니다.
    나중에 설정 구조가 복잡해지면 PyYAML로 바꾸면 됩니다.
    """

    config = {}

    if not path.exists():
        return config

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            config[key.strip().lstrip("\ufeff")] = value.strip()

    return config

def load_config(config_path=CONFIG_PATH):
    config = {
        "agent_id": "bas-agent",
        "campaign_agent_id": "local-campaign-agent",
        "display_name": "BasAgent",
        "collector_type": "unknown",
        "agent_role": "",
        "asset_id": "",
        "segment_id": "",
        "hostname": "",
        "platform": "",
        "capabilities": "",
        "controls": "",
        "safety_mode": "",
        "controller_url": "http://127.0.0.1:8000",
        "controller_urls": "",
        "interval_seconds": "5",
        "execution_mode": "simulation",
    }

    config.update(parse_simple_yaml(config_path))
    config["interval_seconds"] = int(config.get("interval_seconds", 5))

    return config


def parse_csv_list(value):
    return [
        item.strip()
        for item in str(value or "").split(",")
        if item.strip()
    ]


def parse_controller_urls(config):
    urls = []

    for key in ("controller_url", "controller_urls"):
        for item in parse_csv_list(config.get(key)):
            normalized = item.rstrip("/")
            if normalized and normalized not in urls:
                urls.append(normalized)

    return urls or ["http://127.0.0.1:8000"]


def request_json(method, url, payload=None):
    """
    BasAgent가 Controller API와 통신하기 위한 공통 함수입니다.

    외부 requests 패키지 없이 Python 표준 라이브러리만 사용합니다.
    그래서 설치 환경 차이를 줄일 수 있습니다.
    """

    body = None
    headers = {
        "Content-Type": "application/json",
    }

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method=method,
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        response_body = response.read().decode("utf-8")

    if not response_body:
        return {}

    return json.loads(response_body)


class BasAgent:
    """
    BasAgent는 CampaignAgent 환경 안에 설치되는 BAS 실행 에이전트입니다.

    역할:
    - 중앙 Controller에 등록합니다.
    - 주기적으로 heartbeat를 보냅니다.
    - 자신에게 할당된 Job을 가져옵니다.
    - CampaignRunner를 통해 캠페인을 실행합니다.
    - 실행 결과를 Controller에 업로드합니다.
    """

    def __init__(self, config):
        self.config = config
        self.agent_id = config["agent_id"]
        self.controller_urls = parse_controller_urls(config)
        self.controller_url = self.controller_urls[0]
        self.interval_seconds = config["interval_seconds"]
        self.execution_mode = config["execution_mode"]

    def run_forever(self):
        self.register()

        while True:
            try:
                self.heartbeat()
                job = self.get_next_job()

                if job:
                    self.execute_job(job)

            except urllib.error.URLError as exc:
                print(f"[!] Controller connection failed: {exc}")

            except Exception as exc:
                print(f"[!] BasAgent error: {exc}")

            time.sleep(self.interval_seconds)

    def request_controller(self, method, path, payload=None):
        errors = []
        ordered_urls = [self.controller_url] + [
            url for url in self.controller_urls
            if url != self.controller_url
        ]

        for controller_url in ordered_urls:
            try:
                response = request_json(method, f"{controller_url}{path}", payload)
                self.controller_url = controller_url
                return response
            except urllib.error.URLError as exc:
                errors.append(f"{controller_url}: {exc}")

        raise urllib.error.URLError("; ".join(errors))

    def register(self):
        payload = {
            "agent_id": self.agent_id,
            "campaign_agent_id": self.config["campaign_agent_id"],
            "display_name": self.config["display_name"],
            "collector_type": self.config["collector_type"],
            "agent_role": self.config.get("agent_role") or None,
            "asset_id": self.config.get("asset_id") or None,
            "segment_id": self.config.get("segment_id") or None,
            "hostname": self.config.get("hostname") or None,
            "platform": self.config.get("platform") or None,
            "execution_mode": self.config.get("execution_mode") or None,
            "safety_mode": self.config.get("safety_mode") or None,
            "capabilities": parse_csv_list(self.config.get("capabilities")),
            "controls": parse_csv_list(self.config.get("controls")),
        }

        response = self.request_controller(
            "POST",
            "/agents/register",
            payload,
        )

        print(f"[+] Registered BasAgent: {response.get('agent', {}).get('agent_id')} @ {self.controller_url}")

    def heartbeat(self):
        self.request_controller(
            "POST",
            f"/agents/{self.agent_id}/heartbeat",
            {
                "status": "online",
            },
        )

    def get_next_job(self):
        response = self.request_controller(
            "GET",
            f"/agents/{self.agent_id}/jobs/next",
        )

        return response.get("job")

    def execute_job(self, job):
        job_id = job["job_id"]

        print(f"[+] Job received: {job_id}")

        try:
            execution_mode = job.get("execution_mode") or self.execution_mode

            if execution_mode not in ("simulation", "real"):
                raise RuntimeError(
                    f"Unsupported execution_mode: {execution_mode}. "
                    "Allowed modes: simulation, real."
                )
            previous_defer_elk = os.environ.get("BAS_DEFER_ELK_CHECKS")
            previous_agent_role = os.environ.get("BAS_AGENT_ROLE")
            previous_allow_real = os.environ.get("BAS_ALLOW_REAL_EXECUTION")
            if job.get("defer_elk_checks", False):
                os.environ["BAS_DEFER_ELK_CHECKS"] = "1"
            if self.config.get("agent_role"):
                os.environ["BAS_AGENT_ROLE"] = self.config["agent_role"]
            if execution_mode == "real" and self.config.get("safety_mode") == "approval_required":
                os.environ.setdefault("BAS_ALLOW_REAL_EXECUTION", "1")

            try:
                result, output_path = run_campaign(
                    campaign_id=job["campaign_id"],
                    selected_orders=job.get("selected_orders"),
                    selected_steps=job.get("selected_steps"),
                    include_normal=job.get("include_normal", True),
                    execution_mode=execution_mode,
                )
            finally:
                if previous_defer_elk is None:
                    os.environ.pop("BAS_DEFER_ELK_CHECKS", None)
                else:
                    os.environ["BAS_DEFER_ELK_CHECKS"] = previous_defer_elk
                if previous_agent_role is None:
                    os.environ.pop("BAS_AGENT_ROLE", None)
                else:
                    os.environ["BAS_AGENT_ROLE"] = previous_agent_role
                if previous_allow_real is None:
                    os.environ.pop("BAS_ALLOW_REAL_EXECUTION", None)
                else:
                    os.environ["BAS_ALLOW_REAL_EXECUTION"] = previous_allow_real

            print(f"[+] Job completed: {job_id}")
            print(f"[+] Result saved: {output_path}")

            self.submit_result(
                job_id=job_id,
                status="completed",
                execution_id=result.get("execution_id"),
                result=result,
                error=None,
            )
        
        except Exception as exc:
            print(f"[!] Job failed: {job_id}: {exc}")

            self.submit_result(
                job_id=job_id,
                status="failed",
                execution_id=None,
                result=None,
                error=str(exc),
            )

    def submit_result(self, job_id, status, execution_id, result, error):
        payload = {
            "status": status,
            "execution_id": execution_id,
            "result": result,
            "error": error,
        }

        self.request_controller(
            "POST",
            f"/agents/{self.agent_id}/jobs/{job_id}/result",
            payload,
        )


def main():
    parser = argparse.ArgumentParser(description="BasAgent runtime")
    parser.add_argument("--config", default=str(CONFIG_PATH))
    parser.add_argument(
        "--execution-mode",
        choices=["simulation", "real"],
        default=None,
        help="Override execution_mode from config.yaml for this run.",
    )
    args = parser.parse_args()

    config = load_config(Path(args.config))

    if args.execution_mode:
        config["execution_mode"] = args.execution_mode

    agent = BasAgent(config=config)
    agent.run_forever()

if __name__ == "__main__":
    main()

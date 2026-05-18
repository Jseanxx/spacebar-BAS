from pathlib import Path
import argparse
import sys
import json
import time
import urllib.error
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bas.controller import run_campaign


DEFAULT_AGENT_ID = "SB05-bas-agent"
DEFAULT_CONTROLLER_URL = "http://127.0.0.1:8000"


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

    def __init__(self, agent_id, controller_url, interval_seconds=5):
        self.agent_id = agent_id
        self.controller_url = controller_url.rstrip("/")
        self.interval_seconds = interval_seconds

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

    def register(self):
        payload = {
            "agent_id": self.agent_id,
            "campaign_agent_id": "SB-05",
            "display_name": self.agent_id,
            "collector_type": "elastic_agent",
        }

        response = request_json(
            "POST",
            f"{self.controller_url}/agents/register",
            payload,
        )

        print(f"[+] Registered BasAgent: {response.get('agent', {}).get('agent_id')}")

    def heartbeat(self):
        request_json(
            "POST",
            f"{self.controller_url}/agents/{self.agent_id}/heartbeat",
            {
                "status": "online",
            },
        )

    def get_next_job(self):
        response = request_json(
            "GET",
            f"{self.controller_url}/agents/{self.agent_id}/jobs/next",
        )

        return response.get("job")

    def execute_job(self, job):
        job_id = job["job_id"]

        print(f"[+] Job received: {job_id}")

        try:
            result, output_path = run_campaign(
                campaign_id=job["campaign_id"],
                selected_orders=job.get("selected_orders"),
                include_normal=job.get("include_normal", True),
            )

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

        request_json(
            "POST",
            f"{self.controller_url}/agents/{self.agent_id}/jobs/{job_id}/result",
            payload,
        )


def main():
    parser = argparse.ArgumentParser(description="BasAgent runtime")
    parser.add_argument("--agent-id", default=DEFAULT_AGENT_ID)
    parser.add_argument("--controller-url", default=DEFAULT_CONTROLLER_URL)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    agent = BasAgent(
        agent_id=args.agent_id,
        controller_url=args.controller_url,
        interval_seconds=args.interval,
    )

    agent.run_forever()


if __name__ == "__main__":
    main()
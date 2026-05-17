# 컨트롤러 호출 (bas/controller.py)

import argparse
import json

from bas.controller import run_campaign


def main():
    parser = argparse.ArgumentParser(description="Mini BAS campaign runner")
    parser.add_argument("--campaign", default="SB-05", help="Campaign ID to run")
    args = parser.parse_args()

    result, output_path = run_campaign(args.campaign)

    print(f"[+] Campaign executed: {result['campaign_id']}")
    print(f"[+] Execution ID: {result['execution_id']}")
    print(f"[+] Result saved: {output_path}")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

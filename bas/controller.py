# 핵심 실행 / 캠페인 읽고, 모듈 실행, 결과모아서 저장
"""
1. execution_id 생성
2. campaign YAML 읽기
3. flow를 order 순서대로 정렬
4. 각 step마다 target YAML 읽기
5. step에 적힌 모듈 import
6. module.run() 실행
7. ELK 확인 정보 붙이기
8. steps 결과에 저장
9. 마지막에 JSON 파일 저장
"""


from datetime import datetime, timezone, timedelta
import uuid

from bas.loader import load_campaign, load_target
from bas.module_loader import load_module
from bas.result_writer import write_run_result
from bas.elk_checker import check_elk


KST = timezone(timedelta(hours=9))


def now_kst():
    return datetime.now(KST).isoformat(timespec="seconds")

def resolve_dependencies(steps, requested_orders):
    step_by_order = {step.get("order"): step for step in steps}
    resolved = set(requested_orders or [])

    def visit(order):
        step = step_by_order.get(order)
        if not step:
            return

        for dependency in step.get("depends_on_orders", []):
            if dependency not in resolved:
                resolved.add(dependency)
                visit(dependency)

    for order in list(resolved):
        visit(order)

    return sorted(resolved)


def run_campaign(campaign_id, selected_orders=None, include_normal=True):
    execution_id = f"exec-{datetime.now(KST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    campaign = load_campaign(campaign_id)
    steps = sorted(campaign.get("flow", []), key=lambda item: item.get("order", 0))

    requested_orders = sorted(selected_orders or [])
    auto_included_orders = []
    final_orders = None

    if requested_orders:
        resolved_attack_orders = resolve_dependencies(steps, requested_orders)
        auto_included_orders = [
            order for order in resolved_attack_orders
            if order not in requested_orders
        ]

        max_order = max(resolved_attack_orders)

        final_orders = set(resolved_attack_orders)

        if include_normal:
            for step in steps:
                if step.get("phase") == "normal" and step.get("order", 0) <= max_order:
                    final_orders.add(step.get("order"))

        steps = [
            step for step in steps
            if step.get("order") in final_orders
        ]



    run_result = {
        "execution_id": execution_id,
        "campaign_id": campaign.get("campaign_id"),
        "campaign_name": campaign.get("campaign_name"),
        "started_at": now_kst(),
        "steps": [],
        "requested_orders": requested_orders,
        "auto_included_orders": auto_included_orders,
        "final_orders": sorted(final_orders) if final_orders else None,
        "include_normal": include_normal,

    }

    for step in steps:
        target = load_target(step["target"])
        module = load_module(step["module"])

        step_started_at = now_kst()

        try:
            module_result = module.run(target=target, params=step.get("params", {}))
            status = module_result.get("status", "unknown")
            error = None
        except Exception as exc:
            module_result = {}
            status = "failed"
            error = str(exc)

        evidence_key = module_result.get("evidence_key")
        elk_result = check_elk(target, evidence_key) if evidence_key else None

        step_result = {
            "order": step.get("order"),
            "phase": step.get("phase"),
            "name": step.get("name"),
            "target_id": step.get("target"),
            "module": step.get("module"),
            "technique_id": step.get("technique_id"),
            "started_at": step_started_at,
            "finished_at": now_kst(),
            "status": status,
            "module_result": module_result,
            "elk_check": elk_result,
            "error": error
        }

        run_result["steps"].append(step_result)

    run_result["finished_at"] = now_kst()

    output_path = write_run_result(execution_id, run_result)
    return run_result, output_path

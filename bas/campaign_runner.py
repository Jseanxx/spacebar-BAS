from datetime import datetime, timezone, timedelta
import uuid

from bas.loader import load_campaign, load_target
from bas.module_loader import load_module
from bas.result_writer import write_run_result
from bas.elk_checker import check_elk


KST = timezone(timedelta(hours=9))


def now_kst():
    # 실행 결과와 step 시간을 한국 시간 기준으로 남기기 위한 공통 함수입니다.
    return datetime.now(KST).isoformat(timespec="seconds")


class CampaignRunner:
    """
    CampaignRunner는 하나의 BAS 캠페인을 실제로 실행하는 엔진입니다.

    용어 정리:
    - CampaignAgent: AWS에 올라간 각 vulnLab / 캠페인 환경
    - BasAgent: CampaignAgent 안에 설치되는 BAS 실행 에이전트
    - CampaignRunner: BasAgent 내부에서 campaign YAML을 실행하는 코드 엔진

    이 파일의 의미:
    - campaign YAML을 읽습니다.
    - selected_orders와 depends_on_orders를 기준으로 실행 범위를 계산합니다.
    - 각 module.run()을 호출합니다.
    - evidence_key 기준으로 ELK 확인 정보를 붙입니다.
    - outputs/runs/*.json에 실행 결과를 저장합니다.
    """

    def __init__(self, campaign_id, selected_orders=None, include_normal=True):
        self.campaign_id = campaign_id
        self.selected_orders = sorted(selected_orders or [])
        self.include_normal = include_normal
        self.execution_id = self._create_execution_id()

    def run(self):
        """
        캠페인 실행의 진입점입니다.

        지금은 Controller가 이 메서드를 직접 호출하지만,
        최종 구조에서는 BasAgent가 Job을 받은 뒤 이 메서드를 호출하게 됩니다.
        """
        campaign = load_campaign(self.campaign_id)
        all_steps = self._load_sorted_steps(campaign)

        selected_steps, auto_included_orders, final_orders = self._select_steps(all_steps)

        run_result = self._build_initial_result(
            campaign=campaign,
            auto_included_orders=auto_included_orders,
            final_orders=final_orders,
        )

        for step in selected_steps:
            step_result = self._execute_step(step)
            run_result["steps"].append(step_result)

        run_result["finished_at"] = now_kst()

        output_path = write_run_result(self.execution_id, run_result)
        return run_result, output_path

    def _create_execution_id(self):
        # 결과 파일명과 추적 ID로 사용됩니다. uuid 일부를 붙여 같은 초 실행 충돌을 줄입니다.
        timestamp = datetime.now(KST).strftime("%Y%m%d-%H%M%S")
        random_suffix = uuid.uuid4().hex[:6]
        return f"exec-{timestamp}-{random_suffix}"

    def _load_sorted_steps(self, campaign):
        # 중요한 줄: YAML 작성 순서가 아니라 order 값을 기준으로 실행 순서를 고정합니다.
        return sorted(campaign.get("flow", []), key=lambda item: item.get("order", 0))

    def _select_steps(self, steps):
        """
        실제 실행할 step 목록을 결정합니다.

        selected_orders가 비어 있으면 전체 캠페인을 실행합니다.
        selected_orders가 있으면 의존 공격 단계와 필요한 normal 단계를 자동 포함합니다.
        """
        if not self.selected_orders:
            return steps, [], None

        resolved_attack_orders = self._resolve_dependencies(steps, self.selected_orders)

        auto_included_orders = [
            order for order in resolved_attack_orders
            if order not in self.selected_orders
        ]

        max_order = max(resolved_attack_orders)
        final_orders = set(resolved_attack_orders)

        if self.include_normal:
            for step in steps:
                is_normal_step = step.get("phase") == "normal"
                is_before_attack = step.get("order", 0) <= max_order

                # 선택한 공격 단계 이전의 정상 행위를 함께 실행해 baseline 맥락을 유지합니다.
                if is_normal_step and is_before_attack:
                    final_orders.add(step.get("order"))

        selected_steps = [
            step for step in steps
            if step.get("order") in final_orders
        ]

        return selected_steps, auto_included_orders, sorted(final_orders)

    def _resolve_dependencies(self, steps, requested_orders):
        """
        depends_on_orders를 따라가며 필요한 선행 공격 단계를 자동 포함합니다.

        예: 사용자가 6번만 선택해도 6번이 3번, 4번에 의존하면 3번과 4번도 포함됩니다.
        """
        step_by_order = {
            step.get("order"): step
            for step in steps
        }

        resolved = set(requested_orders or [])

        def visit(order):
            step = step_by_order.get(order)

            # preview API에서 order 검증을 먼저 하므로 일반적으로 여기까지 오지 않습니다.
            if not step:
                return

            for dependency in step.get("depends_on_orders", []):
                if dependency not in resolved:
                    resolved.add(dependency)
                    visit(dependency)

        for order in list(resolved):
            visit(order)

        return sorted(resolved)

    def _build_initial_result(self, campaign, auto_included_orders, final_orders):
        bas_agent = self._build_bas_agent_metadata()

        return {
            "execution_id": self.execution_id,
            "campaign_id": campaign.get("campaign_id"),
            "campaign_name": campaign.get("campaign_name"),
            "started_at": now_kst(),
            "finished_at": None,
            "bas_agent": bas_agent,

            # 기존 프론트/테스트 호환용 필드입니다.
            # 새 코드에서는 bas_agent를 기준으로 사용하면 됩니다.
            "agent": bas_agent,

            "requested_orders": self.selected_orders,
            "auto_included_orders": auto_included_orders,
            "final_orders": final_orders,
            "include_normal": self.include_normal,
            "steps": [],
        }

    def _build_bas_agent_metadata(self):
        return {
            "type": "local_bas_agent",
            "runner": "campaign_runner",
            "mode": "simulation",
            "policy": {
                "on_step_failure": "continue",
                "include_normal": self.include_normal,
                "resolve_dependencies": True,
            },
        }

    def _execute_step(self, step):
        """
        단일 step을 실행합니다.

        이 함수가 실제 모듈 실행 지점입니다.
        target 로딩, module import, module.run(), ELK 확인, 결과 정리를 처리합니다.
        """
        step_started_at = now_kst()

        try:
            target = load_target(step["target"])
            module = load_module(step["module"])

            # 중요한 줄: 각 공격/정상 행위 모듈의 run()이 실제로 호출되는 지점입니다.
            module_result = module.run(
                target=target,
                params=step.get("params", {}),
            )

            status = module_result.get("status", "unknown")
            error = None

        except Exception as exc:
            target = {}
            module_result = {}
            status = "failed"
            error = str(exc)

        evidence_key = module_result.get("evidence_key")

        # evidence_key가 있어야 target YAML의 log_queries 중 어떤 쿼리를 쓸지 결정할 수 있습니다.
        elk_result = check_elk(target, evidence_key) if evidence_key else None

        return {
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
            "error": error,
        }

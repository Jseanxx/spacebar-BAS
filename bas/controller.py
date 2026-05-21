from bas.campaign_runner import CampaignRunner


def run_campaign(
    campaign_id,
    selected_orders=None,
    selected_steps=None,
    include_normal=True,
    execution_mode="simulation",
):
    """
    BAS 캠페인 실행용 외부 진입점입니다.

    execution_mode:
    - simulation: 실제 명령 없이 시뮬레이션 결과를 반환합니다.
    - real: real 지원 모듈만 실제 명령을 실행합니다.
    """

    runner = CampaignRunner(
        campaign_id=campaign_id,
        selected_orders=selected_orders,
        selected_steps=selected_steps,
        include_normal=include_normal,
        execution_mode=execution_mode,
    )

    return runner.run()

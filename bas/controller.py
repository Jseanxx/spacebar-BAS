from bas.campaign_runner import CampaignRunner


def run_campaign(campaign_id, selected_orders=None, include_normal=True):
    """
    BAS 캠페인 실행용 내부 진입점입니다.

    이 파일의 의미:
    - main.py, api.py는 기존처럼 run_campaign()만 호출합니다.
    - 실제 캠페인 실행은 CampaignRunner가 담당합니다.
    - 나중에 BasAgent가 생겨도 이 함수 이름을 유지하면 기존 호출부를 덜 바꿀 수 있습니다.
    """

    # 중요한 줄: Controller 직접 실행을 CampaignRunner 실행으로 위임합니다.
    runner = CampaignRunner(
        campaign_id=campaign_id,
        selected_orders=selected_orders,
        include_normal=include_normal,
    )

    return runner.run()

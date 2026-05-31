# SB-AD BAS 멘토 피드백 반영 구현 체크리스트

## 0. 문서 목적

이 문서는 5주차 2회차 멘토링에서 멘토님이 설명한 BAS의 핵심 의도와, 이후 정리된 6주차 방향성인 **자산 현황, 보안 솔루션/탐지 체계, 공격 맵**을 현재 SB-AD BAS 최신본에 어떻게 반영할지 정리한 구현 체크리스트다.

현재 프로젝트는 실제 기업 환경처럼 EDR, NDR, WAF, 방화벽을 모두 구축한 상태가 아니므로, 상용 보안 솔루션 검증 대신 **ELK 기반 탐지 체계 검증형 BAS**로 범위를 명확히 잡는다.

발표와 문서에서 사용할 핵심 문장:

> Spacebar BAS는 공격 Technique을 실행한 뒤, 해당 행위가 SB-AD 자산 환경에서 어떤 로그로 남고 ELK/Kibana 탐지룰에 의해 Alert로 전환되는지 검증하는 ELK 탐지 체계 검증형 BAS입니다.

## 1. 멘토님 피드백에서 뽑은 구현 요구사항

### 1.1 멘토님 의도

- BAS는 단순히 공격 명령을 실행하는 도구가 아니다.
- BAS에는 자산 정보가 있어야 한다.
- BAS에는 네트워크 구간 정보가 있어야 한다.
- 각 자산과 구간에 어떤 보안 솔루션 또는 보안 통제가 적용되어 있는지 보여야 한다.
- 공격이 어느 자산에서 어느 자산으로 전달되는지 보여야 한다.
- Agent는 공격 시작점과 도착점에서 공격이 어디까지 도달했는지 확인하는 기준이 된다.
- 공격이 목표 자산까지 도달했다면 중간 보안 통제가 차단하지 못했다는 의미로 해석할 수 있다.
- 우리 프로젝트는 현실적으로 차단형 보안 솔루션 검증보다 로그 기반 탐지 및 대응 검증에 가깝다.
- 따라서 단기적으로는 공격 시뮬레이터와 ELK 탐지 검증을 완성하고, 장기적으로 자산/구간/보안 솔루션/Agent 기반 BAS로 확장하는 방향이 맞다.

### 1.2 우리 프로젝트식 해석

상용 BAS의 `보안 솔루션`을 현재 프로젝트에서는 다음과 같이 대체한다.

| 상용 BAS 관점 | SB-AD 프로젝트 적용 |
| --- | --- |
| EDR | Sysmon, Windows Security Log, PowerShell Logging |
| Log Forwarder | Winlogbeat |
| SIEM | ELK/Kibana |
| Detection Rule | Kibana Security Detection Rule |
| Network Boundary | AWS Security Group |
| Security Control Result | 원천 로그 확인, Alert 발생, 로그만 있음, 미탐 |

따라서 `탐지했다 = 차단했다`라고 단정하지 않고, **탐지 체계가 해당 공격 행위를 관찰하고 경보화할 수 있었다**라고 표현한다.

## 2. 현재 최신본에 이미 있는 기반

### 2.1 데이터 모델

- [x] `targets/SB-AD.yaml`에 `segments`가 있음
- [x] `targets/SB-AD.yaml`에 `assets`가 있음
- [x] `targets/SB-AD.yaml`에 `security_controls`가 있음
- [x] `targets/SB-AD.yaml`에 `attack_paths`가 있음
- [x] `targets/SB-AD.yaml`에 `log_queries`가 있음
- [x] `targets/SB-AD.yaml`에 `alert_queries`가 있음

### 2.2 백엔드

- [x] Agent 등록/heartbeat 구조가 있음
- [x] `/targets/{target_id}/asset-discovery`에서 target inventory와 agent registration을 합칠 수 있음
- [x] multi-agent operation 구조가 있음
- [x] step별 agent role 라우팅 구조가 있음
- [x] ELK source log / alert check 결과를 operation step에 붙이는 구조가 있음
- [x] report builder에 coverage, backlog, navigator layer 생성 구조가 있음

### 2.3 프론트엔드

- [x] 자산 맵 화면이 있음
- [x] Attacker, PC01, FS01, DC01, ELK 노드가 표시됨
- [x] Agent online/offline 상태 표시 기반이 있음
- [x] ELK 연동 상태 표시 기반이 있음
- [x] Technique Library, Execution Queue, Evidence 패널이 있음
- [x] Recent Detection 패널이 있음
- [x] 실행 중인 asset highlight 기반이 있음

## 3. P0: 멘토 피드백을 직접 반영하는 필수 구현

### 3.1 자산 현황을 BAS답게 보이게 만들기

목표:

자산을 단순 노드로 보여주는 것이 아니라, **이 자산이 어떤 역할이고 어떤 로그/탐지 체계로 검증되는지** 바로 보이게 한다.

체크리스트:

- [ ] 자산 노드 클릭 시 우측 또는 하단 상세 패널을 연다.
- [ ] 자산 상세 패널에 `asset_id`, `hostname`, `private_ip`, `public_ip`, `platform`, `role`, `segment_id`를 표시한다.
- [ ] 자산 상세 패널에 `agent_required`, `agent_role`, `agent status`, `last seen`을 표시한다.
- [ ] 자산 상세 패널에 연결된 control 목록을 표시한다.
- [ ] PC01에 `Sysmon`, `PowerShell Logging`, `Winlogbeat`, `Kibana Rule`을 표시한다.
- [ ] FS01에 `Sysmon`, `Windows Security Log`, `Winlogbeat`, `Kibana Rule`을 표시한다.
- [ ] DC01에 `Windows Security Log`, `AD Audit Log`, `Winlogbeat`, `Kibana Rule`을 표시한다.
- [ ] ELK에 `Kibana Detection Rules`, `Alert Index`, `winlogbeat-*`를 표시한다.
- [ ] 자산별 최근 실행 Technique 수를 표시한다.
- [ ] 자산별 Alert 발생 수를 표시한다.
- [ ] 자산별 로그만 확인된 Technique 수를 표시한다.
- [ ] 자산별 미탐 Technique 수를 표시한다.

수용 기준:

- [ ] 발표자가 PC01을 클릭했을 때 “PC01은 직원 PC 역할이고, PowerShell/WinRM 실행 흔적을 Sysmon과 PowerShell Log로 수집해 ELK에서 검증한다”고 설명할 수 있다.
- [ ] 발표자가 DC01을 클릭했을 때 “DC01에는 Agent를 설치하지 않고 AD 보안 이벤트를 관찰 대상으로 둔다”고 설명할 수 있다.
- [ ] 발표자가 ELK를 클릭했을 때 “ELK가 탐지 백엔드이며 Alert 발생 여부를 검증한다”고 설명할 수 있다.

### 3.2 공격 맵을 데이터 기반으로 바꾸기

목표:

현재 맵의 선을 단순 SVG 장식이 아니라 `targets/SB-AD.yaml`의 `attack_paths` 기반으로 표현한다.

체크리스트:

- [ ] `attack_paths`에 `path_id`를 추가한다.
- [ ] 각 path에 `source_asset_id`, `target_asset_id`, `label`, `techniques`를 유지한다.
- [ ] 각 path에 `expected_controls`를 추가한다.
- [ ] 각 path에 `expected_logs`를 추가한다.
- [ ] App에서 `target.attack_paths`를 읽어 path별 edge 데이터를 만든다.
- [ ] source/target asset position을 기준으로 edge를 계산하거나, 우선 고정 좌표 edge와 path_id를 연결한다.
- [ ] edge 위에 label을 표시한다.
- [ ] edge 위에 Technique badge를 표시한다.
- [ ] edge 위에 탐지 결과 badge를 표시한다.
- [ ] 실행 중인 path는 점선 화살표 애니메이션으로 표시한다.
- [ ] 완료된 path는 탐지 결과에 따라 색상을 바꾼다.

색상 규칙:

- [ ] `running`: 파랑 점선 애니메이션
- [ ] `detected`: 초록
- [ ] `logged_only`: 노랑
- [ ] `missed`: 빨강
- [ ] `not_run`: 회색
- [ ] `failed`: 어두운 빨강 또는 회색

수용 기준:

- [ ] `PC01 -> FS01` edge에 `T1021.006`, `T1059.001`, `T1105`가 보인다.
- [ ] `FS01 -> Attacker` edge에 `T1074.001`, `T1041`이 보인다.
- [ ] Technique 실행 후 해당 Technique이 속한 edge 상태가 바뀐다.
- [ ] 발표자가 “이 공격은 PC01에서 FS01로 이동했고, 이 구간에서는 WinRM/PowerShell 로그와 Kibana Rule로 검증한다”고 설명할 수 있다.

### 3.3 ELK 탐지 체계 패널 만들기

목표:

멘토님이 말한 보안 솔루션 검증 구조를 우리 환경에서는 ELK 탐지 체계 검증으로 대체한다.

체크리스트:

- [ ] 화면에 `ELK Detection Controls` 또는 `탐지 체계` 패널을 추가한다.
- [ ] 패널에 `Sysmon`, `Windows Security Log`, `PowerShell Logging`, `Winlogbeat`, `Kibana Detection Rules`를 표시한다.
- [ ] 각 control이 연결된 자산 수를 표시한다.
- [ ] 각 control이 사용된 Technique 수를 표시한다.
- [ ] 각 control의 상태를 `configured`, `verified`, `gap`, `planned`로 표시한다.
- [ ] 최신 run 기준으로 control별 탐지 결과를 집계한다.
- [ ] `Sysmon`: source log matched 수 표시
- [ ] `Kibana Rules`: alert matched 수 표시
- [ ] `Winlogbeat`: 로그 수집 성공 여부 표시

수용 기준:

- [ ] 화면만 보고도 “우리 프로젝트는 보안 솔루션 대신 ELK 기반 탐지 체계를 검증 대상으로 삼았다”는 구조가 드러난다.
- [ ] `Kibana Detection Rules`가 몇 개 Technique에서 Alert를 냈는지 보인다.
- [ ] 로그만 있고 Alert가 없는 경우 탐지룰 보완이 필요하다는 메시지가 보인다.

### 3.4 Technique 상세 증적 패널 만들기

목표:

멘토님이 말한 캠페인 페이지 3, 즉 실제 로그 증적을 BAS 화면에서 확인할 수 있게 한다.

체크리스트:

- [ ] Timeline 또는 Recent Detection에서 Technique 클릭 시 상세 패널을 연다.
- [ ] 상세 패널에 Technique ID와 이름을 표시한다.
- [ ] 실행 자산과 대상 자산을 표시한다.
- [ ] 실행 명령 요약을 표시한다.
- [ ] 기대 로그와 실제 로그 확인 여부를 표시한다.
- [ ] KQL source query를 표시한다.
- [ ] Kibana alert query를 표시한다.
- [ ] Alert rule name 또는 rule_id를 표시한다.
- [ ] event.code를 표시한다.
- [ ] host.name을 표시한다.
- [ ] timestamp를 표시한다.
- [ ] sample event 1개를 요약 표시한다.
- [ ] `원천 로그 확인`, `Alert 발생`, `로그만 확인`, `미탐` 상태를 명확히 표시한다.

수용 기준:

- [ ] T1021.006을 클릭하면 WinRM 관련 KQL과 Alert 결과가 보인다.
- [ ] T1003.001을 클릭하면 LSASS 접근 관련 KQL, event.code 10, rundll32/comsvcs 증거가 보인다.
- [ ] T1003.006을 클릭하면 DC01의 4662 / DCSync GUID 증거가 보인다.

### 3.5 결과 판정 모델 통일

목표:

실행 상태와 탐지 상태가 섞이지 않게 하고, BAS식 결과를 일관되게 보여준다.

체크리스트:

- [ ] 실행 상태와 탐지 상태를 분리한다.
- [ ] 실행 상태는 `queued`, `running`, `completed`, `failed`, `simulated`, `blocked`로 유지한다.
- [ ] 탐지 상태는 `detected`, `logged_only`, `alert_only`, `missed`, `not_checked`, `not_run`으로 통일한다.
- [ ] `detected`: source log와 alert가 모두 확인됨
- [ ] `logged_only`: source log는 있으나 alert 없음
- [ ] `alert_only`: alert는 있으나 source sample 부족
- [ ] `missed`: source log와 alert 모두 없음
- [ ] `not_checked`: ELK 확인 미수행
- [ ] `not_run`: 실행 전
- [ ] UI의 모든 badge에서 같은 색상/문구를 사용한다.
- [ ] report builder의 classification과 App의 `getDetectionStatus` 기준을 맞춘다.

수용 기준:

- [ ] 같은 결과가 맵, 타임라인, 증적 패널, 보고서에서 같은 상태로 보인다.
- [ ] `성공`과 `탐지 성공`이 혼동되지 않는다.

## 4. P1: 발표 완성도를 높이는 구현

### 4.1 공격 흐름 애니메이션

목표:

사용자가 Run을 눌렀을 때 공격이 자산 사이를 이동하는 느낌을 시각적으로 보여준다.

체크리스트:

- [ ] 실행 중인 step의 source asset과 target asset을 찾는다.
- [ ] 해당 edge에 움직이는 점선 또는 pulse animation을 적용한다.
- [ ] source asset node를 파랑으로 강조한다.
- [ ] target asset node를 도착지로 강조한다.
- [ ] step 완료 후 edge를 결과 색상으로 고정한다.
- [ ] 다음 step으로 넘어갈 때 다음 edge가 활성화된다.
- [ ] 실행 큐 순서와 맵 애니메이션 순서가 일치한다.

수용 기준:

- [ ] Run 클릭 후 Attacker -> PC01 -> FS01 -> Attacker/DC01 흐름이 눈으로 보인다.
- [ ] 멘토님이 보여준 Attack Map/Infection Map처럼 “공격 경로”가 직관적으로 보인다.

### 4.2 탐지 커버리지 점수

목표:

상용 BAS처럼 실행 결과를 숫자로 요약한다.

체크리스트:

- [ ] 최신 run 또는 operation 기준으로 전체 Technique 수를 계산한다.
- [ ] 실행 완료 Technique 수를 계산한다.
- [ ] `detected` 수를 계산한다.
- [ ] `logged_only` 수를 계산한다.
- [ ] `missed` 수를 계산한다.
- [ ] 탐지 커버리지를 계산한다.
- [ ] 로그 가시성을 계산한다.
- [ ] Alert 전환률을 계산한다.
- [ ] Overview에 score card를 배치한다.
- [ ] Report summary에도 같은 수치를 넣는다.

권장 지표:

- Detection Coverage: `detected / executed`
- Telemetry Coverage: `(detected + logged_only + alert_only) / executed`
- Alert Conversion Rate: `detected / (detected + logged_only)`
- Execution Rate: `completed / total`

수용 기준:

- [ ] 실행 후 “탐지 커버리지 70%”처럼 한눈에 볼 수 있다.
- [ ] 미탐이 발생했을 때 커버리지 점수가 내려간다.

### 4.3 보완 백로그 UI

목표:

BAS 결과가 “잘 됐다/안 됐다”에서 끝나지 않고, 무엇을 고쳐야 하는지까지 보여준다.

체크리스트:

- [ ] `report.backlog` 또는 report builder의 backlog 결과를 UI에서 읽는다.
- [ ] 우측 또는 하단에 `Detection Backlog` 패널을 만든다.
- [ ] backlog item에 priority를 표시한다.
- [ ] affected technique을 표시한다.
- [ ] affected host를 표시한다.
- [ ] gap reason을 표시한다.
- [ ] suggested action을 표시한다.
- [ ] suggested query를 표시한다.
- [ ] verification method를 표시한다.

수용 기준:

- [ ] 미탐 Technique이 발생하면 “KQL 조건 완화 필요”, “Winlogbeat 수집 채널 확인 필요” 같은 보완 항목이 생긴다.
- [ ] 발표자가 “BAS를 돌린 결과 무엇을 보완해야 하는지 자동으로 남긴다”고 설명할 수 있다.

### 4.4 실행 타임라인 고도화

목표:

공격 맵은 공간 구조, 타임라인은 시간 구조로 역할을 나눈다.

체크리스트:

- [ ] Timeline row에 실행 시작 시각을 표시한다.
- [ ] Timeline row에 완료 시각을 표시한다.
- [ ] Timeline row에 Alert 발생 시각을 표시한다.
- [ ] Timeline row에 source asset과 target asset을 표시한다.
- [ ] Timeline row에 Technique ID를 표시한다.
- [ ] Timeline row에 탐지 상태 badge를 표시한다.
- [ ] Timeline row 클릭 시 Technique 상세 증적 패널과 연결한다.

수용 기준:

- [ ] “공격자 동선”을 시간순으로 설명할 수 있다.
- [ ] DF/IR 보고서의 타임라인과 연결할 수 있다.

## 5. P2: 보고서 및 데모 완성도

### 5.1 HTML 결과 보고서 연결

목표:

BAS 실행 결과를 멘토링/발표 때 바로 보여줄 수 있는 HTML 보고서로 연결한다.

체크리스트:

- [ ] Run Detail 또는 Evidence 패널 상단에 `HTML 보고서 보기` 버튼을 추가한다.
- [ ] 버튼 클릭 시 최신 operation report artifact를 연다.
- [ ] report artifact가 없으면 생성 상태 또는 안내 메시지를 표시한다.
- [ ] 보고서 첫 화면에 캠페인 이름, 실행 시간, 자산 범위, 커버리지 점수를 표시한다.
- [ ] 보고서에 자산 맵 또는 공격 경로 요약을 넣는다.
- [ ] 보고서에 Technique별 탐지 결과 표를 넣는다.
- [ ] 보고서에 KQL 증거를 넣는다.
- [ ] 보고서에 Alert 증거를 넣는다.
- [ ] 보고서에 미탐 원인과 보완 backlog를 넣는다.

수용 기준:

- [ ] BAS 실행 후 클릭 한 번으로 결과 보고서를 확인할 수 있다.
- [ ] 보고서만 봐도 “어떤 자산에서 어떤 공격을 실행했고 ELK가 무엇을 탐지했는지” 알 수 있다.

### 5.2 발표용 Demo Mode

목표:

실제 Agent나 ELK가 완전히 준비되지 않아도, 멘토링/발표에서 흐름을 설명할 수 있게 한다.

체크리스트:

- [ ] Demo Mode 토글을 추가한다.
- [ ] Demo Mode에서는 미리 준비된 operation fixture를 불러온다.
- [ ] Demo Mode에서는 공격 흐름 애니메이션이 재생된다.
- [ ] Demo Mode에서는 detected/logged_only/missed 결과가 섞여 보인다.
- [ ] Demo Mode에서는 report preview가 열린다.
- [ ] Demo Mode임을 화면에 명확히 표시한다.

수용 기준:

- [ ] AWS/ELK 상태가 불안정해도 발표 흐름을 망치지 않는다.
- [ ] 실제 기능과 데모 데이터를 혼동하지 않게 표시된다.

## 6. 데이터 모델 수정 체크리스트

### 6.1 `targets/SB-AD.yaml`

- [ ] `attack_paths`에 `path_id` 추가
- [ ] `attack_paths`에 `expected_controls` 추가
- [ ] `attack_paths`에 `expected_logs` 추가
- [ ] 각 Technique step과 `attack_path_id` 연결
- [ ] 각 Technique step과 `source_asset_id`, `target_asset_id` 연결
- [ ] 각 Technique step과 `log_query_key`, `alert_query_key` 연결
- [ ] `security_controls`에 UI 표시용 `description` 추가
- [ ] `security_controls`에 `display_group` 추가
- [ ] `security_controls`에 `validated_by` 추가
- [ ] asset에 `log_sources` 추가
- [ ] asset에 `detection_rules` 추가
- [ ] asset에 `business_impact` 또는 `criticality_reason` 추가

### 6.2 Campaign YAML

- [ ] 각 flow step에 `source_asset_id` 추가
- [ ] 각 flow step에 `target_asset_id` 추가
- [ ] 각 flow step에 `attack_path_id` 추가
- [ ] 각 flow step에 `expected_result` 추가
- [ ] 각 flow step에 `evidence_fields` 추가
- [ ] 각 flow step에 `safe_demo_command`와 `real_command`를 분리할지 검토

### 6.3 Operation JSON

- [ ] final step에 `path_id` 저장
- [ ] final step에 `source_asset_id` 저장
- [ ] final step에 `target_asset_id` 저장
- [ ] final step에 `source_status` 저장
- [ ] final step에 `alert_status` 저장
- [ ] final step에 `detection_status` 저장
- [ ] final step에 `sample_events` 저장
- [ ] final step에 `first_seen_at`, `alert_seen_at` 저장
- [ ] final step에 `gap_reason` 저장
- [ ] final step에 `recommended_action` 저장

## 7. 프론트엔드 반영 체크리스트

### 7.1 `frontend/src/App.jsx`

- [ ] `attackPaths` useMemo 추가
- [ ] `pathStatusMap` useMemo 추가
- [ ] `assetStatsMap` useMemo 추가
- [ ] `controlStatsMap` useMemo 추가
- [ ] `selectedAsset` 상태 추가
- [ ] `selectedStep` 상태 추가
- [ ] asset node 클릭 시 `selectedAsset` 설정
- [ ] timeline row 클릭 시 `selectedStep` 설정
- [ ] edge 클릭 시 해당 path의 Technique 목록 표시
- [ ] Evidence 패널을 선택된 step 상세 중심으로 개편
- [ ] Overview에 coverage score 추가
- [ ] ELK 탐지 체계 패널 추가
- [ ] Remediation Backlog 패널 추가
- [ ] Report 버튼 연결

### 7.2 `frontend/src/styles.css`

- [ ] 공격 경로 edge 상태별 색상 추가
- [ ] 점선 화살표 애니메이션 추가
- [ ] selected asset 강조 스타일 추가
- [ ] selected path 강조 스타일 추가
- [ ] security control chip 스타일 추가
- [ ] detection status badge 스타일 통일
- [ ] evidence drawer 또는 detail panel 스타일 추가
- [ ] backlog card 스타일 추가
- [ ] coverage score card 스타일 추가

## 8. 백엔드 반영 체크리스트

### 8.1 `api.py`

- [ ] `/targets/{target_id}/asset-discovery` 응답에 asset별 control 상태 요약 추가
- [ ] `/targets/{target_id}/asset-discovery` 응답에 path별 source/target asset 정보 추가
- [ ] `/operations/{operation_id}` 응답에 report summary 포함 여부 확인
- [ ] `/operations/{operation_id}/report` 또는 report artifact 조회 API 추가 검토
- [ ] operation step 생성 시 `source_asset_id`, `target_asset_id`, `attack_path_id` 복사
- [ ] ELK check 결과에서 sample event를 UI가 바로 쓰기 좋게 정규화
- [ ] Alert check 결과에서 rule_id, rule_name, alert_time을 정규화
- [ ] 미탐 사유를 backend에서 우선 분류할지 report builder에서 분류할지 결정

### 8.2 `bas/report_builder.py`

- [ ] report summary에 asset coverage 추가
- [ ] report summary에 path coverage 추가
- [ ] report summary에 control coverage 추가
- [ ] technical report에 attack path별 결과 추가
- [ ] technical report에 asset별 결과 추가
- [ ] backlog reason을 UI에서 쓰기 쉬운 enum으로 정리
- [ ] HTML report 생성이 필요하면 markdown/json 외 HTML artifact 추가

## 9. SB-AD 자산 맵 설계 체크리스트

### 9.1 맵 구간

- [ ] Attacker Zone
- [ ] User Endpoint Zone
- [ ] Server Zone
- [ ] Domain Core Zone
- [ ] Detection Backend Zone

현재 `ELK`는 Server Zone에 있으나, UI에서는 Detection Backend 역할이 잘 보이도록 별도 강조를 고려한다.

### 9.2 자산 노드

- [ ] Attacker Ubuntu
  - [ ] 공격 실행 서버
  - [ ] Impacket, HTTP server, upload server
  - [ ] Agent 필요
- [ ] PC01
  - [ ] 직원 PC
  - [ ] PowerShell, WinRM 출발지
  - [ ] Agent 필요
  - [ ] Sysmon/PowerShell/Winlogbeat 수집
- [ ] FS01
  - [ ] 파일 서버
  - [ ] WinRM 대상, LSASS dump, staging/exfil 위치
  - [ ] Agent 필요
  - [ ] Sysmon/Security/Winlogbeat 수집
- [ ] DC01
  - [ ] 도메인 컨트롤러
  - [ ] Agent 불필요
  - [ ] AD Security Log 관찰 대상
  - [ ] DCSync/Kerberos/Logon 이벤트 수집
- [ ] ELK
  - [ ] 탐지 백엔드
  - [ ] winlogbeat-* index
  - [ ] Kibana Detection Rule
  - [ ] Alert index

### 9.3 공격 경로

- [ ] Attacker Ubuntu -> PC01
  - [ ] Initial Access / reverse shell
  - [ ] 관련 Technique: T1204.002, T1059.003
  - [ ] 검증 통제: Sysmon, Winlogbeat, Kibana Rule
- [ ] PC01 -> FS01
  - [ ] WinRM lateral movement
  - [ ] 관련 Technique: T1021.006, T1059.001, T1105
  - [ ] 검증 통제: PowerShell Logging, Sysmon, Winlogbeat, Kibana Rule
- [ ] FS01 -> Attacker Ubuntu
  - [ ] Data staging and exfiltration
  - [ ] 관련 Technique: T1074.001, T1041
  - [ ] 검증 통제: Sysmon Network, Security Event, Kibana Rule
- [ ] Attacker Ubuntu -> DC01
  - [ ] Domain replication abuse
  - [ ] 관련 Technique: T1003.006
  - [ ] 검증 통제: Windows Security Log 4662, Winlogbeat, Kibana Rule

## 10. 데모 시나리오 수용 기준

최종적으로 아래 흐름이 되면 멘토님 피드백 반영이 충분히 보인다.

- [ ] 사용자가 SB-AD 캠페인을 선택한다.
- [ ] 화면에 Attacker, PC01, FS01, DC01, ELK 자산이 구간별로 보인다.
- [ ] 각 자산에 Agent 상태와 로그/탐지 통제가 보인다.
- [ ] 사용자가 기본 흐름을 실행 큐에 담는다.
- [ ] Run을 누르면 공격 경로가 순서대로 점선 애니메이션으로 활성화된다.
- [ ] 각 Technique이 어느 자산에서 실행되는지 보인다.
- [ ] 각 Technique이 어느 자산을 대상으로 하는지 보인다.
- [ ] 실행 후 ELK 원천 로그 확인 여부가 보인다.
- [ ] 실행 후 Kibana Alert 발생 여부가 보인다.
- [ ] 탐지 결과가 Detected / Logged Only / Missed로 구분된다.
- [ ] 미탐 또는 로그만 확인된 항목은 보완 backlog로 남는다.
- [ ] HTML 또는 markdown 보고서를 열어 결과를 확인할 수 있다.

## 11. 작업 순서 제안

### 1단계: 데이터 연결

- [ ] Campaign flow step과 `attack_paths`를 연결한다.
- [ ] Operation step에 source/target/path 정보를 저장한다.
- [ ] App에서 path별 상태를 계산한다.

### 2단계: 맵 고도화

- [ ] 맵 edge를 path 기반으로 표시한다.
- [ ] edge에 Technique badge를 붙인다.
- [ ] edge에 detection badge를 붙인다.
- [ ] 실행 중 edge 애니메이션을 붙인다.

### 3단계: 증적 상세화

- [ ] Technique 클릭 상세 패널을 만든다.
- [ ] KQL, Alert Query, sample event를 표시한다.
- [ ] 캠페인 페이지 3의 증적 개념과 연결한다.

### 4단계: 커버리지/백로그

- [ ] 탐지 커버리지 점수를 만든다.
- [ ] 로그 가시성 점수를 만든다.
- [ ] 미탐 원인과 보완 backlog를 UI에 표시한다.

### 5단계: 보고서

- [ ] operation report artifact 연결 버튼을 만든다.
- [ ] report에 공격 맵, 타임라인, 증적, backlog를 포함한다.
- [ ] 발표용 demo fixture를 준비한다.

## 12. 완료 정의

이 체크리스트의 완료 기준은 다음과 같다.

- [ ] UI가 단순 공격 실행기가 아니라 자산 기반 탐지 검증 콘솔처럼 보인다.
- [ ] 자산, 구간, ELK 탐지 체계, 공격 경로가 한 화면에서 연결된다.
- [ ] Technique 실행 결과가 원천 로그와 Alert 증거로 설명된다.
- [ ] 미탐 항목이 보완 backlog로 이어진다.
- [ ] 보고서가 자동 생성되어 발표와 산출물에 사용할 수 있다.
- [ ] 발표자가 “상용 보안 솔루션 전체 검증은 아니지만, ELK 탐지 체계를 대상으로 한 BAS 검증 구조를 구현했다”고 자신 있게 말할 수 있다.


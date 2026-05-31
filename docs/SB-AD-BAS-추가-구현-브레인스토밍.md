# SB-AD BAS 추가 구현 및 브레인스토밍

## 1. 현재 방향

Spacebar BAS는 현실적인 프로젝트 범위를 고려해 상용 EDR, NDR, WAF, 방화벽 차단 검증이 아니라 **ELK 기반 탐지 체계 검증형 BAS**로 정리한다.

즉, Technique을 실행했을 때 다음을 확인하는 것이 핵심이다.

- 공격 행위가 어느 자산에서 실행되었는가
- 공격 흐름이 어느 자산으로 이동했는가
- 해당 행위가 원천 로그에 남았는가
- Kibana Detection Rule Alert가 발생했는가
- Alert가 없었다면 로그 수집 문제인지, 탐지룰 문제인지 구분할 수 있는가

발표 표현은 `탐지했다 = 막았다`라고 단정하기보다, **ELK 탐지 체계가 해당 공격 행위를 관찰하고 경보화할 수 있는지 검증했다**라고 설명하는 것이 안전하다.

## 2. 추가 구현해야 할 것

### 2.1 자산 현황 고도화

현재 Attacker, PC01, FS01, DC01, ELK 자산은 표시되지만, 자산별 보안 검증 정보가 더 필요하다.

추가할 항목:

- 자산 역할: 공격자 서버, 직원 PC, 파일 서버, 도메인 컨트롤러, 로그 분석 서버
- IP, OS, 도메인, 네트워크 구간
- Agent 설치 여부와 online/offline 상태
- 로그 수집 여부
- 연결된 로그 수집기와 탐지 체계
- 최근 실행된 Technique 수
- 최근 탐지 성공/실패 수

### 2.2 ELK 탐지 체계 패널

상용 보안 솔루션 대신 ELK 탐지 체계를 검증 대상으로 삼기 때문에, 화면에서 이 구조가 명확히 보여야 한다.

추가할 항목:

- PC01: Sysmon, PowerShell Log, Winlogbeat, Kibana Rule
- FS01: Sysmon, Windows Security Log, Winlogbeat, Kibana Rule
- DC01: Security Event, AD Audit Log, Winlogbeat, Kibana Rule
- ELK: Index, Detection Rule, Alert Index

상태값:

- 수집 정상
- 로그 확인
- Alert 발생
- 로그만 있음
- 미탐
- 미수집

### 2.3 공격 맵 고도화

현재 맵은 자산 간 흐름을 보여주는 시각적 구조에 가깝다. BAS처럼 보이려면 각 공격 경로에 Technique과 탐지 결과가 붙어야 한다.

추가할 항목:

- Attacker -> PC01: 초기 실행, reverse shell
- PC01 -> FS01: WinRM lateral movement
- FS01 -> Attacker: 파일 압축, 외부 전송
- Attacker -> DC01: DCSync, 도메인 복제 악용

각 경로에 붙일 정보:

- Technique ID
- 실행 자산
- 대상 자산
- 실행 상태
- 원천 로그 확인 여부
- Kibana Alert 발생 여부
- 탐지 결과

색상 기준:

- 초록: Alert 발생
- 노랑: 로그만 확인
- 빨강: 미탐
- 회색: 미실행
- 파랑: 실행 중

### 2.4 Technique 실행 결과 판정

Technique마다 단순 성공/실패가 아니라 BAS식 검증 상태가 필요하다.

결과 상태:

- 실행됨
- 목표 자산 도달
- 원천 로그 확인
- 탐지룰 Alert 발생
- 로그만 있음
- 미탐
- 실행 실패

최종 판정:

- Detected
- Logged Only
- Missed
- Not Executed
- Failed

### 2.5 KQL 및 증적 상세 패널

멘토님이 말한 캠페인 페이지 3의 핵심은 실제 공격이나 쿼리 결과가 로그 시스템에 남았다는 증적이다. 따라서 Technique 클릭 시 증거를 바로 볼 수 있어야 한다.

상세 패널에 넣을 항목:

- Technique ID
- Technique 이름
- 실행 자산
- 대상 자산
- 실행 명령 요약
- 기대 로그
- KQL 쿼리
- Kibana Rule 이름
- Rule ID
- event.code
- host.name
- timestamp
- Alert 발생 여부
- 원천 로그 샘플

### 2.6 탐지 커버리지 점수

상용 BAS는 결과를 점수와 커버리지로 보여준다. Spacebar BAS도 ELK 탐지 기준으로 점수화가 필요하다.

추가할 지표:

- 전체 Technique 수
- 실행 Technique 수
- Alert 발생 Technique 수
- 로그만 확인된 Technique 수
- 미탐 Technique 수
- 탐지 커버리지
- 로그 가시성
- Alert 전환률

예시:

- 전체 12개 Technique 실행
- 8개 Alert 발생
- 2개 로그만 확인
- 2개 미탐
- 탐지 커버리지 66.7%
- 로그 가시성 83.3%

### 2.7 미탐 원인 및 보완 백로그

BAS를 실행하는 목적은 탐지 성공 여부만 보는 것이 아니라, 탐지 체계의 보완점을 찾는 것이다.

미탐 원인 후보:

- 로그 수집 안 됨
- Sysmon 설정 부족
- Winlogbeat 수집 채널 누락
- KQL 조건이 너무 좁음
- host.name 불일치
- event.code 불일치
- Rule 비활성화
- Rule schedule/look-back time 문제
- 공격 실행 실패

보완 제안 예시:

- Winlogbeat 수집 채널 추가
- Sysmon Event ID 추가
- Kibana Rule 조건 완화
- Rule schedule/look-back 조정
- severity 조정
- 보조 증거 KQL 추가

### 2.8 실행 타임라인

공격 맵은 자산 간 흐름을 보여주고, 타임라인은 실제 침해 흐름을 시간순으로 보여준다.

추가할 항목:

- 실행 시간
- 자산
- Technique
- 실행 명령 요약
- 로그 발생 시간
- Alert 발생 시간
- 탐지 상태

예시:

- 10:31 PC01에서 PowerShell 실행
- 10:32 FS01 WinRM 접속
- 10:34 Rubeus 다운로드
- 10:36 LSASS dump 시도
- 10:38 Kibana Alert 발생

### 2.9 Agent 상태 고도화

멘토님이 BAS에는 Agent가 필요하다고 말했기 때문에 Agent 상태를 더 실질적으로 보여줘야 한다.

추가할 항목:

- Agent role
- online/offline
- last seen
- hostname
- 실행 가능한 capability
- 현재 job 상태
- 최근 실행 성공/실패
- 설치 위치
- 권한 상태
- safety mode 여부

### 2.10 결과 보고서 연결

BAS 실행 결과는 최종적으로 HTML 보고서로 정리되어야 한다.

보고서에 포함할 항목:

- 캠페인 요약
- 자산 범위
- 실행 Technique 목록
- 탐지 성공/실패 요약
- 공격 맵
- 실행 타임라인
- KQL 증거
- Alert 증거
- 미탐 원인
- 보완 권고

## 3. 구현 우선순위

### P0

- 공격 경로마다 Technique, 실행 자산, 대상 자산, 탐지 결과 붙이기
- Technique 클릭 시 KQL, Alert, 원천 로그 증거 패널 표시
- Run 결과를 Detected, Logged Only, Missed로 판정
- ELK 탐지 체계 상태를 자산별로 표시

### P1

- 공격 흐름 애니메이션 추가
- 탐지 커버리지 점수 추가
- 실행 타임라인 추가
- 미탐 원인 및 보완 백로그 생성

### P2

- HTML 결과 보고서 자동 생성 연결
- Agent 상태 상세화
- 발표용 데모 모드 추가
- 상용 BAS 스타일의 점수/차트 고도화

## 4. 브레인스토밍

### UI

Technique을 실행했을 때, 어떤 Technique이 어느 자산 또는 PC에서 실행되었는지 시각적으로 보여주고 싶다.

구현 아이디어:

- Attacker, PC01, FS01, DC01, ELK를 자산 노드로 표시
- Technique 실행 시 해당 자산 노드가 강조됨
- 공격 흐름은 자산 사이의 화살표로 표시
- 실행 중인 공격은 점선 화살표가 움직이는 애니메이션으로 표현
- 공격이 다음 자산으로 이동하면 화살표가 순차적으로 활성화됨
- 각 Technique 단계에 번호를 붙여 공격 흐름을 따라갈 수 있게 함
- 실행 완료 단계는 초록색, 로그만 확인된 단계는 노랑, 미탐 단계는 빨강으로 표시

### ELK 탐지 결과 표시

Technique 실행 후 ELK에서 로그가 탐지되었는지, Kibana Alert가 발생했는지를 보여주고 싶다.

구현 아이디어:

- 각 Technique 카드에 탐지 상태 표시
- `원천 로그 확인`, `Alert 발생`, `로그만 확인`, `미탐` 상태를 구분
- 자산 노드 아래에 해당 자산에서 발생한 Alert 개수 표시
- 공격 경로 화살표 옆에 탐지 결과 뱃지 표시
- ELK 아이콘 또는 패널을 따로 두고, 어떤 Rule이 Alert를 만들었는지 표시
- 탐지 성공 시 “ELK 탐지 체계가 해당 행위를 식별함”으로 표현
- 차단 여부가 아니라 탐지 가능 여부를 평가한다는 설명을 UI와 보고서에 함께 반영

### 결과 보고서

BAS 실행 후 결과 보고서를 자동으로 만들고 싶다.

구현 아이디어:

- 실행 결과 상세 화면 상단에 `HTML 보고서 보기` 버튼 추가
- 보고서 첫 화면에는 캠페인 이름, 실행 시간, 대상 자산, 탐지 커버리지 표시
- 공격 맵 이미지를 보고서에 포함
- Technique별 실행 결과와 탐지 결과를 표로 정리
- KQL 쿼리와 Alert 증거를 접을 수 있는 상세 영역으로 제공
- 미탐 Technique은 보완 필요 항목으로 자동 분류
- 마지막 섹션에 탐지룰 개선안과 다음 조치 목록 추가

## 5. 정리

현재 UI는 자산 맵 기반 BAS 방향으로 잘 이동하고 있다. 다음 핵심은 예쁜 맵 자체가 아니라, **자산 사이의 공격 흐름과 ELK 탐지 결과를 데이터로 연결하는 것**이다.

따라서 앞으로는 다음 문장을 기준으로 개발하면 된다.

> Technique을 실행했을 때, 어느 자산에서 어떤 공격 행위가 발생했고, ELK 탐지 체계가 그 행위를 로그와 Alert로 확인했는지 보여주는 BAS.


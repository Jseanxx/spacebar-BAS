# BAS 고도화 체크리스트 및 상용 BAS 비교 분석

작성일: 2026-05-21

## 0. 현재 결론

현재 Spacebar BAS는 **SB-01 캠페인 검증용 Mini BAS MVP**로는 의미 있는 수준까지 올라왔다.
다만 AttackIQ, Picus, CALDERA 같은 상용/성숙 BAS 기준으로 보면 아직 **실제 공격 실행성, 개별 Technique 실행, 탐지 갭 분석, 리포트 자동화, Agent 운영 체계**가 부족하다.

평가 점수:

| 기준 | 점수 |
|---|---:|
| 프로젝트 MVP 기준 | 72 / 100 |
| 상용 BAS 기준 | 35 / 100 |
| 발표/포트폴리오 설득력 | 75 / 100 |
| 실무형 확장 가능성 | 65 / 100 |

## 1. 상용 BAS 기준 체크리스트

| 항목 | 상용 BAS 기준 | 현재 상태 | 평가 |
|---|---|---:|---|
| Controller / Web UI | 캠페인 실행, 결과, 점수, 증거 확인 | 있음 | 좋음 |
| Agent 구조 | 대상 서버 설치, 주기적 비콘, 명령 수신, 결과 반환 | 기본 있음 | 보통 |
| MITRE ATT&CK 매핑 | Technique/Tactic 기준 자동 매핑 | 있음 | 좋음 |
| 캠페인 실행 | 전체 체인, 선택 실행, 의존성 처리 | 일부 있음 | 보통 |
| 개별 Technique 실행 | Atomic 단위 실행 가능 | 애매함 | 부족 |
| 실제 공격 실행 | 각 Technique별 안전한 실제 행위 실행 | 일부만 있음 | 부족 |
| 로그 검증 | 실행 직후 SIEM/ELK에서 탐지 확인 | 있음 | 보통 |
| 증거 수집 | 명령, 로그, 탐지 결과, 원본 이벤트 연결 | 일부 있음 | 보통 |
| 탐지 갭 분석 | 미탐 원인, 필요한 룰 추천 | 거의 없음 | 부족 |
| 리포트 | PDF/HTML/Markdown/CSV 보고서 자동 생성 | 없음 | 부족 |
| 스케줄링 | 매일/매주 자동 검증 | 없음 | 부족 |
| 멀티 에이전트 | 여러 서버/OS/팀원 환경 동시 실행 | 구조만 가능 | 부족 |
| 안전장치 | kill switch, cleanup, dry-run, 권한 제한 | 거의 없음 | 부족 |
| 룰 추천 | 미탐 시 Sigma/KQL/탐지룰 제안 | 없음 | 부족 |
| 운영 보안 | 인증, RBAC, API token, 감사 로그 | 없음 | 부족 |

## 2. 부족한 부분 우선순위

### 1. 각 Technique의 실제 실행 모듈 부족

가장 중요한 부족점이다.

현재 SB-01 11개 Technique 중 상당수는 `SB01_log_evidence` 기반의 안전 시뮬레이션이다.
즉, BAS가 직접 공격 행위를 발생시키기보다 이미 수집된 ELK 로그 근거를 확인하는 성격이 강하다.

우선 실제 실행 모듈로 고도화할 후보:

- `T1190` Jenkins CLI file read
- `T1552.001` credential file access
- `T1552.004` private key discovery
- `T1074.001` local data staging
- `T1048.002` outbound exfiltration simulation

### 2. 개별 Technique 실행 모드가 명확하지 않음

현재 UI는 선택한 Technique과 필요한 선행 단계를 함께 실행하는 **Campaign Chain 방식**에 가깝다.
상용 BAS 또는 CALDERA식 구조에 가깝게 가려면 실행 방식을 분리해야 한다.

필요한 실행 모드:

| 실행 모드 | 의미 |
|---|---|
| Atomic | 선택한 Technique 하나만 실행 |
| Chain | 선택한 Technique + 선행 의존 단계 실행 |
| Full Campaign | 캠페인 전체 실행 |

### 3. BAS 실행 로그와 ELK 탐지 로그의 상관관계가 약함

현재는 `lookback` 시간 범위 안에서 유사한 로그를 찾는 방식이다.
실무형 검증으로 보이려면 BAS 실행 시 고유 marker를 남기고, ELK에서 그 marker를 찾아야 한다.

예시:

```text
run_id=exec-20260521-xxxx
technique_id=T1083
marker=SB01_BAS_T1083_exec-20260521-xxxx
```

이렇게 해야 “방금 BAS가 실행한 행위가 방금 ELK에서 탐지됐다”는 증거가 된다.

### 4. 탐지 실패 시 보완안이 부족함

상용 BAS는 탐지 여부만 보여주지 않는다.
미탐이면 다음 내용을 제안한다.

- 어떤 로그 소스가 빠졌는지
- 어떤 필드가 부족한지
- 어떤 Filebeat/auditd/Winlogbeat 설정이 필요한지
- 어떤 KQL/Sigma 룰을 추가해야 하는지

현재는 미탐 결과를 보여주는 수준에 가깝다.

### 5. Agent 설치 및 운영 체계가 약함

CALDERA Sandcat처럼 “대상 환경에 설치된 Agent” 느낌을 더 살려야 한다.

필요한 기능:

- agent install script
- agent config file
- heartbeat status
- agent group
- OS/platform 표시
- 마지막 실행 시간
- 권한 확인
- 실행 가능 모듈 목록

### 6. 정상 행위와 공격 행위 혼합 기능 부족

멘토링 피드백 기준으로 정상 로그와 공격 로그가 함께 있어야 탐지 검증 설득력이 올라간다.

필요한 분류:

- Normal
- Suspicious
- Attack

이후 탐지 룰이 Attack만 잘 골라내는지 검증해야 한다.

### 7. 보고서 자동화 없음

포트폴리오와 발표에서 강한 기능이 될 수 있다.

최소 필요 산출물:

- 실행 결과 Markdown export
- Technique별 탐지 여부
- ELK query
- Evidence sample
- 미탐 보완안

## 3. 다음 고도화 방향

우선순위 높은 작업:

1. 실행 버튼을 `Atomic`, `Chain`, `Full Campaign`으로 분리
2. SB-01 11개 중 최소 3개 이상을 실제 실행 모듈로 전환
3. 실행마다 `run_id marker`를 남기고 ELK에서 marker 기반 검증
4. 미탐 시 KQL/수집 설정 보완안 출력
5. 결과를 Markdown 보고서로 export

이 5개를 구현하면 프로젝트 기준 점수는 85점 이상으로 올릴 수 있다.

## 4. bas-operation-builder 브랜치 검토 기록

팀원 브랜치:

```text
origin/bas-operation-builder
commit: 740fb41 Initial Caldera-style operation builder
```

확인된 주요 기능:

- `/techniques` API 추가
- 전체 campaign YAML의 flow를 Technique library로 수집
- `selected_steps` 기반 사용자 조합 실행 지원
- 선택한 캠페인 target 기준 Technique compatibility 계산
- UI에 Operation Builder 개념 추가
- Technique library에서 큐에 담고 실행하는 방식 추가
- Queue reorder, remove 기능 추가

가져올 가치:

- 높음.
- 특히 **Operation Builder**, **Technique Library**, **Execution Queue**, **Compatibility Check**는 상용 BAS 방향과 잘 맞는다.
- CALDERA의 Ability/Adversary/Operation 개념과도 방향이 유사하다.

주의점:

- 현재 SB-01 브랜치 변경과 `api.py`, `frontend/src/App.jsx`, `frontend/src/styles.css`, `bas/campaign_runner.py`, `bas/elk_checker.py`가 크게 겹친다.
- 그대로 merge하면 SB-01 11개 Technique 확장, ELK live check, 기록 초기화 기능이 회귀할 수 있다.
- 특히 팀원 브랜치의 `targets/SB-01.yaml`은 ELK가 `enabled: false`이고 SB-01 flow도 2개 Technique 중심이라 현재 SB-01 최신 상태보다 뒤처져 있다.

권장 병합 전략:

1. 지금 SB-01 작업 브랜치를 먼저 커밋한다.
2. `bas-operation-builder`를 바로 merge하지 않는다.
3. 별도 통합 브랜치를 만든다.
4. 아래 기능만 선별 이식한다.

선별 이식 후보:

- `StepSelection`
- `/techniques`
- `/campaigns/{campaign_id}/technique-compatibility`
- `selected_steps`
- Operation Queue UI
- Queue reorder/remove UI

보존해야 할 현재 기능:

- SB-01 11개 Technique flow
- SB-01 ELK live check 설정
- `now-24h` lookback
- sample event 확장 필드
- `DELETE /campaigns/{campaign_id}/history`
- SB-01 기록 초기화 버튼
- `SB01_log_evidence.py`

최종 판단:

`bas-operation-builder`는 **가져올만하다.**
다만 지금 브랜치에 직접 merge하면 안 되고, Operation Builder 기능만 선별 이식하는 방식이 안전하다.

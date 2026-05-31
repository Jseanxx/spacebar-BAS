# SB-AD BAS Report Specification

## 1. 목적

SB-AD BAS를 실행하는 목적은 단순히 공격 명령이 실행됐는지 확인하는 것이 아니다. 목표는 다음을 자동으로 판단하고 사람이 읽을 수 있는 결과 보고서로 남기는 것이다.

- 현재 탐지 체계가 어떤 공격 단계를 탐지했는가
- 원본 로그는 남았지만 alert가 생성되지 않은 구간은 어디인가
- 탐지 룰이 없거나 너무 약한 구간은 어디인가
- MITRE ATT&CK 기준으로 어떤 technique 커버리지가 확보됐는가
- 재실행 시 탐지율이 개선됐는가 또는 퇴보했는가
- SOC/탐지 엔지니어가 다음에 고쳐야 할 룰과 로그 수집 지점은 무엇인가

따라서 SB-AD BAS의 결과물은 `run json`만으로 끝나면 안 된다. 실행이 끝날 때마다 사람이 읽을 수 있는 보고서와 기계가 재사용할 수 있는 structured report를 함께 생성해야 한다.

## 2. 상용 BAS/보안 검증 제품 리서치 요약

공개 문서와 벤더 자료 기준으로 확인한 보고서 특징은 다음과 같다. 제품별 내부 스키마 전체가 공개된 것은 아니므로, 아래 내용은 공개 자료에서 확인 가능한 보고서/대시보드 구성요소와 그에 따른 적용 방향이다.

| 제품/벤더 | 공개 자료에서 확인한 보고서 특징 | SB-AD 적용 포인트 |
| --- | --- | --- |
| Cymulate BAS Advanced Scenarios | Assessment report/dashboard가 overall summary, agent details, detection efficacy를 제공하고, execution이 validated/prevented/detected 되었는지 보여준다. MITRE ATT&CK에 매핑된 threats/techniques prevented/detected metrics, queries, threats prevented, alerts detected, events logged, mitigation guidance, attack indicators, Sigma rules를 포함한다. | `Executive Summary`, `Agent/Host Details`, `Detected/Logged/Missed`, `MITRE Mapping`, `Detection Query`, `Rule Improvement`, `Sigma/KQL Recommendation` 섹션 필요 |
| SafeBreach | BAS는 stakeholder별 configurable views, charts/tables/graphs, automated weekly/monthly reports, trends, threat groups/threat types/playbooks/TTPs별 posture, key risk indicators, remediation success rate를 보여줘야 한다고 설명한다. | 보고서 타입을 executive/technical/backlog로 분리하고, 추세 비교와 KRI를 포함 |
| AttackIQ | Security control validation은 prevention/detection/response 계층을 end-to-end로 검증하고, blocked threats that do not trigger alerts 같은 coordination gap, alert fidelity loss, over/under-alerting, MITRE/compliance benchmark, pass/fail evidence를 보여준다. | `source log matched but alert missed`, `alert generated but low fidelity`, `control handoff gap` 같은 gap taxonomy 필요 |
| Picus Security Control Validation | 예방/탐지 control을 지속 검증하고 MITRE ATT&CK 매핑으로 coverage/visibility를 시각화한다. Detection/prevention gaps, mitigation recommendations, vendor-specific prevention signatures and detection rules, executive reports/dashboards, performance trends, benchmarking을 강조한다. | `coverage heatmap`, `mitigation recommendation`, `trend`, `benchmark placeholder` 추가 |
| Mandiant Security Validation | Director/agents 구조로 emulation content를 agent에 전달하고 자동 control testing을 수행한다. Effectiveness gauges로 tested controls가 TTP against how performed를 보여주며, MITRE/NIST mapping, environmental drift alerting, uncorrelated SIEM events, improvement guidance를 제공한다. | multi-agent 결과를 하나의 report로 합치고, drift/regression 감지 및 uncorrelated event 상태를 표현 |
| SCYTHE AEV | Board-ready evidence, MITRE ATT&CK coverage scoring, risk posture over time, crown jewel exposure, per-tool detection gap analysis, risk-adjusted ROI, detected/blocked/missed across kill chain, re-test after fixes를 강조한다. | 경영진 요약에는 점수, 커버리지, gap 수, 개선 추세를 짧게 제공하고 기술 상세는 별도 |
| BreachLock | Reporting dashboard에서 report name/link/status, product/module/type, created by/when, PDF download를 관리한다. Executive Summary와 Detailed Report를 분리해 board/executives와 DevSecOps/auditors/compliance에 맞춘다. | 보고서 카탈로그 화면과 export 상태 관리 필요 |
| Pentera Security Validation Report | sample report에서 executive summary, cyber resilience score, test settings, duration, included IP ranges, critical assets, credentials, lateral movement, data accessible, host takeover, EDR/AV bypass, total actions, successful/no-result ratios, trend, key findings, remediation guidance, MITRE heatmap을 확인할 수 있다. | SB-AD도 `환경 설정`, `실행 범위`, `위험 카테고리별 결과`, `trend`, `remediation`, `MITRE heatmap` 필요 |

## 3. 참고한 공개 자료

- Cymulate BAS Advanced Scenarios Data Sheet: <https://l.cymulate.com/hubfs/Datasheet/BAS%20Advanced%20Scenarios_Data%20Sheet.pdf>
- SafeBreach BAS Customizable Reporting: <https://www.safebreach.com/blog/bas-101-lesson-5-customizable-reporting/>
- AttackIQ Security Control Validation: <https://www.attackiq.com/solutions/security-control-validation/>
- Picus Security Control Validation: <https://www.picussecurity.com/platform/security-control-validation>
- Mandiant Security Validation: <https://cloud.google.com/security/products/mandiant-security-validation?cid=us>
- SCYTHE CISO / AEV reporting page: <https://scythe.io/ciso>
- BreachLock reporting workflow: <https://www.breachlock.com/resources/blog/reporting-for-decision-makers-security-practitioners-with-the-breachlock-unified-platform/>
- Pentera sample Security Validation Report: <https://pentera.io/wp-content/uploads/2024/09/pentera-summary-report-platform.pdf>
- Elastic Security alert schema: <https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema>
- MITRE ATT&CK Navigator: <https://mitre.github.io/attack-navigator/enterprise/>

## 4. SB-AD 보고서 산출물

BAS 실행이 끝나면 다음 산출물을 자동 생성한다.

```text
outputs/
  runs/
    exec-YYYYMMDD-HHMMSS-xxxxxx.json
  reports/
    exec-YYYYMMDD-HHMMSS-xxxxxx.report.json
    exec-YYYYMMDD-HHMMSS-xxxxxx.summary.md
    exec-YYYYMMDD-HHMMSS-xxxxxx.technical.md
    exec-YYYYMMDD-HHMMSS-xxxxxx.detection-backlog.csv
    exec-YYYYMMDD-HHMMSS-xxxxxx.attack-navigator.json
    exec-YYYYMMDD-HHMMSS-xxxxxx.html
```

초기 구현 우선순위:

1. `report.json`
2. `summary.md`
3. `technical.md`
4. `detection-backlog.csv`
5. `attack-navigator.json`
6. `html` 또는 PDF export

PDF는 처음부터 직접 만들지 않는다. 우선 HTML을 만들고 브라우저 print-to-PDF 또는 Playwright PDF 출력으로 확장한다.

## 5. 보고서 타입

### 5.1 Executive Summary

대상:

- 팀장, PM, 비기술 이해관계자
- 포트폴리오/발표 자료

목적:

- 이번 BAS 실행에서 탐지 체계가 어느 정도 작동했는지 한눈에 보여준다.
- 세부 명령보다 결과와 개선 방향을 강조한다.

필수 섹션:

- 실행 개요
- 총점 / 탐지율 / 로그 수집률 / alert 생성률
- 핵심 탐지 gap Top 5
- MITRE ATT&CK 커버리지 요약
- 고위험 technique 결과
- 전회 대비 개선/퇴보
- 다음 액션 요약

### 5.2 Technical Detection Report

대상:

- SOC 분석가
- 탐지 룰 작성자
- 프로젝트 팀원

목적:

- 각 technique이 어떤 명령으로 실행됐고, 어떤 로그/alert로 확인됐는지 증거를 남긴다.
- 탐지 실패 원인을 분류한다.

필수 섹션:

- Step timeline
- Technique별 실행 결과
- Source log query와 결과
- Alert query와 결과
- Sample event/alert fields
- Rule ID, rule name, severity, tags
- 실패 원인 분석
- 권장 KQL/룰 보완 방향

### 5.3 Detection Engineering Backlog

대상:

- 룰 개선 담당자
- 다음 작업 회의

목적:

- 보고서를 읽고 바로 작업 티켓으로 전환할 수 있게 한다.

필수 필드:

- priority
- technique_id
- step_order
- gap_type
- affected_host
- current_rule_id
- recommended_action
- suggested_query
- owner
- effort
- due_hint
- verification_method

### 5.4 MITRE Coverage Layer

대상:

- ATT&CK Navigator 시각화
- 커버리지 발표

목적:

- Technique별 탐지 상태를 matrix에서 색으로 보여준다.

색상 규칙:

| 상태 | 색상 | 의미 |
| --- | --- | --- |
| `detected` | green | 원본 로그와 alert 모두 확인 |
| `logged_only` | yellow | 원본 로그는 있으나 alert 없음 |
| `missed` | red | 실행 성공했으나 source/alert 모두 없음 |
| `not_checked` | gray | ELK 연결 실패 또는 검증 불가 |
| `blocked` | blue | safety gate 또는 방어 통제로 실행 차단 |

## 6. 핵심 지표 정의

### 6.1 실행 지표

| Metric | 계산식 | 의미 |
| --- | --- | --- |
| `total_steps` | 전체 step 수 | 보고서 대상 technique 수 |
| `executed_steps` | status in `success`, `simulated` | 실행 완료된 step |
| `failed_steps` | status in `failed`, `manual_required` | 실행 실패 또는 수동 필요 |
| `blocked_steps` | status starts with `blocked` | safety gate/의존성으로 차단 |
| `execution_rate` | executed / total | BAS 실행 완성도 |

### 6.2 탐지 지표

| Metric | 계산식 | 의미 |
| --- | --- | --- |
| `telemetry_coverage` | source matched / executed attack steps | 원본 로그 수집률 |
| `alert_coverage` | alert matched / executed attack steps | 탐지 룰 alert 생성률 |
| `detection_coverage` | detected / executed attack steps | source + alert 기준 탐지율 |
| `logged_only_rate` | logged_only / executed attack steps | 룰 누락 또는 rule schedule 문제 |
| `miss_rate` | missed / executed attack steps | 로그/alert 모두 실패한 비율 |
| `not_checked_rate` | not_checked / executed attack steps | ELK/API 검증 실패 비율 |

### 6.3 품질 지표

| Metric | 판단 기준 | 의미 |
| --- | --- | --- |
| `alert_latency_seconds` | alert timestamp - step finished_at | 탐지 지연 |
| `evidence_quality` | high/medium/low | sample event가 technique 의도와 얼마나 직접 연결되는지 |
| `rule_specificity` | high/medium/low | 룰이 너무 하드코딩인지, 너무 광범위한지 |
| `rule_actionability` | high/medium/low | alert만 보고 조치 가능한지 |
| `false_positive_risk` | high/medium/low | 정상 행위와 겹칠 가능성 |

## 7. 탐지 상태 판정 로직

각 step은 실행 결과와 ELK 결과를 조합해 최종 상태를 가진다.

```text
if step.status is blocked:
    detection_status = "blocked"
elif step.status is failed:
    detection_status = "execution_failed"
elif elk_check.checked is false:
    detection_status = "not_checked"
elif source.matched and alert.matched:
    detection_status = "detected"
elif source.matched and not alert.matched:
    detection_status = "logged_only"
elif not source.matched and alert.matched:
    detection_status = "alert_without_source_sample"
else:
    detection_status = "missed"
```

`alert_without_source_sample`은 이상하지만 가능하다. alert index에는 결과가 있는데 source query가 너무 좁거나 lookback이 맞지 않는 경우다. 이 상태는 룰 실패가 아니라 보고서에서 query 보정 대상으로 표시한다.

## 8. Gap Taxonomy

탐지 실패를 단순히 `missed`로 끝내지 않고 원인 분류를 한다.

| gap_type | 조건 | 의미 | 권장 액션 |
| --- | --- | --- | --- |
| `no_telemetry` | source 없음, alert 없음 | 로그 수집 자체가 안 됨 | Sysmon/Winlogbeat/채널 확인 |
| `no_alert` | source 있음, alert 없음 | 룰이 없거나 조건이 안 맞음 | KQL/EQL 룰 작성 또는 수정 |
| `alert_delay` | source 있음, alert 늦게 생성 | 룰 주기/lookback 문제 | interval/lookback 조정 |
| `query_too_narrow` | alert 있음, source query 없음 | 검증 query가 너무 좁음 | report query 수정 |
| `rule_too_broad` | alert 있음, FP 위험 높음 | 정상 행위와 충돌 가능 | 조건 강화, allowlist |
| `hardcoded_ioc` | 특정 IP/파일명만 의존 | 환경 바뀌면 실패 | 행위 기반 조건으로 개선 |
| `missing_rule_metadata` | rule id/severity/tag 누락 | 관리/보고 어려움 | naming/tag 정책 적용 |
| `disabled_or_failed_rule` | 룰 비활성/실행 실패 | alert 생성 불가 | Kibana rule status 확인 |
| `agent_or_execution_failed` | step 실행 실패 | 공격 검증 불가 | Agent/권한/변수 확인 |
| `not_checked` | ELK 연결 실패 | 탐지 검증 불가 | BAS_ELK_URL/API 설정 |

## 9. 점수 모델

초기 점수는 단순하고 설명 가능해야 한다.

### 9.1 Step별 점수

| 상태 | 점수 |
| --- | --- |
| `detected` | 100 |
| `logged_only` | 60 |
| `alert_without_source_sample` | 50 |
| `blocked` | 80 |
| `not_checked` | 제외 또는 40 |
| `execution_failed` | 제외 또는 30 |
| `missed` | 0 |

`not_checked`와 `execution_failed`를 점수에 포함할지는 보고서 설정값으로 둔다. 발표용 기본값은 포함하지 않고, 운영 품질 보고서에서는 별도 감점으로 표시한다.

### 9.2 Severity Weight

| risk | weight |
| --- | --- |
| low | 1.0 |
| medium | 1.2 |
| high | 1.5 |
| critical | 2.0 |

### 9.3 최종 점수

```text
coverage_score = weighted_average(step_detection_score)
telemetry_score = source_matched / executed
alert_score = alert_matched / executed
operational_score = executed / total

final_score =
  coverage_score * 0.55
  + telemetry_score * 100 * 0.15
  + alert_score * 100 * 0.20
  + operational_score * 100 * 0.10
```

점수는 `0~100`으로 표시한다.

## 10. 보고서 데이터 스키마

### 10.1 report.json

```json
{
  "report_id": "report-exec-20260524-094908-6083b2",
  "execution_id": "exec-20260524-094908-6083b2",
  "campaign_id": "SB-AD",
  "campaign_name": "Spacebar AD Detection Validation",
  "generated_at": "2026-05-24T10:20:00+09:00",
  "report_version": "0.1",
  "profile": "technical",
  "summary": {
    "final_score": 82,
    "execution_rate": 1.0,
    "telemetry_coverage": 0.92,
    "alert_coverage": 0.75,
    "detection_coverage": 0.75,
    "logged_only_count": 2,
    "missed_count": 1,
    "not_checked_count": 0,
    "critical_gaps": 1
  },
  "scope": {
    "target": "SB-AD",
    "hosts": ["PC01.mycompany.local", "FS01.mycompany.local", "DC01.mycompany.local"],
    "agent_roles": ["pc01", "fs01", "attacker"],
    "started_at": "...",
    "finished_at": "..."
  },
  "mitre": {
    "techniques_tested": ["T1021.006"],
    "detected": ["T1021.006"],
    "logged_only": [],
    "missed": []
  },
  "steps": [],
  "recommendations": [],
  "backlog": []
}
```

### 10.2 Step Result 확장 필드

기존 run step을 그대로 쓰되 보고서 생성 시 아래 필드를 추가 계산한다.

```json
{
  "order": 10,
  "technique_id": "T1021.006",
  "name": "10. WinRM Remote Execution",
  "risk": "high",
  "agent_role": "pc01",
  "execution_host": "PC01_to_FS01",
  "execution_status": "success",
  "detection_status": "detected",
  "source_status": "matched",
  "alert_status": "matched",
  "source_event_count": 3,
  "alert_count": 1,
  "alert_latency_seconds": 74,
  "gap_type": null,
  "rule": {
    "rule_id": "359665d4-2915-44c8-b780-6131add0dbd2",
    "name": "10.T1021.006 ...",
    "severity": "high",
    "tags": ["SB-AD", "T1021.006"]
  },
  "queries": {
    "source": "winlog.channel:...",
    "alert": "kibana.alert.rule.rule_id:..."
  },
  "evidence": {
    "sample_source_events": [],
    "sample_alerts": []
  },
  "recommendation": {
    "action": "keep",
    "reason": "Source and alert both matched."
  }
}
```

## 11. Executive Summary Markdown 템플릿

```md
# SB-AD BAS 결과 요약

## 한 줄 결론
이번 실행에서 전체 12개 공격 단계 중 9개가 탐지됐고, 2개는 로그만 남았으며, 1개는 미탐지되었습니다.

## 핵심 지표

| 지표 | 값 |
| --- | --- |
| 최종 점수 | 82/100 |
| 실행률 | 12/12 |
| 원본 로그 수집률 | 11/12 |
| Alert 탐지율 | 9/12 |
| 미탐지 | 1 |
| 로그만 존재 | 2 |

## 가장 중요한 Gap

1. T1041 Exfiltration Over C2: 원본 네트워크 로그는 있으나 alert 미생성
2. T1003.006 DCSync: 4662 수집은 되었으나 rule id 기준 alert 미확인
3. T1105 Tool Transfer: PowerShell 4104는 있으나 정상 admin 다운로드와 구분 약함

## 다음 액션

- T1041 룰을 외부 목적지 + PowerShell/cmd 조합으로 보완
- DCSync rule 실행 주기와 lookback 확인
- T1105 정상 관리 행위 allowlist 추가
```

## 12. Technical Report Markdown 템플릿

```md
# SB-AD BAS 기술 상세 보고서

## 1. 실행 정보

- Execution ID:
- Campaign:
- Started:
- Finished:
- Mode:
- Agents:

## 2. Technique별 결과

| Order | Technique | Risk | Execution | Source Log | Alert | Gap | Action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | T1021.006 | high | success | matched | matched | - | keep |

## 3. 상세 증거

### 10. T1021.006 WinRM Remote Execution

- 실행 주체: PC01 Agent
- 대상: FS01
- 기대 이벤트: Sysmon Event ID 1, `wsmprovhost.exe`
- Source query:

```kql
...
```

- Alert query:

```kql
...
```

- 결과:
  - source events: 3
  - alerts: 1
  - detection status: detected

## 4. 탐지 보완 권고

...
```

## 13. Detection Backlog CSV 필드

```csv
priority,technique_id,order,gap_type,affected_host,current_rule_id,current_rule_name,recommended_action,suggested_query,owner,effort,verification_method
P1,T1041,16,no_alert,FS01,sb-ad-t1041-exfiltration-over-c2,16.T1041...,Tune rule, ...,준서,M,Re-run step 16
```

필드 설명:

| 필드 | 설명 |
| --- | --- |
| `priority` | P0/P1/P2/P3 |
| `technique_id` | MITRE ID |
| `order` | SB-AD 시나리오 순번 |
| `gap_type` | Gap taxonomy |
| `affected_host` | PC01/FS01/DC01/Attacker |
| `current_rule_id` | 현재 Kibana rule id |
| `current_rule_name` | 현재 rule name |
| `recommended_action` | keep/tune/create/enable/fix_ingestion/fix_query |
| `suggested_query` | 권장 KQL/EQL |
| `owner` | 담당자 |
| `effort` | S/M/L |
| `verification_method` | 재검증 방법 |

## 14. MITRE ATT&CK Navigator Layer

Navigator layer는 자동 생성한다.

Technique color/comment 예시:

```json
{
  "techniqueID": "T1021.006",
  "score": 100,
  "color": "#16a34a",
  "comment": "Detected. Source log and Kibana alert matched. Rule: 10.T1021.006"
}
```

점수 매핑:

| detection_status | score |
| --- | --- |
| detected | 100 |
| logged_only | 60 |
| alert_without_source_sample | 50 |
| blocked | 80 |
| not_checked | 40 |
| missed | 0 |

## 15. 추천 액션 생성 규칙

### 15.1 detected

```text
action = keep
message = 현재 룰은 실행 행위를 탐지함. 다만 false positive 위험과 조건 하드코딩 여부를 검토.
```

### 15.2 logged_only

```text
action = tune_or_create_rule
message = 원본 로그는 수집되었으나 alert가 없음. source query를 기준으로 rule 생성 또는 기존 rule 조건 보완.
```

### 15.3 missed

```text
action = fix_telemetry_then_rule
message = 원본 로그와 alert 모두 없음. 로그 수집 설정부터 확인하고 이후 rule 작성.
```

### 15.4 not_checked

```text
action = fix_validation_pipeline
message = ELK 연결 또는 query 검증이 실패함. BAS_ELK_URL, 인증, index, lookback 확인.
```

### 15.5 hardcoded_ioc

```text
action = generalize_detection
message = 특정 IP/파일명/사용자에 과도하게 의존함. 행위 기반 조건과 환경 변수 기반 allowlist로 개선.
```

## 16. SB-AD Technique별 보고서 권고 기본값

| Order | Technique | 핵심 증거 | 좋은 결과 | 대표 Gap | 기본 권고 |
| --- | --- | --- | --- | --- | --- |
| 2 | T1059.003 | cmd.exe process creation | source+alert | 정상 cmd와 구분 약함 | Parent/command context 보강 |
| 3 | T1095 | outbound non-web TCP | source+alert | 특정 IP/port 하드코딩 | 내부/루프백 제외 + process 기준 |
| 4 | T1087.002 | net group/domain query | source+alert | 정상 admin 조회와 충돌 | user/parent allowlist |
| 5 | T1018 | nltest/nslookup/net view | source+alert | discovery 명령 과탐 | command keyword + user context |
| 6 | T1033 | whoami/quser/qwinsta | source+alert | 단독 whoami는 약함 | 시나리오 correlation 권장 |
| 10 | T1021.006 | wsmprovhost.exe on FS01 | source+alert | svc_file 고정 | WinRM process + remote logon 보조 |
| 11 | T1059.001 | powershell child of wsmprovhost | source+alert | 4104 누락 가능 | Sysmon 1 + PowerShell 4104 병행 |
| 12 | T1105 | Invoke-WebRequest/curl/wget | source+alert | 정상 다운로드와 충돌 | 외부 host + output path + parent context |
| 13 | T1003.001 | rundll32 -> lsass + comsvcs | source+alert | Sysmon 10 미수집 | Event 10/CallTrace 필수 |
| 15 | T1074.001 | public share file create | source+alert | 공유 폴더 정상 파일 생성과 충돌 | svc_file/user + 파일명/확장자 보조 |
| 16 | T1041 | external HTTP upload | source+alert | IP/port 하드코딩 | 내부망 제외 + process + upload method |
| 19 | T1003.006 | DC01 4662 replication GUID | source+alert | audit policy 미설정 | 4662/SACL/SubjectUserName 확인 |

## 17. 구현 컴포넌트

### 17.1 `bas/report_builder.py`

역할:

- run json 읽기
- step별 detection_status 계산
- metrics 계산
- gap taxonomy 적용
- recommendations 생성
- output 파일 생성

함수:

```python
def build_report(execution_id: str) -> dict:
    ...

def classify_step(step: dict) -> dict:
    ...

def calculate_metrics(classified_steps: list[dict]) -> dict:
    ...

def generate_recommendations(classified_steps: list[dict]) -> list[dict]:
    ...

def write_report_artifacts(report: dict) -> dict:
    ...
```

### 17.2 API

추가 API:

| Method | Path | 설명 |
| --- | --- | --- |
| `POST` | `/runs/{execution_id}/report` | 해당 run의 report 생성 |
| `GET` | `/reports` | report 목록 |
| `GET` | `/reports/{report_id}` | report json |
| `GET` | `/reports/{report_id}/summary.md` | executive summary |
| `GET` | `/reports/{report_id}/technical.md` | technical report |
| `GET` | `/reports/{report_id}/backlog.csv` | backlog csv |
| `GET` | `/reports/{report_id}/navigator.json` | ATT&CK Navigator layer |

### 17.3 Frontend

대시보드에 `보고서` 탭 추가.

필수 UI:

- Report list
- Generate report button
- Executive summary preview
- Technique result table
- Gap table
- Download buttons
  - JSON
  - Markdown
  - CSV
  - Navigator layer
  - HTML/PDF

## 18. 자동 보고서 생성 트리거

### 18.1 기본 정책

Job 또는 operation 완료 시 자동 생성.

```text
on job completed:
    if result.execution_id:
        build_report(execution_id)
```

### 18.2 재생성 정책

보고서는 재생성 가능해야 한다.

재생성 사유:

- classification logic 변경
- 룰 메타데이터 보강
- ELK alert 재조회
- 보고서 템플릿 수정

report metadata에 다음을 남긴다.

```json
{
  "report_version": "0.1",
  "generator_version": "sb-ad-report-builder-0.1",
  "generated_at": "...",
  "source_execution_id": "..."
}
```

## 19. 리포트 신뢰성 원칙

보고서가 과장되면 안 된다.

원칙:

- `not_checked`를 `missed`나 `detected`로 임의 변환하지 않는다.
- simulation mode 결과는 실제 탐지율 계산에서 기본 제외한다.
- source log와 alert를 분리해서 보여준다.
- 탐지율은 denominator를 명확히 표시한다.
- 하드코딩된 탐지 룰은 `rule_specificity` 또는 `hardcoded_ioc`로 표시한다.
- sample event가 없으면 evidence quality를 낮춘다.
- MITRE coverage는 “테스트한 technique 범위 내 coverage”라고 명시한다.

## 20. MVP 구현 순서

### Phase 1. Offline Report Builder

- 기존 `outputs/runs/*.json`을 입력으로 report 생성
- summary.md / technical.md / backlog.csv 생성
- ELK 재조회 없음

### Phase 2. Dashboard Report Tab

- reports 목록 표시
- report preview
- download buttons

### Phase 3. ELK Recheck

- report 생성 시 source/alert query 재실행
- alert latency 계산
- sample event 확장

### Phase 4. Navigator Layer

- ATT&CK Navigator JSON export
- technique color/score/comment 적용

### Phase 5. Trend Report

- 동일 campaign 최근 N회 비교
- detection_coverage trend
- regression/new gap/improved gap 표시

## 21. 완료 기준

MVP 완료 기준:

- BAS 실행 후 `outputs/reports`에 readable report가 자동 생성된다.
- Executive summary만 읽어도 탐지율과 주요 gap을 알 수 있다.
- Technical report에서 각 technique별 query/evidence/alert/rule id를 확인할 수 있다.
- Detection backlog CSV를 보고 바로 룰 개선 작업을 시작할 수 있다.
- simulation 결과와 real 결과가 명확히 구분된다.

최종 완료 기준:

- 대시보드에서 보고서를 열람/다운로드할 수 있다.
- MITRE Navigator layer를 import할 수 있다.
- 이전 실행과 비교해 개선/퇴보를 표시한다.
- source log matched와 alert matched를 분리해 보여준다.
- 탐지 룰 보완 권고가 gap_type별로 자동 생성된다.


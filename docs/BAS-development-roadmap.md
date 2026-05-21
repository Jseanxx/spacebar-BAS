# Spacebar BAS 개발 기록 및 고도화 로드맵

작성일: 2026-05-21

## 0. 현재 정의

Spacebar BAS는 상용 BAS 완제품이 아니라, **MITRE ATT&CK 캠페인 기반으로 Technique 실행과 로그 탐지 검증을 자동화하는 Mini BAS 프레임워크**다.

현재 목표는 다음과 같다.

1. 팀원별 캠페인의 `Techniques Used`를 실행 가능한 BAS 모듈로 만든다.
2. 실행 결과가 ELK, Wazuh, Winlogbeat, Sysmon 등에서 실제 로그로 확인되는지 검증한다.
3. 탐지되지 않는 Technique은 필요한 로그 소스, 필드, KQL/Sigma 룰을 보완한다.
4. 최종적으로 DF/IR 보고서와 플레이북 작성에 필요한 증거를 자동 정리한다.

## 1. 현재 구현 상태

| 영역 | 현재 상태 | 평가 |
|---|---|---|
| Web UI | Campaign Validation Console, Technique Library, Execution Queue 제공 | MVP 가능 |
| API Controller | campaign 실행, job queue, agent 등록, history reset 지원 | MVP 가능 |
| Campaign YAML | 캠페인별 Technique flow 정의 | 확장 가능 |
| Target YAML | 환경별 host, capability, ELK query 분리 | 확장 가능 |
| Module 구조 | `modules/attack/*.py` 단위로 실행 로직 분리 | 확장 가능 |
| BasAgent | controller 등록, heartbeat, job 수신, 결과 업로드 가능 | 기본형 |
| ELK 검증 | `evidence_key` 기반 Elasticsearch query 확인 | 기본형 |
| Report | 자동 보고서 생성 없음 | 부족 |
| Scheduler | 정기 검증 없음 | 부족 |
| Detection Gap 분석 | 미탐 보완안 자동 제안 없음 | 부족 |

## 2. SB-01 기준 구현 현황

SB-01은 Jenkins/App/PostgreSQL/ELK 기반 AWS CI/CD 환경을 대상으로 한다.

현재 SB-01은 11개 Technique flow를 가진다.

| Order | Technique | 현재 모듈 상태 |
|---:|---|---|
| 1 | `T1592` Gather Victim Host Information | 로그 근거 확인 |
| 2 | `T1078` Valid Accounts | 로그 근거 확인 |
| 3 | `T1190` Exploit Public-Facing Application | 안전 실행 모듈 구현 |
| 4 | `T1213` Data from Information Repositories | 로그 근거 확인 |
| 5 | `T1552.001` Credentials In Files | 안전 실행 모듈 구현 |
| 6 | `T1552.004` Private Keys | 안전 실행 모듈 구현 |
| 7 | `T1021.004` SSH | 실제 SSH 실행 모듈 구현 |
| 8 | `T1083` File and Directory Discovery | 실제 SSH 실행 모듈 구현 |
| 9 | `T1213.006` Databases | 로그 근거 확인 |
| 10 | `T1074.001` Local Data Staging | 안전 실행 모듈 구현 |
| 11 | `T1048.002` Exfiltration over Asymmetric Encrypted Non-C2 Protocol | 안전 실행 모듈 구현 |

2026-05-21에 추가한 안전 실행 모듈:

| Technique | Module | 안전 기준 |
|---|---|---|
| `T1190` | `attack.T1190_jenkins_cli_file_read` | 민감 파일 대신 canary 파일만 사용 |
| `T1552.001` | `attack.T1552_001_jenkins_credential_file_access` | credential 값 출력 없이 메타데이터만 확인 |
| `T1552.004` | `attack.T1552_004_jenkins_private_key_discovery` | private key 본문 출력 없이 경로/권한/크기만 확인 |
| `T1074.001` | `attack.T1074_001_sb01_app_local_staging` | `/tmp` 아래 marker/listing 파일만 생성 |
| `T1048.002` | `attack.T1048_002_https_exfil_simulation` | 데이터 업로드 없이 HTTPS outbound flow만 생성 |

## 3. 새 캠페인 추가 표준 절차

다른 팀원 환경을 붙일 때는 아래 구조를 따른다.

```text
campaigns/SB-XX.yaml
targets/SB-XX.yaml
modules/attack/<technique_module>.py
agent_runtime/config.sbxx.yaml
docs/<optional-campaign-note>.md
```

### 3.1 Campaign YAML

`campaigns/SB-XX.yaml`에는 Technique 실행 순서를 작성한다.

필수 필드:

| 필드 | 의미 |
|---|---|
| `order` | 실행 순서 |
| `phase` | normal / suspicious / attack |
| `module` | 실행할 Python 모듈 |
| `target` | 대상 환경 ID |
| `technique_id` | MITRE ATT&CK Technique ID |
| `depends_on_orders` | 선행 단계 |
| `requires` | 필요한 capability |
| `params.behavior` | 실행 행위 이름 |
| `params.evidence_key` | ELK/Wazuh 검증 쿼리 키 |

### 3.2 Target YAML

`targets/SB-XX.yaml`에는 환경별 접속 정보와 로그 검증 쿼리를 작성한다.

필수 영역:

| 영역 | 의미 |
|---|---|
| `capabilities` | 해당 환경에서 실행 가능한 기능 |
| 환경별 접속 정보 | SSH, WinRM, API endpoint 등 |
| `elk` 또는 `wazuh` | 로그 검증 대상 |
| `log_queries` | `evidence_key`별 탐지 쿼리 |

### 3.3 Module

모듈은 다음 원칙을 지킨다.

1. `run(target, params=None)` 인터페이스를 사용한다.
2. `execution_mode: simulation`이면 실제 명령을 실행하지 않는다.
3. `execution_mode: real`이어도 민감 파일 원문, credential, private key를 출력하지 않는다.
4. 가능한 경우 marker/canary를 남겨 추적 가능하게 한다.
5. 실행 결과에는 `behavior`, `evidence_key`, `commands`, `artifacts`를 포함한다.

## 4. AD/Windows 환경 확장 방향

AD 환경은 Linux SSH 방식과 다르게 설계해야 한다.

권장 구조:

```text
Windows BasAgent
  -> PowerShell / WinRM 기반 안전 실행
  -> Windows Event Log / Sysmon / Winlogbeat 수집
  -> ELK 또는 Wazuh에서 Event ID 기반 검증
```

AD 환경에서 우선 구현할 만한 검증 포인트:

| 행위 | Technique 후보 | 주요 로그 |
|---|---|---|
| Kerberos service ticket request | `T1558.003` Kerberoasting | Windows Security `4769` |
| 의심스러운 PowerShell 실행 | `T1059.001` PowerShell | PowerShell Operational, Sysmon `1` |
| credential dump 계열 방어 검증 | `T1003` OS Credential Dumping | Sysmon `10`, Security 로그 |
| 원격 접속 | `T1021.001` RDP / `T1021.002` SMB | Security `4624`, `4627`, `4648` |
| AD 객체 탐색 | `T1087`, `T1018` | PowerShell, LDAP query 로그, Sysmon |

주의:

- AD 환경 BAS는 실제 credential 탈취가 아니라 **안전한 이벤트 발생과 탐지 검증**을 우선한다.
- Rubeus, Mimikatz 같은 도구명 탐지는 실습 가치가 있지만, 발표/포트폴리오에서는 “도구 실행”보다 “어떤 이벤트와 필드가 남는지”를 중심으로 설명한다.
- Windows 모듈은 `modules/attack/windows_*.py` 또는 `modules/attack/Txxxx_windows_*.py` 식으로 구분한다.

## 5. 다음 고도화 우선순위

### 1단계: run_id marker 기반 검증

현재는 시간 범위 기반으로 ELK에서 유사 로그를 찾는다.
다음 단계에서는 BAS 실행마다 고유 marker를 남겨야 한다.

예시:

```text
execution_id=exec-20260521-xxxx
technique_id=T1083
marker=SB01_BAS_T1083_exec-20260521-xxxx
```

목표:

- BAS 실행 결과와 ELK 로그를 1:1로 연결
- “방금 실행한 행위가 방금 수집됐다”는 증거 강화

### 2단계: 실행 모드 분리

현재는 Campaign Chain 방식에 가깝다.
상용 BAS처럼 보이려면 실행 모드를 분리해야 한다.

| 모드 | 의미 |
|---|---|
| Atomic | 선택한 Technique 하나만 실행 |
| Chain | 선택한 Technique과 선행 의존 단계 실행 |
| Full Campaign | 캠페인 전체 실행 |

### 3단계: Agent 운영 체계 강화

필요 기능:

- agent install script
- agent config validation
- heartbeat 상세 상태
- OS/platform 표시
- 실행 가능한 capability 표시
- 마지막 실행 시간
- agent별 실행 이력

### 4단계: Detection Gap 분석

탐지 실패 시 다음을 자동으로 제안해야 한다.

- 누락된 로그 소스
- 필요한 Filebeat/auditd/Winlogbeat/Sysmon 설정
- 필요한 KQL 또는 Sigma 룰
- 확인해야 할 주요 필드

### 5단계: 보고서 자동화

최소 산출물:

- 실행 결과 Markdown export
- Technique별 실행/탐지 여부
- 사용한 ELK query
- sample event
- 미탐 보완안

## 6. 발표/포트폴리오 표현 문장

권장 표현:

> MITRE ATT&CK 캠페인에 매핑된 Technique을 안전한 BAS 모듈로 실행하고, ELK/Wazuh에서 수집된 로그와 비교하여 탐지 가능 여부를 검증하는 Mini BAS 프레임워크를 개발하고 있습니다.

피해야 할 표현:

> 상용 BAS 수준으로 완성했습니다.

현재 상태를 정확히 말하면:

> SB-01 환경에서는 일부 Technique을 실제 안전 실행 모듈로 전환했고, 나머지 팀원 환경은 동일한 Campaign/Target/Module 구조로 확장할 예정입니다.

## 7. 유지보수 원칙

1. 팀원별 환경은 `campaigns/SB-XX.yaml`, `targets/SB-XX.yaml`로 분리한다.
2. 공통 기능은 모듈화하되, 환경 종속 값은 Target YAML에 둔다.
3. 민감 값 출력 금지, canary/metadata/marker 우선 원칙을 지킨다.
4. 로그 검증은 `evidence_key`와 `log_queries`로 연결한다.
5. 미탐이 나오면 실패가 아니라 “보완할 로그/룰을 찾은 결과”로 기록한다.

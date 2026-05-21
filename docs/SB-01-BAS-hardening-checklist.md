# SB-01 BAS 고도화 구현 체크리스트

작성일: 2026-05-21

## 0. 목표

이 문서는 SB-01 BAS를 “보여주기용 대시보드”에서 **실제 Technique 실행과 ELK 탐지 검증이 연결되는 Mini BAS**로 고도화하기 위한 작업 체크리스트다.

최종 목표:

- SB-01 11개 Technique이 각각 실행 가능한 BAS 모듈을 가진다.
- 각 실행은 안전한 marker/canary를 남긴다.
- ELK에서 해당 실행의 로그를 확인할 수 있다.
- 미탐이면 어떤 로그 수집기/필드/룰이 부족한지 바로 알 수 있다.
- 동일 구조를 AD, Windows, K8s, Web 환경에도 확장할 수 있다.

## 1. 현재 SB-01 상태 점검

### 1.1 Campaign/Target 구조

- [x] `campaigns/SB-01.yaml`에 11개 Technique flow가 정의되어 있다.
- [x] `targets/SB-01.yaml`에 SB-01 환경 정보와 `log_queries`가 분리되어 있다.
- [x] Technique별 `behavior`와 `evidence_key`가 존재한다.
- [x] `requires` 기반 capability 검증 구조가 있다.
- [ ] 각 Technique마다 실제 실행 모듈이 완전히 존재하는지 재점검한다.
- [ ] 각 Technique마다 “정상/의심/공격” 분류가 명확한지 확인한다.

### 1.2 현재 실제 실행 모듈 상태

| Order | Technique | 현재 상태 | 다음 보완 |
|---:|---|---|---|
| 1 | `T1592` | 로그 근거 확인 | Jenkins endpoint recon 안전 실행 모듈 필요 |
| 2 | `T1078` | 로그 근거 확인 | Jenkins API token 인증 확인 모듈 필요 |
| 3 | `T1190` | 안전 실행 모듈 있음 | marker 기반 ELK 매칭 필요 |
| 4 | `T1213` | 로그 근거 확인 | Jenkins job/config metadata 접근 모듈 필요 |
| 5 | `T1552.001` | 안전 실행 모듈 있음 | marker 기반 ELK 매칭 필요 |
| 6 | `T1552.004` | 안전 실행 모듈 있음 | marker 기반 ELK 매칭 필요 |
| 7 | `T1021.004` | SSH 실행 모듈 있음 | SSH 접속 marker/command 로그 보강 |
| 8 | `T1083` | 디렉터리 탐색 모듈 있음 | auditd marker 매칭 보강 |
| 9 | `T1213.006` | 로그 근거 확인 | PostgreSQL 안전 조회 모듈 필요 |
| 10 | `T1074.001` | 안전 실행 모듈 있음 | staging cleanup 필요 |
| 11 | `T1048.002` | 안전 실행 모듈 있음 | VPC Flow Log 수집 안정화 필요 |

## 2. 가장 먼저 해야 할 핵심 작업

### 2.1 run_id marker 기반 1:1 검증

현재 가장 큰 부족점이다.

지금은 ELK에서 `now-24h` 범위로 비슷한 로그를 찾는다.
좋은 BAS가 되려면 **BAS가 방금 실행한 행위와 ELK 로그가 1:1로 연결**되어야 한다.

구현 체크리스트:

- [ ] `CampaignRunner`가 각 step 실행 시 `execution_id`, `step_order`, `technique_id`를 module params에 자동 주입한다.
- [ ] 각 module은 marker를 생성할 때 `execution_id`를 포함한다.
- [ ] marker 형식을 통일한다.

권장 marker 형식:

```text
SB01_BAS_<TECHNIQUE_ID>_<EXECUTION_ID>
```

예시:

```text
SB01_BAS_T1083_exec-20260521-171424-f2ac34
```

- [ ] ELK query가 기존 범용 조건뿐 아니라 marker 조건을 우선 사용하도록 변경한다.
- [ ] marker 검색이 실패하면 fallback query로 기존 증거를 확인한다.
- [ ] UI의 Evidence 영역에 marker, matched query, matched event timestamp를 표시한다.

완료 기준:

- [ ] BAS 실행 결과에 marker가 표시된다.
- [ ] ELK sample event에서 같은 marker가 확인된다.
- [ ] marker가 없을 때는 “강한 검증 실패, fallback 근거만 확인”으로 표시된다.

## 3. SB-01 ELK 수집 보완 체크리스트

### 3.1 Jenkins 로그

필요 로그:

| 로그 | 목적 | 상태 |
|---|---|---|
| Jenkins access log | Jenkins CLI/API 접근 확인 | 확인 필요 |
| Jenkins build log | job/config/credential 접근 흐름 확인 | 확인 필요 |
| Jenkins Docker container log | CLI, 플러그인, 컨트롤러 이벤트 보완 | 추가 권장 |

체크리스트:

- [ ] Jenkins 서버에 Filebeat가 설치되어 있는지 확인한다.
- [ ] Jenkins access log 경로를 확정한다.
- [ ] Jenkins build log 경로를 확정한다.
- [ ] Docker container json log 수집 여부를 확인한다.
- [ ] Filebeat input에 `fields.sb01_server: jenkins`를 넣는다.
- [ ] Filebeat input에 `fields.sb01_log_type`을 로그별로 넣는다.
- [ ] ELK에서 `sb01_server:jenkins` 검색이 되는지 확인한다.
- [ ] `jenkins_cli_file_read` marker가 access/controller log에 남는지 확인한다.

권장 `log_queries`:

```text
jenkins_host_recon: sb01_server:jenkins AND sb01_log_type:jenkins_access
jenkins_valid_account: sb01_server:jenkins AND sb01_log_type:jenkins_access
jenkins_cli_file_read: sb01_server:jenkins AND sb01_log_type:jenkins_access AND message:<marker>
jenkins_repository_read: sb01_server:jenkins AND sb01_log_type:jenkins_build
jenkins_credentials_file_access: sb01_server:jenkins AND sb01_log_type:jenkins_build
jenkins_private_key_discovery: sb01_server:jenkins AND sb01_log_type:jenkins_build
```

### 3.2 App 서버 로그

필요 로그:

| 로그 | 목적 | 상태 |
|---|---|---|
| `/var/log/auth.log` | Jenkins -> App SSH 접속 확인 | 구성됨 |
| `/var/log/audit/audit.log` | 운영 경로 접근, staging 확인 | 구성됨 |
| nginx access log | App HTTP 접근 확인 | 추가 권장 |
| Docker container log | App API 내부 로그 확인 | 추가 권장 |

체크리스트:

- [ ] App 서버 Filebeat가 system/auth log를 수집하는지 확인한다.
- [ ] auditd rule이 `/opt/spacebar-booking` 접근을 잡는지 확인한다.
- [ ] auditd rule이 `/tmp/sb01-bas-stage-*` 생성도 잡는지 검토한다.
- [ ] `T1021.004` SSH 실행 시 `/var/log/auth.log`에 Jenkins source IP가 남는지 확인한다.
- [ ] `T1083` 실행 시 auditd에 `process.executable:/usr/bin/ls`가 남는지 확인한다.
- [ ] `T1074.001` 실행 시 `/tmp/sb01-bas-stage-*` marker가 추적되는지 확인한다.

권장 auditd rule:

```text
-w /opt/spacebar-booking -p r -k sb01_app_path_read
-w /tmp -p wa -k sb01_tmp_staging
```

### 3.3 PostgreSQL 로그

현재 부족한 부분이다.

필요 로그:

| 로그 | 목적 |
|---|---|
| PostgreSQL connection log | App 또는 Jenkins에서 DB 접속 확인 |
| PostgreSQL statement log | 안전한 조회 쿼리 확인 |

체크리스트:

- [ ] DB 서버 Filebeat 설치 여부를 확인한다.
- [ ] PostgreSQL log 경로를 확인한다.
- [ ] `log_connections=on` 상태를 확인한다.
- [ ] 안전한 조회 쿼리만 실행하는 `T1213.006` 모듈을 만든다.
- [ ] DB query marker를 SQL comment로 남길 수 있는지 확인한다.

예시 marker query:

```sql
/* SB01_BAS_T1213_006_exec-xxxx */
select count(*) from bookings;
```

권장 `log_queries`:

```text
db_postgresql_access: sb01_server:db AND sb01_log_type:postgresql AND message:<marker>
```

### 3.4 AWS VPC Flow Log

현재 `T1048.002` 검증의 핵심이다.

체크리스트:

- [ ] VPC Flow Log가 활성화되어 있는지 확인한다.
- [ ] Flow Log가 S3/CloudWatch 중 어디로 가는지 확인한다.
- [ ] ELK 수집 경로가 있는지 확인한다.
- [ ] `source.ip`가 App 서버 private IP로 들어오는지 확인한다.
- [ ] `destination.port:443` outbound가 잡히는지 확인한다.
- [ ] VPC Flow Log는 payload/HTTP path를 볼 수 없다는 한계를 문서화한다.

주의:

- VPC Flow Log는 “443으로 나갔다”는 네트워크 증거다.
- 어떤 파일을 보냈는지, HTTP body가 무엇인지는 알 수 없다.
- 그래서 `T1048.002`는 Filebeat/App 로그와 VPC Flow Log를 함께 보는 것이 좋다.

## 4. BasAgent 고도화 체크리스트

### 4.1 Agent 실행 모드

현재 기본값은 `simulation`이다.

체크리스트:

- [ ] `agent_runtime/config.sb01.yaml`에 `execution_mode: simulation/real` 의미를 주석으로 설명한다.
- [ ] real mode 실행 전 capability check를 수행한다.
- [ ] real mode에서 필요한 바이너리 확인 기능을 추가한다.

필요 확인 항목:

| 대상 | 확인 |
|---|---|
| Jenkins | `java`, `curl`, Jenkins CLI jar 존재 여부 |
| App | `ssh`, deploy key, target host 접근 가능 여부 |
| DB | `psql` 또는 DB 접속 방식 |
| ELK | `localhost:9200` 연결 가능 여부 |

### 4.2 Agent 설치/운영

체크리스트:

- [ ] `scripts/install-agent-linux.sh` 작성
- [ ] `scripts/install-agent-windows.ps1` 작성
- [ ] systemd service 예시 작성
- [ ] Windows scheduled task 또는 service 예시 작성
- [ ] agent heartbeat에 OS/platform 추가
- [ ] agent heartbeat에 capability 목록 추가
- [ ] agent heartbeat에 마지막 실행 시간 추가
- [ ] agent heartbeat에 execution mode 표시

### 4.3 Agent 안전장치

체크리스트:

- [ ] kill switch 추가
- [ ] step timeout 기본값 설정
- [ ] cleanup 함수 인터페이스 추가
- [ ] dry-run 모드 추가
- [ ] 민감 경로 denylist 추가
- [ ] stdout/stderr secret masking 추가

민감 출력 금지 예시:

```text
BEGIN OPENSSH PRIVATE KEY
password=
token=
secret=
credential=
```

## 5. BAS 실행 모드 개선 체크리스트

현재 실행 방식은 Operation Queue + Campaign 실행 중심이다.
상용 BAS처럼 보이려면 실행 모드를 명확히 나눠야 한다.

| 모드 | 의미 | 필요 여부 |
|---|---|---|
| Atomic | 선택한 Technique 하나만 실행 | 필수 |
| Chain | 선택한 Technique + 의존 단계 실행 | 필수 |
| Full Campaign | 캠페인 전체 실행 | 필수 |

체크리스트:

- [ ] UI에 `Atomic`, `Chain`, `Full Campaign` 실행 버튼을 분리한다.
- [ ] API request에 `execution_scope` 필드를 추가한다.
- [ ] `Atomic`에서는 `depends_on_orders`를 자동 포함하지 않는다.
- [ ] `Chain`에서는 `depends_on_orders`를 포함한다.
- [ ] `Full Campaign`에서는 전체 flow를 실행한다.
- [ ] 실행 결과에 `operation_mode`를 명확히 표시한다.

## 6. Detection Gap 분석 체크리스트

현재는 탐지 여부만 보여주는 수준이다.
좋은 BAS는 미탐일 때 “왜 안 잡혔는지”를 알려줘야 한다.

체크리스트:

- [ ] `elk_check.matched=false`일 때 gap reason을 생성한다.
- [ ] `query_source=missing`이면 target YAML에 query 추가 필요로 표시한다.
- [ ] Elasticsearch 연결 실패면 ELK 상태 문제로 분리한다.
- [ ] event count 0이면 수집기/룰/시간범위 문제로 분리한다.
- [ ] Technique별 필요한 로그 소스를 매핑한다.
- [ ] 미탐 시 보완 KQL 예시를 출력한다.

Gap reason 예시:

| 상황 | 원인 후보 | 보완 |
|---|---|---|
| ELK 연결 실패 | ELK down, port forwarding 없음 | ELK 상태 확인 |
| query 없음 | target YAML 미작성 | `log_queries` 추가 |
| event 0 | Filebeat 미수집, auditd rule 없음 | agent/rule 보완 |
| marker 없음 | 모듈 marker 미삽입 | module 수정 |
| marker는 있으나 Technique 필드 없음 | 파서/정규화 부족 | ingest pipeline 보완 |

## 7. Report Export 체크리스트

발표/포트폴리오 설득력을 높이는 기능이다.

체크리스트:

- [ ] 실행 결과 Markdown export 추가
- [ ] Technique별 실행 상태 표 생성
- [ ] Technique별 ELK query 출력
- [ ] sample event 출력
- [ ] 미탐 보완안 출력
- [ ] 실행 환경 정보 출력
- [ ] 실행 시간과 agent 정보 출력

권장 보고서 구조:

```text
1. Campaign Summary
2. Execution Environment
3. Technique Execution Result
4. Detection Validation
5. Evidence Samples
6. Detection Gaps
7. Recommended Improvements
```

## 8. SB-01 v1 완료 기준

SB-01 BAS v1은 아래 조건을 만족하면 “1차 완성”으로 본다.

- [ ] 11개 Technique이 모두 module로 연결되어 있다.
- [ ] 최소 8개 이상 Technique이 실제 안전 실행 모듈을 가진다.
- [ ] 모든 실행 모듈이 `simulation`과 `real` 모드를 지원한다.
- [ ] 모든 실행 모듈이 marker/canary를 남긴다.
- [ ] ELK가 marker 기반으로 최소 6개 이상 Technique을 1:1 검증한다.
- [ ] marker 검증이 어려운 로그는 그 한계를 문서화한다.
- [ ] 미탐 Technique은 gap reason과 보완안을 출력한다.
- [ ] 실행 결과 Markdown report를 생성할 수 있다.
- [ ] cleanup 또는 안전한 임시 파일 관리가 가능하다.

## 9. AD/다른 팀원 환경 확장 체크리스트

SB-01에서 만든 구조를 다른 환경에 붙일 때는 아래 순서로 진행한다.

### 9.1 공통 절차

- [ ] 팀원 캠페인의 `Techniques Used` 목록을 확정한다.
- [ ] Technique별 안전 실행 가능 여부를 분류한다.
- [ ] 로그 소스와 주요 Event ID/필드를 정리한다.
- [ ] `campaigns/SB-XX.yaml`을 만든다.
- [ ] `targets/SB-XX.yaml`을 만든다.
- [ ] 필요한 module을 만든다.
- [ ] ELK/Wazuh query를 연결한다.
- [ ] simulation 실행을 먼저 검증한다.
- [ ] real safe mode 실행을 검증한다.

### 9.2 AD/Windows 전용

권장 언어:

```text
Python BasAgent + PowerShell 실행 모듈
```

체크리스트:

- [ ] Windows BasAgent 실행 방법을 정한다.
- [ ] PowerShell 실행 wrapper를 만든다.
- [ ] Winlogbeat 수집 상태를 확인한다.
- [ ] Sysmon 설치 여부를 확인한다.
- [ ] Security Event ID 수집 여부를 확인한다.
- [ ] `T1558.003` Kerberoasting은 DC Event ID `4769`로 검증한다.
- [ ] `T1059.001` PowerShell은 Event ID `4104` 또는 Sysmon `1`로 검증한다.
- [ ] `T1021.001` RDP는 Event ID `4624`, LogonType `10`으로 검증한다.
- [ ] 위험한 credential dump는 실제 탈취 대신 안전한 접근 시도/탐지 이벤트로 대체한다.

## 10. 다음 작업 순서 추천

가장 효율적인 순서:

1. `CampaignRunner`에서 `execution_id`를 각 module에 주입
2. SB-01 신규/기존 module에 marker 통일 적용
3. ELK checker를 marker 우선 검증으로 개선
4. App auditd `/tmp` staging rule 추가
5. PostgreSQL 안전 조회 모듈 추가
6. Jenkins Docker/container log 수집 보완
7. UI 실행 모드 `Atomic / Chain / Full Campaign` 분리
8. Detection Gap reason 출력
9. Markdown report export 추가
10. AD/Windows module template 작성

## 11. 오늘 당장 착수할 3개

우선순위를 줄이면 아래 3개부터 한다.

- [ ] `execution_id` marker를 모든 module에 자동 주입한다.
- [ ] `T1213.006` PostgreSQL 안전 조회 모듈을 만든다.
- [ ] ELK checker에서 marker query와 fallback query를 분리한다.

이 3개가 끝나면 SB-01 BAS는 “실행과 탐지 검증이 연결된다”는 설득력이 크게 올라간다.

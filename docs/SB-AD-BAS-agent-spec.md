# SB-AD BAS Multi-Agent Specification

## 1. 결론

SB-AD 환경에 BAS 에이전트를 설치하고 실제 Kibana Security 탐지 룰을 검증하는 구조는 구현 가능하다.

권장 설치 대상은 3곳이다.

| 설치 위치 | Agent role | 설치 여부 | 목적 |
| --- | --- | --- | --- |
| PC01 | `pc01` | 설치 | 사용자 PC 행위, 도메인 조회, WinRM 기반 FS01 명령 전달 |
| FS01 | `fs01` | 설치 | FS01 내부 로컬 행위, 특히 LSASS dump 같은 민감 행위 |
| Attacker Ubuntu | `attacker` | 설치 | Impacket, DCSync, HTTP 파일 제공, upload 수신 |
| DC01 | 없음 | 설치 안 함 | 도메인 컨트롤러는 로그 발생/탐지 대상만 담당 |
| ELK | 없음 | 설치 안 함 | Controller가 Elasticsearch/Kibana API로 조회 |

핵심은 단순히 3곳에 에이전트를 설치하는 것이 아니라, Controller가 각 테크닉의 `agent_role`을 보고 올바른 Agent에 작업을 분배하는 multi-agent routing 구조를 만드는 것이다.

## 2. 현재 확인된 환경

AWS 인스턴스는 읽기 전용으로 다음 상태를 확인했다.

| 자산 | OS 계열 | Private IP | Public IP | 상태 |
| --- | --- | --- | --- | --- |
| MyCompany-PC01 | Windows | `10.0.4.216` | `43.201.217.167` | running |
| MyCompany-FS01 | Windows | `10.0.10.77` | `3.36.156.17` | running |
| MyCompany-DC01 | Windows | `10.0.13.205` | `52.78.216.139` | running |
| Attacker-Ubuntu | Linux | `10.0.1.194` | `54.180.55.229` | running |
| elk-gh | Linux | `10.0.4.30` | `54.116.120.198` | running |

도메인/호스트 기준값은 `targets/SB-AD.yaml`을 기준으로 한다.

| 항목 | 값 |
| --- | --- |
| AD domain | `mycompany.local` |
| NetBIOS domain | `MYCOMPANY` |
| PC01 FQDN | `PC01.mycompany.local` |
| FS01 FQDN | `FS01.mycompany.local` |
| DC01 FQDN | `DC01.mycompany.local` |
| Attacker private IP | `10.0.1.194` |
| ELK private IP | `10.0.4.30` |

## 3. 전체 아키텍처

권장 구조는 Controller를 Attacker Ubuntu에 두고, PC01/FS01/Attacker Agent가 Controller로 outbound polling하는 방식이다.

```text
Operator Browser
      |
      | SSH tunnel or restricted internal HTTP
      v
Attacker Ubuntu
  - BAS Controller API
  - optional frontend hosting
  - Attacker BasAgent
  - HTTP file server / upload server
      |
      +-- PC01 BasAgent      outbound -> Controller
      +-- FS01 BasAgent      outbound -> Controller
      +-- Controller         query -> Elasticsearch/Kibana
      |
      +-- DC01               no agent, log source only
```

이 구조의 장점:

- Agent VM에는 inbound port를 새로 열 필요가 없다.
- Controller가 VPC 내부 IP로 PC01/FS01/Attacker 상태를 관리한다.
- Operator는 SSH tunnel로 로컬 브라우저에서 대시보드를 볼 수 있다.
- DC01에는 실행 코드를 올리지 않기 때문에 도메인 컨트롤러 오염 가능성이 줄어든다.

## 4. 통신 포트와 네트워크 조건

### 4.1 필수 통신

| 방향 | 포트 | 용도 | 권장 허용 범위 |
| --- | --- | --- | --- |
| PC01 -> Attacker | TCP 8000 | BasAgent가 Controller API polling | VPC 내부만 |
| FS01 -> Attacker | TCP 8000 | BasAgent가 Controller API polling | VPC 내부만 |
| Attacker -> Attacker | TCP 8000 | Attacker Agent local/controller 통신 | localhost/VPC |
| Controller -> ELK | TCP 9200 또는 Kibana API | source log / alert 확인 | Controller 위치만 |
| Operator -> Attacker | TCP 443 또는 22 | SSH tunnel | 사용자 IP만 |
| PC01/FS01 -> Attacker | TCP 80 | T1105 파일 다운로드 | VPC 내부만 |
| FS01/PC01 -> Attacker | TCP 8080 | T1041 upload 검증 | VPC 내부만 |

### 4.2 피해야 할 구성

- PC01/FS01에 Controller inbound port를 열지 않는다.
- DC01에 BAS Agent를 설치하지 않는다.
- Attacker Controller TCP 8000을 `0.0.0.0/0`에 공개하지 않는다.
- Elasticsearch 9200을 외부 전체에 공개하지 않는다.

## 5. 코드 구성과 패키징

Controller와 Agent는 같은 코드베이스를 사용한다.

배포에 포함할 항목:

- `agent_runtime/`
- `bas/`
- `campaigns/`
- `modules/`
- `targets/`
- `api.py`
- `requirements.txt`

배포에서 제외할 항목:

- `.git/`
- `frontend/node_modules/`
- `frontend/dist/`
- `outputs/`
- `.env`
- 접속키, 비밀번호, 해시, 토큰
- 임시 dump, 업로드 결과, 실행 로그

공통 Python 의존성:

```text
fastapi
uvicorn
PyYAML
```

Agent 자체는 Controller 통신에 Python 표준 라이브러리 `urllib`를 사용한다. 다만 같은 코드베이스에서 campaign/target YAML을 읽기 때문에 `PyYAML`은 공통으로 설치하는 편이 안전하다.

## 6. Multi-Agent Routing 설계

### 6.1 현재 구조의 한계

현재 BAS는 다음 흐름이다.

```text
UI -> POST /jobs -> 단일 agent_id에 job 생성 -> 해당 Agent가 전체 selected_steps 실행
```

이 방식은 PC01 단계만 실행할 때는 동작하지만, SB-AD 전체 시나리오에는 부족하다. 예를 들어 13번은 `fs01`, 19번은 `attacker`가 실행해야 하는데 PC01 Agent 하나에 전체 job을 주면 해당 단계가 role mismatch로 스킵될 수 있다.

### 6.2 목표 구조

새 구조는 `Operation`을 부모 단위로 두고, 각 step을 알맞은 Agent에게 sub-job으로 나눠 보낸다.

```text
UI -> POST /operations
Controller:
  1. selected_steps 확정
  2. depends_on_orders 반영
  3. order 기준 정렬
  4. 각 step의 agent_role 추출
  5. online Agent 확인
  6. step별 sub-job 생성
  7. 순서대로 실행
  8. 결과 병합
  9. ELK source query + alert query 확인
```

### 6.3 순서 보존 방식

SB-AD는 공격 시나리오 순서가 중요하므로 처음 구현은 병렬 실행이 아니라 sequential routing으로 한다.

```text
for step in selected_steps sorted by order:
    role = resolve_agent_role(step)
    agent = select_online_agent(role)
    create sub-job for one step
    wait until sub-job completed/failed/timeout
    run ELK check or attach agent-provided check
    append result to operation
    if critical dependency failed:
        mark dependent steps as blocked or skipped
```

이 방식을 선택하는 이유:

- 10번 WinRM 성공 후 11/12/15/16이 의미를 가진다.
- 15번 staging 후 16번 exfiltration이 의미를 가진다.
- 13번, 19번 같은 민감 단계는 앞 단계와 분리해서 통제해야 한다.
- 탐지 시점과 alert 생성 대기 시간을 step 단위로 다루기 쉽다.

### 6.4 Agent role 추출 규칙

우선순위:

1. `step.params.commands[0].agent_role`
2. `step.params.agent_role`
3. `step.agent_role`
4. 없으면 `manual_operator`로 분류하고 실행 차단

현재 SB-AD YAML은 `commands[].agent_role`에 role이 들어 있다.

### 6.5 Agent 등록 스키마 확장

기존 등록 정보:

```json
{
  "agent_id": "sbad-pc01-bas-agent",
  "campaign_agent_id": "SB-AD",
  "display_name": "SB-AD PC01 BasAgent",
  "collector_type": "winlogbeat"
}
```

확장 권장:

```json
{
  "agent_id": "sbad-pc01-bas-agent",
  "campaign_agent_id": "SB-AD",
  "agent_role": "pc01",
  "hostname": "PC01.mycompany.local",
  "platform": "windows",
  "collector_type": "winlogbeat",
  "execution_mode": "simulation",
  "capabilities": [
    "windows",
    "powershell",
    "cmd",
    "winrm",
    "sysmon",
    "windows_security"
  ]
}
```

### 6.6 Operation 데이터 구조

```json
{
  "operation_id": "op-20260524-120000-ab12cd",
  "campaign_id": "SB-AD",
  "status": "running",
  "operation_mode": "multi_agent",
  "created_at": "2026-05-24T12:00:00+09:00",
  "started_at": "2026-05-24T12:00:01+09:00",
  "finished_at": null,
  "requested_steps": [
    {"campaign_id": "SB-AD", "order": 10},
    {"campaign_id": "SB-AD", "order": 13}
  ],
  "final_steps": [
    {"order": 10, "agent_role": "pc01", "agent_id": "sbad-pc01-bas-agent"},
    {"order": 13, "agent_role": "fs01", "agent_id": "sbad-fs01-bas-agent"}
  ],
  "sub_jobs": [],
  "steps": [],
  "summary": {
    "total": 0,
    "success": 0,
    "failed": 0,
    "blocked": 0,
    "detected": 0,
    "missed": 0,
    "not_checked": 0
  }
}
```

### 6.7 Sub-job 데이터 구조

```json
{
  "job_id": "job-20260524-120001-ef34aa",
  "operation_id": "op-20260524-120000-ab12cd",
  "agent_id": "sbad-pc01-bas-agent",
  "agent_role": "pc01",
  "campaign_id": "SB-AD",
  "selected_steps": [
    {"campaign_id": "SB-AD", "order": 10, "inputs": {}}
  ],
  "include_normal": false,
  "status": "queued",
  "created_at": "2026-05-24T12:00:01+09:00",
  "started_at": null,
  "finished_at": null,
  "result": null,
  "error": null
}
```

### 6.8 API 추가 명세

신규 API:

| Method | Path | 용도 |
| --- | --- | --- |
| `POST` | `/operations` | multi-agent operation 생성 |
| `GET` | `/operations` | operation 목록 조회 |
| `GET` | `/operations/{operation_id}` | operation 상세 조회 |
| `POST` | `/operations/{operation_id}/cancel` | queued/running operation 취소 |

기존 API 유지:

| Method | Path | 용도 |
| --- | --- | --- |
| `POST` | `/agents/register` | Agent 등록 |
| `POST` | `/agents/{agent_id}/heartbeat` | Agent heartbeat |
| `GET` | `/agents/{agent_id}/jobs/next` | Agent job polling |
| `POST` | `/agents/{agent_id}/jobs/{job_id}/result` | Agent 결과 업로드 |

### 6.9 Agent 선택 규칙

Controller는 다음 기준으로 Agent를 선택한다.

1. `campaign_agent_id == "SB-AD"`
2. `agent_role == required_role`
3. `status == "online"`
4. `last_heartbeat_at`이 최근 N초 이내
5. `execution_mode`가 요청 모드와 맞거나, request가 simulation이면 simulation agent 허용

동일 role Agent가 여러 개면:

1. `preferred_agent_id`가 있으면 우선
2. 가장 최근 heartbeat
3. running job이 가장 적은 Agent

## 7. SB-AD 테크닉별 라우팅

| 순번 | MITRE | 행위 | Agent role | 필수 선행 | 위험도 |
| --- | --- | --- | --- | --- | --- |
| 2 | T1059.003 | Windows Command Shell | `pc01` | 없음 | high |
| 3 | T1095 | Non-Application Layer Protocol | `pc01` | 없음 | high |
| 4 | T1087.002 | Domain Account Discovery | `pc01` | 없음 | low |
| 5 | T1018 | Remote System Discovery | `pc01` | 없음 | low |
| 6 | T1033 | System Owner/User Discovery | `pc01` | 없음 | low |
| 10 | T1021.006 | WinRM Remote Execution | `pc01` | 없음 | high |
| 11 | T1059.001 | PowerShell Over WinRM | `pc01` | 10 | high |
| 12 | T1105 | Ingress Tool Transfer | `pc01` | 10, attacker HTTP 준비 | medium |
| 13 | T1003.001 | LSASS Memory Dump | `fs01` | 10 권장 | critical |
| 15 | T1074.001 | Local Data Staging | `pc01` | 10 | high |
| 16 | T1041 | Exfiltration Over C2 | `pc01` | 15, attacker upload 준비 | high |
| 19 | T1003.006 | DCSync | `attacker` | 도메인 권한/해시 준비 | critical |

## 8. Controller 설치 명세

### 8.1 설치 위치

권장 위치: Attacker Ubuntu

이유:

- PC01/FS01와 같은 VPC에서 private IP로 통신 가능
- Attacker Agent, 파일 서버, 업로드 서버와 같은 보조 기능을 함께 관리 가능
- Operator는 기존 SSH 접속 경로를 사용해 tunnel 가능

### 8.2 설치 경로

```bash
/opt/spacebar-BAS
```

### 8.3 의존성

필수:

- Ubuntu 계열 Linux
- Python 3.10 이상
- `python3-venv`
- Git 또는 zip/scp 배포 수단
- Controller TCP 8000을 VPC 내부에서 접근 가능

권장:

- systemd 서비스
- 로그 디렉터리 `/var/log/spacebar-bas`
- 실행 결과 디렉터리 `/opt/spacebar-BAS/outputs`

### 8.4 Controller 환경 변수

민감값은 파일에 저장하지 않고 실행 세션 또는 systemd drop-in에만 둔다.

| 변수 | 필수 | 용도 |
| --- | --- | --- |
| `BAS_ELK_URL` | 권장 | Elasticsearch API URL |
| `BAS_ELK_USERNAME` | 필요 시 | Elasticsearch Basic Auth 사용자 |
| `BAS_ELK_PASSWORD` | 필요 시 | Elasticsearch Basic Auth 비밀번호 |
| `BAS_OPERATION_MODE` | 선택 | `simulation` 또는 `real` 기본값 |
| `BAS_ALERT_LOOKBACK_MINUTES` | 선택 | alert 확인 lookback |
| `BAS_STEP_ALERT_WAIT_SECONDS` | 선택 | step 실행 후 alert 생성 대기 시간 |

예시:

```bash
export BAS_ELK_URL="http://10.0.4.30:9200"
export BAS_ELK_USERNAME="<manual input only>"
export BAS_ELK_PASSWORD="<manual input only>"
```

### 8.5 실행

```bash
cd /opt/spacebar-BAS
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

### 8.6 systemd 서비스 예시

```ini
[Unit]
Description=Spacebar BAS Controller
After=network-online.target

[Service]
WorkingDirectory=/opt/spacebar-BAS
ExecStart=/opt/spacebar-BAS/.venv/bin/python -m uvicorn api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
User=ubuntu
Environment=BAS_OPERATION_MODE=simulation

[Install]
WantedBy=multi-user.target
```

## 9. PC01 BasAgent 설치 명세

### 9.1 역할

PC01 Agent는 가장 많은 테크닉을 담당한다.

- 2: cmd 실행
- 3: 외부 TCP 연결
- 4: 도메인 계정 조회
- 5: 원격 시스템 조회
- 6: 현재 사용자 확인
- 10: WinRM으로 FS01 원격 실행
- 11: WinRM 기반 PowerShell
- 12: FS01에 도구 다운로드
- 15: FS01 공유 경로에 synthetic artifact 생성
- 16: FS01에서 Attacker upload endpoint로 전송

### 9.2 설치 위치

```powershell
C:\SpacebarBAS
```

### 9.3 의존성

필수:

- Windows Server 계열 또는 Windows PC
- Python 3.10 이상
- PowerShell 5.1 이상
- `cmd.exe`, `powershell.exe`
- 도메인 DNS 정상
- PC01에서 FS01 WinRM 접근 가능
- PC01에서 Attacker Controller `10.0.1.194:8000` 접근 가능
- PC01에서 Attacker HTTP/upload 포트 접근 가능

로그 수집 조건:

- Sysmon process creation event 수집
- PowerShell logging/Script Block logging 수집
- Winlogbeat 또는 Elastic Agent 정상 동작

### 9.4 설정 파일

권장 `agent_runtime/config.sbad-pc01.yaml`:

```yaml
agent_id: sbad-pc01-bas-agent
campaign_agent_id: SB-AD
agent_role: pc01
hostname: PC01.mycompany.local
platform: windows
display_name: SB-AD PC01 BasAgent
collector_type: winlogbeat
controller_url: http://10.0.1.194:8000
interval_seconds: 2
execution_mode: simulation
capabilities: windows,powershell,cmd,winrm,sysmon,windows_security,active_directory,network
```

현재 Agent 파서는 단순 `key: value` 형태이므로 `capabilities`는 1차 구현에서는 comma-separated string으로 두고, 이후 PyYAML 기반으로 배열을 지원하는 것을 권장한다.

### 9.5 환경 변수

Simulation 모드:

```powershell
$env:BAS_AGENT_ROLE = "pc01"
```

Real 모드 공통:

```powershell
$env:BAS_AGENT_ROLE = "pc01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
```

WinRM 기반 단계 실행 시:

```powershell
$env:BAS_SVC_FILE_PASSWORD = "<manual input only>"
```

주의:

- `BAS_SVC_FILE_PASSWORD`는 config 파일, repo, output에 저장하지 않는다.
- 실행 세션이 끝나면 환경 변수 세션도 닫는다.
- 가능하면 Windows Credential Manager 또는 일회성 interactive input으로 개선한다.

### 9.6 실행 방식

초기 검증:

```powershell
cd C:\SpacebarBAS
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode simulation
```

Real 모드:

```powershell
cd C:\SpacebarBAS
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode real
```

상시 실행은 Windows Scheduled Task가 무난하다. 단, real mode는 실수 방지를 위해 처음에는 수동 실행을 권장한다.

### 9.7 PC01 preflight checklist

실행 전 확인:

- `python --version`
- Controller 접근 가능
- `Resolve-DnsName FS01.mycompany.local`
- `Test-NetConnection FS01.mycompany.local -Port 5985`
- `Test-NetConnection 10.0.1.194 -Port 8000`
- `Test-NetConnection 10.0.1.194 -Port 80`
- `Test-NetConnection 54.180.55.229 -Port 8080`
- `whoami`
- `net group /domain`이 정상 실행되는지 확인

## 10. FS01 BasAgent 설치 명세

### 10.1 역할

FS01 Agent는 FS01 내부에서 직접 실행해야 의미가 있는 민감 행위를 담당한다.

- 13: LSASS Memory Dump

PC01에서 WinRM으로 FS01에 명령을 내리는 방식도 가능하지만, BAS 관점에서는 FS01 내부 행위를 FS01 Agent가 담당하는 편이 더 명확하다.

### 10.2 설치 위치

```powershell
C:\SpacebarBAS
```

### 10.3 의존성

필수:

- Windows Server 계열
- Python 3.10 이상
- PowerShell 5.1 이상
- 관리자 권한 또는 필요한 프로세스 접근 권한
- FS01에서 Controller `10.0.1.194:8000` 접근 가능
- Sysmon Event ID 10 Process Access 수집 설정

로그 수집 조건:

- Sysmon Event ID 10 Process Access
- Sysmon Event ID 11 File Create
- Windows Security Log
- Winlogbeat 또는 Elastic Agent 정상 동작

### 10.4 설정 파일

권장 `agent_runtime/config.sbad-fs01.yaml`:

```yaml
agent_id: sbad-fs01-bas-agent
campaign_agent_id: SB-AD
agent_role: fs01
hostname: FS01.mycompany.local
platform: windows
display_name: SB-AD FS01 BasAgent
collector_type: winlogbeat
controller_url: http://10.0.1.194:8000
interval_seconds: 2
execution_mode: simulation
capabilities: windows,powershell,sysmon,windows_security,credential_test
```

### 10.5 환경 변수

Simulation 모드:

```powershell
$env:BAS_AGENT_ROLE = "fs01"
```

Real 모드:

```powershell
$env:BAS_AGENT_ROLE = "fs01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
```

LSASS dump 같은 민감 테스트를 실제로 허용할 때만:

```powershell
$env:BAS_ENABLE_CREDENTIAL_TESTS = "1"
```

### 10.6 실행 방식

초기 검증:

```powershell
cd C:\SpacebarBAS
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode simulation
```

Real 모드는 elevated PowerShell에서 수동 실행을 권장한다.

```powershell
cd C:\SpacebarBAS
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode real
```

### 10.7 FS01 preflight checklist

- `python --version`
- Controller 접근 가능
- `Test-NetConnection 10.0.1.194 -Port 8000`
- Sysmon Event ID 10 수집 여부 확인
- `Get-Process lsass` 조회 가능 여부 확인
- `C:\Windows\Temp` 쓰기 가능 여부 확인
- 테스트 종료 후 dump 파일 삭제 절차 준비

### 10.8 FS01 cleanup

민감 테스트 후 반드시 확인:

- `C:\Windows\Temp\lsass.dmp` 삭제
- 테스트용 파일만 삭제하고 운영 파일은 건드리지 않음
- Winlogbeat/Elastic Agent 상태 확인
- FS01 디스크 사용량 확인

## 11. Attacker Ubuntu BasAgent 설치 명세

### 11.1 역할

Attacker Agent는 공격자 측 준비와 도메인 침해급 테스트를 담당한다.

- 12번 T1105용 HTTP file server 준비
- 16번 T1041용 upload server 준비
- 19번 T1003.006 DCSync 실행
- Impacket 도구 경로 확인

### 11.2 설치 위치

Controller와 같은 경로를 사용할 수 있다.

```bash
/opt/spacebar-BAS
```

### 11.3 의존성

필수:

- Ubuntu/Linux
- Python 3.10 이상
- `python3-venv`
- Impacket 또는 `/home/ubuntu/impacket/examples`
- Controller API가 local 또는 private IP로 접근 가능
- Attacker inbound TCP 80, 8080은 VPC 내부에서만 허용

권장:

- `Rubeus.exe` 또는 대체 테스트 파일 위치 확인
- `upload_server.py` 위치 확인
- `/home/ubuntu/analysis` 또는 별도 output 디렉터리

### 11.4 설정 파일

권장 `agent_runtime/config.sbad-attacker.yaml`:

```yaml
agent_id: sbad-attacker-bas-agent
campaign_agent_id: SB-AD
agent_role: attacker
hostname: Attacker-Ubuntu
platform: linux
display_name: SB-AD Attacker BasAgent
collector_type: manual
controller_url: http://10.0.1.194:8000
interval_seconds: 2
execution_mode: simulation
capabilities: linux,bash,impacket,attacker_host,http_server,upload_server
```

### 11.5 환경 변수

Simulation 모드:

```bash
export BAS_AGENT_ROLE=attacker
```

Real 모드:

```bash
export BAS_AGENT_ROLE=attacker
export BAS_ALLOW_REAL_EXECUTION=1
```

DCSync 같은 도메인 침해급 테스트를 실제로 허용할 때만:

```bash
export BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1
export BAS_DA_NTLM_HASH="<manual input only>"
```

주의:

- `BAS_DA_NTLM_HASH`는 파일에 저장하지 않는다.
- shell history에 남지 않도록 입력 방식 개선을 고려한다.
- 가능한 경우 read prompt 또는 임시 protected file descriptor 방식을 사용한다.

### 11.6 실행 방식

초기 검증:

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
python agent_runtime/bas_agent.py --config agent_runtime/config.sbad-attacker.yaml --execution-mode simulation
```

Real 모드:

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
python agent_runtime/bas_agent.py --config agent_runtime/config.sbad-attacker.yaml --execution-mode real
```

### 11.7 Attacker preflight checklist

- `python3 --version`
- Controller API local 접근 가능
- `curl http://127.0.0.1:8000/health`
- `ls /home/ubuntu/impacket/examples`
- `test -f /home/ubuntu/Rubeus.exe` 또는 파일 제공 대상 확인
- TCP 80, 8080 사용 중인지 확인
- `upload_server.py` 실행 가능 여부 확인

### 11.8 보조 서비스 설계

12번과 16번은 보조 서버가 필요하다.

| 서비스 | 기본 포트 | 담당 단계 | 권장 동작 |
| --- | --- | --- | --- |
| HTTP file server | 80 | 12 | T1105 실행 전에만 시작 |
| Upload server | 8080 | 16 | T1041 실행 전에만 시작 |

향후 구현에서는 Attacker Agent에 preflight step을 둔다.

```text
preflight:
  - ensure_http_server(port=80, root=/home/ubuntu)
  - ensure_upload_server(port=8080, output=/home/ubuntu/analysis/uploads)
```

서비스 종료 정책:

- 단발 테스트면 operation 종료 후 중지
- 반복 훈련이면 Controller가 `service_state: persistent`로 표시
- 포트 충돌 시 operation을 blocked로 처리

## 12. 환경 변수 전체 표

### 12.1 공통

| 변수 | 위치 | 필수 | 설명 |
| --- | --- | --- | --- |
| `BAS_AGENT_ROLE` | 모든 Agent | 필수 | `pc01`, `fs01`, `attacker` 중 하나 |
| `BAS_ALLOW_REAL_EXECUTION` | 모든 Agent | real 시 필수 | 실제 명령 실행 허용 |
| `BAS_CONTROLLER_URL` | 선택 | 선택 | config override용 |

### 12.2 PC01

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `BAS_SVC_FILE_PASSWORD` | 10/11/12/15/16 real 시 필수 | FS01 WinRM에 사용할 `svc_file` 비밀번호 |

### 12.3 FS01

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `BAS_ENABLE_CREDENTIAL_TESTS` | 13 real 시 필수 | LSASS dump 같은 자격 증명 테스트 허용 |

### 12.4 Attacker

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS` | 19 real 시 필수 | DCSync 같은 도메인 침해급 테스트 허용 |
| `BAS_DA_NTLM_HASH` | 19 real 시 필수 | DCSync 테스트용 도메인 권한 해시 |

### 12.5 Controller

| 변수 | 필수 | 설명 |
| --- | --- | --- |
| `BAS_ELK_URL` | 권장 | Elasticsearch endpoint |
| `BAS_ELK_USERNAME` | 필요 시 | Elasticsearch 사용자 |
| `BAS_ELK_PASSWORD` | 필요 시 | Elasticsearch 비밀번호 |
| `BAS_STEP_ALERT_WAIT_SECONDS` | 선택 | 탐지 룰 alert 생성 대기 |
| `BAS_ALERT_LOOKBACK_MINUTES` | 선택 | alert 검색 범위 |

## 13. ELK 탐지 검증 설계

ELK 검증은 Agent가 아니라 Controller 중심으로 수행하는 것을 권장한다.

이유:

- ELK 인증 정보가 각 Agent에 퍼지지 않는다.
- source query와 alert query를 한 곳에서 통제한다.
- 결과 병합이 쉽다.

검증 순서:

```text
step 실행 완료
wait BAS_STEP_ALERT_WAIT_SECONDS
source log query 실행
alert query 실행
matched/missed/not_checked 판정
operation step result에 저장
```

판정 필드:

```json
{
  "elk_check": {
    "source": {
      "checked": true,
      "matched": true,
      "event_count": 3,
      "query": "..."
    },
    "alert": {
      "checked": true,
      "matched": true,
      "event_count": 1,
      "query": "..."
    }
  }
}
```

주의:

- Kibana rule alert는 즉시 생성되지 않을 수 있다.
- 룰 주기가 5분이면 `lookback + wait`가 필요하다.
- source log는 잡혔지만 alert가 늦는 경우를 `source_detected_alert_pending` 같은 중간 상태로 둘 수 있다.

## 14. 실패/변수 상황 처리

| 상황 | 처리 |
| --- | --- |
| 필요한 role Agent가 offline | operation을 `blocked` 처리하고 실행하지 않음 |
| Agent heartbeat stale | 해당 Agent를 선택하지 않음 |
| safety gate 미설정 | step을 `blocked_by_safety_gate`로 기록 |
| 선행 step 실패 | 후속 의존 step을 `blocked_by_dependency` 처리 |
| ELK 접근 실패 | 공격 결과는 유지하고 탐지는 `not_checked` |
| alert 미생성 | source log와 alert 상태를 분리 기록 |
| HTTP/upload 포트 충돌 | preflight 실패, 관련 step blocked |
| WinRM 인증 실패 | PC01 step 실패, 11/12/15/16 blocked |
| FS01 권한 부족 | 13 failed 또는 blocked |
| DCSync 변수 미입력 | 19 blocked_by_safety_gate |

## 15. 배포 순서

### Phase 1. Controller만 배포

목표:

- Attacker Ubuntu에서 Controller가 뜬다.
- Operator가 tunnel로 대시보드에 접속한다.
- `/health`, `/campaigns`, `/agents`가 정상 응답한다.

### Phase 2. 3개 Agent simulation 등록

목표:

- PC01/FS01/Attacker Agent가 모두 `simulation` 모드로 online 표시된다.
- Controller가 role별 Agent를 인식한다.
- `/operations/preview` 또는 유사 기능에서 step별 route가 보인다.

### Phase 3. 낮은 위험도 real 검증

대상:

- 2, 4, 5, 6

목표:

- PC01 Agent real mode 동작 확인
- source log와 alert 확인
- 민감 gate 없이도 안전한 단계부터 검증

### Phase 4. WinRM 기반 FS01 행위

대상:

- 10, 11, 12, 15, 16

목표:

- `BAS_SVC_FILE_PASSWORD` 세션 주입
- FS01 대상 원격 행위 로그 확인
- T1105/T1041 전 Attacker 보조 서비스 준비 확인

### Phase 5. FS01 민감 행위

대상:

- 13

목표:

- FS01 Agent elevated real mode
- `BAS_ENABLE_CREDENTIAL_TESTS=1` 설정 시에만 실행
- 테스트 후 dump cleanup

### Phase 6. Attacker 도메인 침해급 행위

대상:

- 19

목표:

- Attacker Agent real mode
- `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1` 설정 시에만 실행
- DC01 4662 source log와 alert 확인

## 16. 설치 전 점검표

### Controller

- Attacker Ubuntu에 코드 배포 완료
- Python venv 생성 완료
- `uvicorn api:app` 실행 가능
- PC01/FS01에서 `10.0.1.194:8000` 접근 가능
- ELK API 접근 방식 결정

### PC01

- Python 설치
- 코드 배포
- Controller 접근 가능
- FS01 WinRM 접근 가능
- `svc_file` 비밀번호 입력 방식 결정
- Sysmon/Winlogbeat 정상

### FS01

- Python 설치
- 코드 배포
- Controller 접근 가능
- 관리자 권한 실행 방식 결정
- Sysmon Event ID 10 수집 확인
- cleanup 절차 준비

### Attacker

- Controller 실행
- Agent 실행
- Impacket 경로 확인
- HTTP file server 준비
- Upload server 준비
- 도메인 침해급 테스트 변수는 수동 입력으로만 관리

## 17. 완료 기준

기능 완료:

- 3개 Agent가 online으로 표시된다.
- Agent 등록 정보에 `agent_role`, `platform`, `capabilities`가 표시된다.
- SB-AD operation 생성 시 12개 테크닉이 role별로 라우팅된다.
- 각 step은 순번대로 실행된다.
- 결과가 하나의 operation report로 병합된다.

탐지 검증 완료:

- source log query 결과가 step별로 표시된다.
- Kibana alert query 결과가 step별로 표시된다.
- source matched / alert missed 상태가 구분된다.
- alert 지연 때문에 놓친 경우 재검증할 수 있다.

안전 완료:

- DC01에는 Agent가 없다.
- safety gate 없이는 13, 19가 실행되지 않는다.
- 비밀번호/해시/토큰은 config, repo, output에 평문 저장되지 않는다.
- 테스트 후 LSASS dump와 임시 artifact cleanup 절차가 있다.


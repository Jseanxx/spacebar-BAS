# PC01 - BasAgent 설치 명세

작성일: 2026-05-26

## 역할

PC01은 사용자 PC이자 초기 실행 지점이다.

PC01 BasAgent는 다음 성격의 행위를 담당한다.

```text
사용자 PC 실행
도메인/계정 탐색
FS01 원격 실행 출발점
외부/내부 네트워크 연결 테스트
```

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | PC01 |
| FQDN | `PC01.mycompany.local` |
| Private IP | `10.0.4.216` |
| Agent role | `pc01` |
| 설치 경로 | `C:\SpacebarBAS` |
| Controller URL | `http://10.0.1.194:8000` |

## 담당 Technique 예시

| Technique | 의미 | PC01 역할 |
| --- | --- | --- |
| T1059.003 | Windows Command Shell | cmd 실행 |
| T1087.002 | Domain Account Discovery | 도메인 계정 조회 |
| T1018 | Remote System Discovery | 원격 시스템 조회 |
| T1033 | System Owner/User Discovery | 현재 사용자 확인 |
| T1021.006 | WinRM | FS01 원격 접속 출발점 |
| T1059.001 | PowerShell | PowerShell 실행 |
| T1105 | Ingress Tool Transfer | 도구 다운로드/전송 |

## 1. RDP 접속

```text
PC name: PC01 public IP 또는 터널 주소
Username: .\Administrator 또는 MYCOMPANY\employee1
```

설치 작업은 관리자 권한 PowerShell에서 진행한다.

## 2. Python 설치 확인

```powershell
python --version
py -3 --version
```

Python 3.10 이상이 없으면 설치한다.

우선 시도:

```powershell
winget install Python.Python.3.12
```

`winget`이 없으면 Python 공식 설치 파일을 수동으로 옮겨 설치한다.

## 3. Git 설치 확인

```powershell
git --version
```

Git이 없으면 두 가지 중 하나를 선택한다.

```text
방법 A: Git 설치 후 clone
방법 B: spacebar-BAS.zip을 복사 후 압축 해제
```

## 4. 코드 배치

Git 사용 시:

```powershell
git clone https://github.com/Jseanxx/spacebar-BAS.git C:\SpacebarBAS
cd C:\SpacebarBAS
git checkout bas-operation-builder
```

ZIP 사용 시:

```powershell
New-Item -ItemType Directory -Force C:\SpacebarBAS
Expand-Archive C:\SpacebarBAS.zip -DestinationPath C:\SpacebarBAS -Force
cd C:\SpacebarBAS
```

주의: 압축 해제 후 `api.py`, `agent_runtime`, `bas`, `campaigns`, `modules`가 `C:\SpacebarBAS` 바로 아래에 있어야 한다.

## 5. Python 가상환경

```powershell
cd C:\SpacebarBAS
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install -r requirements.txt
```

## 6. 설정 파일 확인

파일:

```text
C:\SpacebarBAS\agent_runtime\config.sbad-pc01.yaml
```

중요: repo 기본값이 `127.0.0.1`이면 반드시 수정한다.

```yaml
agent_id: sbad-pc01-bas-agent
campaign_agent_id: SB-AD
agent_role: pc01
asset_id: pc01
segment_id: user-subnet
display_name: SB-AD PC01 BasAgent
hostname: PC01.mycompany.local
platform: windows
collector_type: winlogbeat
controller_url: http://10.0.1.194:8000
interval_seconds: 2
execution_mode: simulation
```

## 7. 네트워크 확인

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
Resolve-DnsName FS01.mycompany.local
Test-NetConnection FS01.mycompany.local -Port 5985
whoami
```

성공 기준:

```text
TcpTestSucceeded : True
```

## 8. BasAgent 실행

1차는 simulation mode만 실행한다.

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "pc01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode simulation
```

기대 출력:

```text
[+] Registered BasAgent: sbad-pc01-bas-agent
```

## 9. Controller에서 확인

Attacker Ubuntu 또는 운영자 Mac 터널에서:

```bash
curl http://127.0.0.1:8000/agents
```

확인할 값:

```text
sbad-pc01-bas-agent
status: online
last_heartbeat_at 값 존재
```

## 10. real mode는 나중에

실제 명령 실행은 아래 환경변수를 명시적으로 켠 뒤 진행한다.

```powershell
$env:BAS_AGENT_ROLE = "pc01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
```

WinRM 테스트에 서비스 계정 암호가 필요하면 세션에서만 입력한다.

```powershell
$env:BAS_SVC_FILE_PASSWORD = "<수동 입력>"
```

암호를 config 파일이나 git에 저장하지 않는다.

## 11. Scheduled Task는 2차

자동 실행은 Agent online 검증 후 등록한다.

현재 Scheduled Task 명세에서 주의할 점:

```text
BAS_AGENT_ROLE 환경변수도 함께 설정되어야 real mode 라우팅이 정상 동작한다.
```

따라서 처음에는 수동 실행으로 검증한다.

## 체크리스트

```text
[ ] Python 3.10 이상 설치
[ ] Git 또는 ZIP으로 C:\SpacebarBAS 코드 배치
[ ] .venv 생성
[ ] requirements.txt 설치
[ ] config.sbad-pc01.yaml controller_url 수정
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공
[ ] BasAgent simulation 실행
[ ] Controller /agents에서 sbad-pc01-bas-agent online 확인
```

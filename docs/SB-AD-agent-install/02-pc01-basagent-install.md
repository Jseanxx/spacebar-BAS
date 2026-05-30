# PC01 - BasAgent 설치 명세

## 역할

PC01은 사용자 PC이자 초기 실행 지점이다. SB-AD 캠페인에서 가장 많은 Technique을 담당한다.

담당 예시:

| Order | Technique | 목적 |
| --- | --- | --- |
| 2 | T1059.003 | Windows Command Shell |
| 3 | T1095 | Non-Application Layer Protocol |
| 4 | T1087.002 | Domain Account Discovery |
| 5 | T1018 | Remote System Discovery |
| 6 | T1033 | System Owner/User Discovery |
| 10 | T1021.006 | WinRM으로 FS01 원격 실행 |
| 11 | T1059.001 | PowerShell over WinRM |
| 12 | T1105 | FS01에 도구 반입 |
| 15 | T1074.001 | 데이터 스테이징 |
| 16 | T1041 | 외부 전송 |

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | PC01 |
| FQDN | `PC01.mycompany.local` |
| Private IP | `10.0.4.216` |
| Agent role | `pc01` |
| 설치 경로 | `C:\SpacebarBAS` |
| Controller URL | `http://10.0.1.194:8000` |

IP는 재기동 후 바뀔 수 있으므로 설치 직전 확인한다.

## 1. RDP 접속

```text
PC name: PC01 public IP 또는 터널 주소
Username: .\Administrator 또는 MYCOMPANY\employee1
```

설치는 관리자 권한 PowerShell에서 진행한다.

## 2. Python 확인

PowerShell 관리자 실행:

```powershell
python --version
py -3 --version
```

Python 3.10 이상이 없으면 먼저 설치한다.

권장:

```powershell
winget install Python.Python.3.12
```

`winget`이 없으면 python.org 설치 파일을 사용한다.

## 3. 설치 경로 생성

```powershell
New-Item -ItemType Directory -Force C:\SpacebarBAS
cd C:\SpacebarBAS
```

## 4. 코드 배치

방법 A. Git 사용 가능 시:

```powershell
git clone https://github.com/Jseanxx/spacebar-BAS.git C:\SpacebarBAS
cd C:\SpacebarBAS
git checkout bas-operation-builder
```

방법 B. ZIP 복사:

```powershell
# zip을 C:\SpacebarBAS.zip으로 복사한 뒤
Expand-Archive C:\SpacebarBAS.zip -DestinationPath C:\SpacebarBAS -Force
cd C:\SpacebarBAS
```

## 5. Python 가상환경

```powershell
cd C:\SpacebarBAS
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install -r requirements.txt
```

## 6. 설정 파일 수정

파일:

```text
C:\SpacebarBAS\agent_runtime\config.sbad-pc01.yaml
```

필수 확인:

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

주의:

- PC01에서는 `controller_url`을 `127.0.0.1`로 두면 안 된다.
- 반드시 Attacker Ubuntu의 private IP `10.0.1.194:8000`을 바라봐야 한다.

## 7. 네트워크 확인

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
Test-NetConnection FS01.mycompany.local -Port 5985
Resolve-DnsName FS01.mycompany.local
whoami
```

정상 기준:

```text
TcpTestSucceeded : True
```

## 8. Simulation mode 실행

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "pc01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode simulation
```

정상 출력 예:

```text
[+] Registered BasAgent: sbad-pc01-bas-agent
```

Controller에서 확인:

```bash
curl http://127.0.0.1:8000/agents
```

## 9. real mode 실행 조건

처음에는 simulation만 확인한다.

실제 명령 실행이 필요할 때만:

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "pc01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode real
```

WinRM으로 FS01에 접속하는 단계는 `svc_file` 암호가 필요하다.

```powershell
$env:BAS_SVC_FILE_PASSWORD = "<수동 입력>"
```

주의:

- 암호를 config 파일에 저장하지 않는다.
- 명령 실행 후 PowerShell 세션을 닫는다.
- 민감값은 git에 올리지 않는다.

## 10. Windows 서비스/자동 실행

초기에는 수동 실행 권장.

안정화 후에는 Scheduled Task로 등록한다.

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "C:\SpacebarBAS\.venv\Scripts\python.exe" `
  -Argument "C:\SpacebarBAS\agent_runtime\bas_agent.py --config C:\SpacebarBAS\agent_runtime\config.sbad-pc01.yaml --execution-mode simulation"

$Trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
  -TaskName "SpaceBaS-PC01-Agent" `
  -Action $Action `
  -Trigger $Trigger `
  -RunLevel Highest `
  -Description "SpaceBaS PC01 BasAgent"
```

## 11. PC01 확인 체크리스트

```text
[ ] Python 3.10 이상 설치됨
[ ] C:\SpacebarBAS 코드 배치됨
[ ] pip install -r requirements.txt 완료
[ ] config.sbad-pc01.yaml controller_url이 10.0.1.194:8000임
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공
[ ] Test-NetConnection FS01.mycompany.local -Port 5985 성공
[ ] BasAgent simulation 실행 성공
[ ] Controller /agents에서 sbad-pc01-bas-agent online 확인
```

## 현재 부족한 점

- 현재 Agent 등록 API는 `agent_role`, `hostname`, `capabilities`를 완전히 저장하지 않는다.
- multi-agent routing이 아직 없어 PC01 Agent가 전체 캠페인을 자동 분배하지 못한다.
- 우선 PC01 단독 Job 실행과 heartbeat 확인을 1차 목표로 한다.

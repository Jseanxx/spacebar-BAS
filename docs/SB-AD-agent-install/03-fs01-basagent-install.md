# FS01 - BasAgent 설치 명세

## 역할

FS01은 파일 서버이며 내부 이동 이후의 민감 행위를 검증하는 위치다.

담당 예시:

| Order | Technique | 목적 |
| --- | --- | --- |
| 13 | T1003.001 | LSASS Memory Dump 계열 검증 |
| 15 | T1074.001 | Local Data Staging |
| 16 | T1041 | Exfiltration over C2 Channel 또는 업로드 검증 |

현재 YAML 기준으로 13번은 `fs01` role이고, 15/16은 PC01에서 WinRM으로 FS01에 명령을 내리는 방식도 포함되어 있다. 향후 BAS스럽게 고도화하려면 FS01 내부 행위는 FS01 Agent가 직접 담당하는 편이 더 명확하다.

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | FS01 |
| FQDN | `FS01.mycompany.local` |
| Private IP | `10.0.10.77` |
| Agent role | `fs01` |
| 설치 경로 | `C:\SpacebarBAS` |
| Controller URL | `http://10.0.1.194:8000` |

## 1. RDP 접속

```text
PC name: FS01 public IP 또는 터널 주소
Username: .\Administrator
```

설치는 관리자 권한 PowerShell에서 진행한다.

## 2. Python 확인

```powershell
python --version
py -3 --version
```

Python 3.10 이상이 없으면 설치한다.

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

Git 사용 가능 시:

```powershell
git clone https://github.com/Jseanxx/spacebar-BAS.git C:\SpacebarBAS
cd C:\SpacebarBAS
git checkout bas-operation-builder
```

ZIP 복사 시:

```powershell
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
C:\SpacebarBAS\agent_runtime\config.sbad-fs01.yaml
```

필수 확인:

```yaml
agent_id: sbad-fs01-bas-agent
campaign_agent_id: SB-AD
agent_role: fs01
asset_id: fs01
segment_id: server-subnet
display_name: SB-AD FS01 BasAgent
hostname: FS01.mycompany.local
platform: windows
collector_type: winlogbeat
controller_url: http://10.0.1.194:8000
interval_seconds: 2
execution_mode: simulation
```

주의:

- FS01에서도 `controller_url`은 Attacker Ubuntu private IP를 바라봐야 한다.

## 7. 네트워크 확인

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
Test-NetConnection 10.0.1.194 -Port 80
Test-NetConnection 10.0.1.194 -Port 8080
whoami
Get-Process lsass
```

정상 기준:

```text
TcpTestSucceeded : True
```

## 8. Simulation mode 실행

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "fs01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode simulation
```

Controller에서 확인:

```bash
curl http://127.0.0.1:8000/agents
```

정상 기대값:

```text
sbad-fs01-bas-agent
status: online
last_heartbeat_at: 최근 시간
```

## 9. real mode 실행 조건

FS01 real mode는 PC01보다 조심해야 한다. 특히 LSASS 관련 테스트는 민감하다.

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "fs01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode real
```

LSASS 계열 테스트 허용 시에만:

```powershell
$env:BAS_ENABLE_CREDENTIAL_TESTS = "1"
```

주의:

- 실제 LSASS dump는 반드시 사전 승인 후 수행한다.
- 테스트 파일은 `C:\Windows\Temp` 또는 별도 테스트 경로로 제한한다.
- 운영/도메인 설정 파일은 수정하지 않는다.

## 10. Windows 서비스/자동 실행

초기에는 수동 실행 권장.

안정화 후 Scheduled Task:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "C:\SpacebarBAS\.venv\Scripts\python.exe" `
  -Argument "C:\SpacebarBAS\agent_runtime\bas_agent.py --config C:\SpacebarBAS\agent_runtime\config.sbad-fs01.yaml --execution-mode simulation"

$Trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
  -TaskName "SpaceBaS-FS01-Agent" `
  -Action $Action `
  -Trigger $Trigger `
  -RunLevel Highest `
  -Description "SpaceBaS FS01 BasAgent"
```

## 11. FS01 확인 체크리스트

```text
[ ] Python 3.10 이상 설치됨
[ ] C:\SpacebarBAS 코드 배치됨
[ ] pip install -r requirements.txt 완료
[ ] config.sbad-fs01.yaml controller_url이 10.0.1.194:8000임
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공
[ ] BasAgent simulation 실행 성공
[ ] Controller /agents에서 sbad-fs01-bas-agent online 확인
[ ] Winlogbeat/Sysmon은 별도로 정상 동작 중
```

## 12. Cleanup

민감 테스트 후 확인:

```powershell
Get-ChildItem C:\Windows\Temp | Where-Object {$_.Name -match "dmp|zip|sb03|spacebas"}
```

필요 시 테스트 산출물만 삭제한다.

```powershell
Remove-Item C:\Windows\Temp\spacebas-* -Force -ErrorAction SilentlyContinue
```

## 현재 부족한 점

- LSASS real test는 안전장치와 cleanup 자동화가 더 필요하다.
- 현재 multi-agent routing이 없어 FS01 Agent가 자동으로 13번만 할당받는 구조는 아직 구현 전이다.
- 우선 FS01 Agent online/heartbeat 확인이 1차 목표다.

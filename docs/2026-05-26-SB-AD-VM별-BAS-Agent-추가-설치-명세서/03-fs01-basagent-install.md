# FS01 - BasAgent 설치 명세

작성일: 2026-05-26

## 역할

FS01은 파일 서버이자 내부 이동 이후 행위가 발생하는 서버다.

FS01 BasAgent는 다음 행위를 검증하는 데 사용한다.

```text
파일 서버 내부 명령 실행
파일 생성/스테이징
LSASS 접근 계열 검증
도구 반입 이후 행위 검증
```

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | FS01 |
| FQDN | `FS01.mycompany.local` |
| Private IP | `10.0.10.77` |
| Agent role | `fs01` |
| 설치 경로 | `C:\SpacebarBAS` |
| Controller URL | `http://10.0.1.194:8000` |

## 담당 Technique 예시

| Technique | 의미 | FS01 역할 |
| --- | --- | --- |
| T1021.006 | WinRM | PC01에서 원격 접속되는 대상 |
| T1059.001 | PowerShell | 원격 PowerShell 실행 흔적 |
| T1105 | Ingress Tool Transfer | 도구 반입 대상 |
| T1003.001 | LSASS Memory | 자격 증명 접근 검증 |
| T1218.011 | Rundll32 | 시스템 바이너리 오용 검증 |
| T1074.001 | Local Data Staging | 로컬 파일 스테이징 |

## 1. RDP 접속

```text
PC name: FS01 public IP 또는 터널 주소
Username: .\Administrator
```

관리자 권한 PowerShell에서 진행한다.

## 2. 사전 수집 도구 확인

FS01에는 이미 아래가 구성되어 있어야 한다.

```text
Sysmon
Winlogbeat
PowerShell Script Block Logging
Windows Security Log
```

확인:

```powershell
Get-Service Sysmon64
Get-Service winlogbeat
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

## 3. Python/Git 확인

```powershell
python --version
py -3 --version
git --version
```

없으면 PC01과 동일하게 설치한다.

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
C:\SpacebarBAS\agent_runtime\config.sbad-fs01.yaml
```

중요: repo 기본값이 `127.0.0.1`이면 반드시 수정한다.

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

## 7. 네트워크 확인

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
Test-NetConnection DC01.mycompany.local -Port 88
Test-NetConnection DC01.mycompany.local -Port 389
whoami
```

성공 기준:

```text
TcpTestSucceeded : True
```

## 8. BasAgent 실행

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "fs01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode simulation
```

기대 출력:

```text
[+] Registered BasAgent: sbad-fs01-bas-agent
```

## 9. Controller에서 확인

```bash
curl http://127.0.0.1:8000/agents
```

확인:

```text
sbad-fs01-bas-agent
status: online
last_heartbeat_at 값 존재
```

## 10. real mode 주의

자격 증명/LSASS 계열 테스트는 안전 게이트를 명시적으로 켜야 한다.

```powershell
$env:BAS_AGENT_ROLE = "fs01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
$env:BAS_ENABLE_CREDENTIAL_TESTS = "1"
```

DC 권한 악용 계열은 별도 승인 전 실행하지 않는다.

```powershell
$env:BAS_ENABLE_DOMAIN_COMPROMISE_TESTS = "1"
```

위 값은 최종 시연 전 승인된 테스트에서만 사용한다.

## 체크리스트

```text
[ ] Sysmon 동작 확인
[ ] Winlogbeat 동작 확인
[ ] PowerShell Logging 확인
[ ] Python 3.10 이상 설치
[ ] C:\SpacebarBAS 코드 배치
[ ] .venv 생성
[ ] requirements.txt 설치
[ ] config.sbad-fs01.yaml controller_url 수정
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공
[ ] BasAgent simulation 실행
[ ] Controller /agents에서 sbad-fs01-bas-agent online 확인
```

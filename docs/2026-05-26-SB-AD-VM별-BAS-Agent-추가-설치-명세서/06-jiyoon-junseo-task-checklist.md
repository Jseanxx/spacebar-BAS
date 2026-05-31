# SB-AD BAS Agent 설치 역할분담 체크리스트

작성일: 2026-05-26

## 오늘 목표

오늘 목표는 완성형 BAS가 아니라, 아래 상태까지 만드는 것이다.

```text
Attacker Controller 실행
Attacker BasAgent online
PC01 BasAgent online
FS01 BasAgent online
Controller /agents에서 3개 Agent 확인
```

## 준서 담당

### 1. Attacker Ubuntu

```text
[ ] Attacker Ubuntu 접속
[ ] /opt/spacebar-BAS 코드 배치
[ ] requirements.txt 설치
[ ] Controller API 실행: 0.0.0.0:8000
[ ] Frontend 실행: 0.0.0.0:5173
[ ] Attacker BasAgent simulation 실행
[ ] /agents에서 sbad-attacker-bas-agent 확인
```

### 2. 네트워크 확인

```text
[ ] PC01 -> 10.0.1.194:8000 접근 가능 여부 확인
[ ] FS01 -> 10.0.1.194:8000 접근 가능 여부 확인
[ ] 필요 시 AWS SG에 VPC 내부 TCP 8000 허용 추가
```

### 3. Controller 확인

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/agents
```

## 지윤 담당

### 1. PC01 BasAgent

```text
[ ] PC01 RDP 접속
[ ] 관리자 PowerShell 실행
[ ] Python 3.10 이상 확인
[ ] Git 또는 ZIP으로 C:\SpacebarBAS 코드 배치
[ ] .venv 생성
[ ] requirements.txt 설치
[ ] config.sbad-pc01.yaml controller_url을 http://10.0.1.194:8000으로 수정
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공 확인
[ ] pc01 role로 BasAgent simulation 실행
[ ] 준서에게 실행 화면 캡처 전달
```

실행 명령:

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "pc01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode simulation
```

### 2. FS01 BasAgent

```text
[ ] FS01 RDP 접속
[ ] 관리자 PowerShell 실행
[ ] Sysmon/Winlogbeat 동작 확인
[ ] Python 3.10 이상 확인
[ ] Git 또는 ZIP으로 C:\SpacebarBAS 코드 배치
[ ] .venv 생성
[ ] requirements.txt 설치
[ ] config.sbad-fs01.yaml controller_url을 http://10.0.1.194:8000으로 수정
[ ] Test-NetConnection 10.0.1.194 -Port 8000 성공 확인
[ ] fs01 role로 BasAgent simulation 실행
[ ] 준서에게 실행 화면 캡처 전달
```

실행 명령:

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "fs01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode simulation
```

## 절대 하지 말 것

```text
[ ] DC01에 BAS Agent 설치하지 않기
[ ] 암호를 config 파일에 저장하지 않기
[ ] GitHub에 암호/키 업로드하지 않기
[ ] Controller 8000을 0.0.0.0/0 public으로 열지 않기
[ ] real mode를 승인 없이 실행하지 않기
[ ] DCSync/LSASS 계열 테스트를 승인 없이 실행하지 않기
```

## 지윤이 준서에게 보내야 할 결과

PC01:

```text
1. Test-NetConnection 10.0.1.194 -Port 8000 결과
2. BasAgent 실행 화면
3. 오류 발생 시 전체 오류 메시지
```

FS01:

```text
1. Test-NetConnection 10.0.1.194 -Port 8000 결과
2. BasAgent 실행 화면
3. Get-Service Sysmon64 결과
4. Get-Service winlogbeat 결과
5. 오류 발생 시 전체 오류 메시지
```

## 완료 판정

Attacker에서 아래 명령 결과에 세 Agent가 보여야 한다.

```bash
curl http://127.0.0.1:8000/agents
```

완료 기준:

```text
sbad-attacker-bas-agent
sbad-pc01-bas-agent
sbad-fs01-bas-agent
```

## 다음 개발 항목

Agent 설치 후 바로 해야 할 개발 항목:

```text
[ ] /agents/register에 agent_role, asset_id, segment_id, hostname, capabilities 저장
[ ] heartbeat에 hostname/platform/current_user/uptime 같은 metadata 추가
[ ] Agent offline 판정 로직 추가
[ ] Technique별 required_agent_role 추가
[ ] Operation 생성 시 Technique별 Agent 자동 분배
[ ] ELK KQL 기반 Evidence 자동 조회
```

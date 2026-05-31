# 지윤 작업 체크리스트 - SB-AD BAS Agent 설치

## 작업 목표

가현 AD 환경에 SpaceBaS BasAgent를 설치해서 Controller에서 Agent 상태를 확인할 수 있게 만든다.

오늘 목표는 공격 실행 완성이 아니라 다음 3개다.

```text
1. Attacker Ubuntu Controller 실행
2. PC01 / FS01 / Attacker BasAgent online 확인
3. 각 Agent가 Controller에 heartbeat를 보내는지 확인
```

## 역할 분담 추천

| 담당 | 작업 |
| --- | --- |
| 준서 | Attacker Ubuntu Controller, Attacker BasAgent, 전체 상태 확인 |
| 지윤 | PC01 BasAgent 설치, FS01 BasAgent 설치 |

## 지윤 담당 범위

### 1. PC01 BasAgent 설치

참고 문서:

```text
docs/SB-AD-agent-install/02-pc01-basagent-install.md
```

핵심:

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "pc01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode simulation
```

확인:

```text
sbad-pc01-bas-agent online
```

### 2. FS01 BasAgent 설치

참고 문서:

```text
docs/SB-AD-agent-install/03-fs01-basagent-install.md
```

핵심:

```powershell
cd C:\SpacebarBAS
$env:BAS_AGENT_ROLE = "fs01"
.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config agent_runtime\config.sbad-fs01.yaml --execution-mode simulation
```

확인:

```text
sbad-fs01-bas-agent online
```

## 공통 주의사항

```text
- 처음에는 반드시 simulation mode로 실행
- real mode는 준서와 합의 후 실행
- 암호/해시/config secret은 파일에 저장하지 않기
- DC01에는 BAS Agent 설치하지 않기
- ELK에는 BAS Agent 설치하지 않기
- PC01/FS01의 controller_url은 http://10.0.1.194:8000 사용
```

## 설치 전 확인

PC01/FS01에서 각각:

```powershell
python --version
Test-NetConnection 10.0.1.194 -Port 8000
```

성공 기준:

```text
TcpTestSucceeded : True
```

## 설치 완료 후 준서에게 전달할 것

```text
1. PC01에서 BasAgent 실행 화면 캡처
2. FS01에서 BasAgent 실행 화면 캡처
3. PC01 Test-NetConnection 10.0.1.194 -Port 8000 결과
4. FS01 Test-NetConnection 10.0.1.194 -Port 8000 결과
5. 오류가 있으면 오류 전문
```

## 현재 부족한 점

설치는 가능하지만 아래는 아직 구현/보강이 필요하다.

```text
- agent_role 기반 자동 routing
- Operation 단위 실행
- ELK Alert API와 BAS 결과 1:1 매칭
- Agent capability UI 표시
- Windows Scheduled Task 정식 운영 등록
```

따라서 이번 설치의 성공 기준은 “전체 BAS 완성”이 아니라 “3개 Agent가 Controller에 붙는 것”이다.

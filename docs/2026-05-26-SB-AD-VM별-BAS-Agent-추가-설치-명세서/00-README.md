# SB-AD VM별 BAS Agent 추가 설치 명세서

작성일: 2026-05-26

## 목적

가현 AD 환경에 SpaceBaS Agent를 올려서, 단순 공격 스크립트 실행이 아니라 다음 구조를 검증한다.

```text
SpaceBaS Controller
  -> VM별 BasAgent 상태 확인
  -> VM별 Technique 실행 지시
  -> 실행 결과 수집
  -> ELK 로그/Evidence와 비교
```

이 문서는 팀원에게 전달하기 위한 설치 명세서다.

## 현재 결론

| 구분 | 판단 |
| --- | --- |
| 문서 목적 | VM별 Agent 설치와 1차 heartbeat 검증 |
| 현재 구현 수준 | BAS 완성형이 아니라 Agent 기반 실행 체계 MVP |
| 오늘 목표 | Attacker, PC01, FS01 Agent online 확인 |
| 아직 미완성 | agent_role 저장, multi-agent routing, ELK 자동 판정 |

## 전체 구조

```text
Operator Mac / Browser
        |
        | SSH tunnel / Browser
        v
Attacker Ubuntu
  - SpaceBaS Controller API : 0.0.0.0:8000
  - SpaceBaS Frontend       : 0.0.0.0:5173
  - Attacker BasAgent       : attacker role
        ^
        |
        | outbound polling
        |
PC01 BasAgent --------------+
  - pc01 role               |
  - 사용자 PC 행위 실행       |
                            |
FS01 BasAgent --------------+
  - fs01 role
  - 파일 서버 내부 행위 실행

DC01
  - BAS Agent 설치 안 함
  - AD/Kerberos/Security 로그 발생 대상
  - Winlogbeat/Sysmon/보안 로그 수집 대상

ELK
  - BAS Agent 설치 안 함
  - Evidence/KQL 검증 대상
```

## VM별 역할

| VM | Agent 설치 | Agent role | 목적 |
| --- | --- | --- | --- |
| Attacker Ubuntu | 설치 | `attacker` | Controller/API/Frontend 실행, 외부 공격자 역할 |
| PC01 | 설치 | `pc01` | 사용자 PC 행위, 도메인 탐색, FS01 원격 실행 출발점 |
| FS01 | 설치 | `fs01` | 파일 서버 내부 행위, LSASS/파일 생성/스테이징 검증 |
| DC01 | 설치 안 함 | 없음 | Kerberos, AD, Security 로그 발생/수집 대상 |
| ELK | 설치 안 함 | 없음 | 로그 저장소, KQL/Evidence 검증 대상 |

## 가장 중요한 네트워크 조건

PC01/FS01 Agent는 Controller로 직접 접속해야 한다.

```text
PC01 -> Attacker Ubuntu private IP:8000
FS01 -> Attacker Ubuntu private IP:8000
```

따라서 Attacker Ubuntu의 Security Group 또는 방화벽에서 최소한 아래가 가능해야 한다.

```text
Source: PC01 private IP 또는 VPC 내부 대역
Port: TCP 8000
Destination: Attacker Ubuntu
```

확인 명령:

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
```

성공 기준:

```text
TcpTestSucceeded : True
```

## 현재 구현상 주의점

현재 코드의 `/agents/register`는 아래 필드만 확실히 저장한다.

```text
agent_id
campaign_agent_id
display_name
collector_type
```

따라서 config에 `agent_role`, `asset_id`, `segment_id`, `capabilities`를 적어도 Controller가 완전한 자산 정보로 저장하지 못한다. 이 부분은 다음 개발 항목이다.

또한 현재 Job 구조는 단일 Agent 대상이다.

```text
현재:
UI -> Job 생성 -> 특정 agent_id 한 개가 실행

목표:
UI -> Operation 생성 -> Technique별 agent_role에 맞춰 PC01/FS01/Attacker로 분배
```

## 설치 문서 목록

```text
00-README.md
01-attacker-ubuntu-controller-agent.md
02-pc01-basagent-install.md
03-fs01-basagent-install.md
04-dc01-log-source.md
05-elk-evidence-backend.md
06-jiyoon-junseo-task-checklist.md
```

## 1차 성공 기준

Controller에서 아래 요청이 성공해야 한다.

```bash
curl http://127.0.0.1:8000/agents
```

기대 상태:

```text
sbad-attacker-bas-agent online
sbad-pc01-bas-agent online
sbad-fs01-bas-agent online
```

단, `online` 표시는 현재 heartbeat 기반으로 판단한다. VM이 꺼지면 heartbeat가 멈추고 offline 판단 로직은 추가 구현이 필요하다.

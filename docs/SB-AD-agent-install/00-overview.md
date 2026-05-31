# SB-AD BAS Agent 설치 개요

## 목적

가현 AD 환경에서 SpaceBaS를 단순 공격 도구가 아니라 BAS 형태로 확장하기 위해, 각 자산에 BasAgent를 설치하고 Controller가 Agent 상태와 실행 결과를 수집하는 구조를 만든다.

## 전체 구조

```text
Operator Browser
  |
  | SSH tunnel / local browser
  v
Attacker Ubuntu
  - SpaceBaS Controller API
  - SpaceBaS Frontend
  - Attacker BasAgent
  - HTTP file server / upload server
  |
  +-- PC01 BasAgent  -> outbound polling -> Controller:8000
  +-- FS01 BasAgent  -> outbound polling -> Controller:8000
  |
  +-- DC01           -> Agent 설치 없음, 로그 발생/수집 대상
  +-- ELK            -> Agent 설치 없음, Controller가 Evidence 조회
```

## VM별 설치 대상

| VM | Agent 설치 | Agent role | 목적 |
| --- | --- | --- | --- |
| Attacker Ubuntu | 설치 | `attacker` | Controller, 외부 공격자 역할, 파일 제공, 업로드 수신, Impacket 계열 실행 |
| PC01 | 설치 | `pc01` | 사용자 PC 행위, 도메인 탐색, WinRM으로 FS01 이동 |
| FS01 | 설치 | `fs01` | 파일 서버 내부 행위, LSASS/스테이징/파일 생성 계열 |
| DC01 | 설치 안 함 | 없음 | Kerberos/AD/Security 로그 발생 및 수집 대상 |
| ELK | 설치 안 함 | 없음 | 로그 저장소, KQL/Evidence 확인 대상 |

## 현재 구현 상태

| 항목 | 상태 |
| --- | --- |
| Agent 등록 API | 구현됨 |
| Agent heartbeat API | 구현됨 |
| Agent job polling API | 구현됨 |
| Agent 결과 업로드 API | 구현됨 |
| PC01/FS01/Attacker config | 작성됨 |
| 실제 VM 설치 | 아직 수행 필요 |
| `agent_role` 기반 multi-agent routing | 아직 구현 전 |
| ELK Alert API 자동 검증 | 일부/추가 구현 필요 |

## 중요한 한계

현재 Controller의 `/jobs` 구조는 기본적으로 한 번에 하나의 `agent_id`에 Job을 넣는 방식이다.

```text
현재:
UI -> Job 생성 -> 지정된 단일 Agent가 selected step 실행

목표:
UI -> Operation 생성 -> 각 Technique의 agent_role에 맞춰 PC01/FS01/Attacker Agent로 분배
```

따라서 지금 설치의 1차 목적은 다음이다.

1. PC01/FS01/Attacker에 BasAgent를 실제로 띄운다.
2. Controller `/agents`에서 3개 Agent가 online으로 보이게 한다.
3. 각 Agent를 대상으로 개별 Job을 보내 실행 가능성을 확인한다.
4. 이후 multi-agent routing을 구현해 캠페인 단위 실행으로 확장한다.

## 공통 파일

설치 시 필요한 코드/설정:

```text
agent_runtime/
bas/
campaigns/
modules/
targets/
api.py
requirements.txt
```

VM별 설정 파일:

```text
agent_runtime/config.sbad-attacker.yaml
agent_runtime/config.sbad-pc01.yaml
agent_runtime/config.sbad-fs01.yaml
```

## 네트워크 조건

| 방향 | 포트 | 목적 |
| --- | --- | --- |
| PC01 -> Attacker | TCP 8000 | BasAgent가 Controller에 register/heartbeat/job polling |
| FS01 -> Attacker | TCP 8000 | BasAgent가 Controller에 register/heartbeat/job polling |
| Operator -> Attacker | TCP 22 또는 443 | SSH 접속/터널링 |
| PC01/FS01 -> Attacker | TCP 80 | T1105 파일 다운로드 테스트 |
| FS01/PC01 -> Attacker | TCP 8080 | T1041 업로드 테스트 |
| Controller -> ELK | TCP 9200/5601 | Evidence/KQL 확인 |

원칙:

- PC01/FS01에 inbound Controller 포트를 열지 않는다.
- Agent는 Controller로 outbound polling한다.
- Controller 8000을 외부 전체에 공개하지 않는다.
- DC01에는 BAS Agent를 설치하지 않는다.

## 설치 순서

1. Attacker Ubuntu에 Controller 설치 및 실행
2. Attacker Ubuntu에 Attacker BasAgent 설치
3. PC01에 PC01 BasAgent 설치
4. FS01에 FS01 BasAgent 설치
5. Controller에서 `/agents` 확인
6. Simulation mode로 Job polling 확인
7. 필요한 Technique부터 real mode 제한 실행

## 전달 문서 목록

```text
00-overview.md
01-attacker-ubuntu-controller-agent.md
02-pc01-basagent-install.md
03-fs01-basagent-install.md
04-dc01-elk-log-source.md
05-jiyoon-task-checklist.md
```

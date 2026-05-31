# SB-AD BAS Mentor Feedback Summary

이 문서는 5주차 2회차 멘토링에서 나온 BAS 관련 피드백을 기준으로, 멘토님이 말한 "엄밀한 의미의 BAS"가 무엇인지 정리한 문서다.

## 1. 핵심 결론

현재 우리가 만든 도구는 공격 시뮬레이션과 탐지룰 검증 기능을 갖춘 상태지만, 엄밀한 의미의 상용 BAS 전체 구조라고 보기는 어렵다.

멘토님이 말한 BAS의 핵심은 단순히 공격 명령을 실행하는 것이 아니라, 다음 질문에 답하는 것이다.

- 우리 회사에는 어떤 자산이 있는가?
- 각 자산은 어느 네트워크 구간에 있는가?
- 각 구간과 자산에는 어떤 보안 솔루션 또는 보안 통제가 적용되어 있는가?
- 특정 공격이 어느 구간을 통과했는가?
- 공격이 목표 자산에 도달했다면, 중간의 어떤 보안 통제가 막지 못했는가?
- 탐지되지 않았다면 어떤 로그, 에이전트, 룰을 추가해야 하는가?

즉 BAS는 공격 실행기가 아니라, 보안 통제 검증 도구에 가깝다.

## 2. 멘토님이 지적한 현재 한계

현재 구조는 다음 기능이 중심이다.

- 캠페인별 공격 테크닉 실행
- ELK/Kibana 탐지룰 매칭 여부 확인
- 실행 결과와 로그 증거 확인
- 결과 보고서 초안 생성

이 자체는 의미가 있지만, 멘토님 기준으로는 공격 시뮬레이터 또는 검증 도구에 더 가깝다.

상용 BAS처럼 보이려면 다음 요소가 추가되어야 한다.

- 자산 정보
- 네트워크 구간 정보
- 구간별 Agent 배치
- 보안 솔루션 또는 논리적 보안 통제 매핑
- 공격 경로별 검증 결과
- 보안 통제가 막았는지, 탐지했는지, 놓쳤는지에 대한 평가
- 탐지 갭과 보완 backlog

## 3. 엄밀한 BAS의 관점

멘토님이 설명한 BAS의 동작 관점은 다음과 같다.

```text
Agent A에서 Agent B로 공격 페이로드를 보낸다.
공격이 B에 도달했다면, A와 B 사이의 보안 통제가 차단하지 못한 것이다.
공격이 로그에는 남았지만 Alert가 없으면 탐지룰이 부족한 것이다.
공격이 로그에도 없으면 로그 수집 체계가 부족한 것이다.
```

따라서 BAS 결과는 단순히 성공/실패가 아니라 다음처럼 나뉘어야 한다.

| 상태 | 의미 |
| --- | --- |
| 공격 실행 성공 | Agent가 공격 행위를 수행함 |
| 목표 도달 | 공격 페이로드나 행위가 대상 자산까지 도달함 |
| 원천 로그 확인 | Sysmon, Security Log, PowerShell Log 등에 흔적이 남음 |
| Alert 발생 | Kibana Security Rule이 탐지함 |
| 로그만 있음 | 로그는 있으나 탐지룰이 Alert를 만들지 못함 |
| 로그 없음 | 수집 정책 또는 에이전트 보완 필요 |
| 실행 불가 | Agent 미설치, 권한 부족, safety gate 등으로 실행 차단 |

## 4. SB-AD에서의 현실적 적용

우리 프로젝트에는 아직 EDR, NDR, WAF, 방화벽 같은 상용 보안 솔루션이 충분히 구축되어 있지 않다.

따라서 1차 목표는 실제 보안 솔루션 성능 평가가 아니라, 다음 논리적 보안 통제를 기준으로 BAS 구조를 만드는 것이다.

| 통제 | 역할 |
| --- | --- |
| Sysmon | 프로세스 실행, 네트워크 연결, 파일 생성, LSASS 접근 등 엔드포인트 행위 관찰 |
| Windows Security Log | 로그온, 권한 사용, AD 객체 접근, DCSync 등 감사 로그 관찰 |
| PowerShell Logging | Script Block, WinRM 기반 PowerShell 실행 관찰 |
| Winlogbeat | Windows 로그를 ELK로 전달하는 수집 통제 |
| Kibana Detection Rules | 수집된 로그를 탐지 Alert로 전환하는 탐지 통제 |
| AWS Security Group | 네트워크 경계와 포트 접근 통제 |
| Manual Response | 현재 자동화되지 않은 수동 대응 절차 |

이 구조를 먼저 만들면, 이후 EDR이나 NDR을 붙이더라도 같은 모델에 `control`만 추가하면 된다.

## 5. 권장 Agent 배치

SB-AD MVP에서는 다음 3개 Agent가 필요하다.

| 위치 | Agent role | 목적 |
| --- | --- | --- |
| PC01 | `pc01` | 사용자 PC 행위, PowerShell 실행, WinRM으로 FS01 접근 |
| FS01 | `fs01` | 파일 서버 내부 행위, LSASS dump 같은 서버 로컬 행위 검증 |
| Attacker Ubuntu | `attacker` | Impacket, DCSync, HTTP 파일 서버, upload 서버 등 공격자 측 작업 |

DC01과 ELK는 Agent 설치 대상이 아니라 로그 관찰 대상이다.

| 위치 | 역할 |
| --- | --- |
| DC01 | AD 보안 이벤트와 DCSync 로그 발생 위치 |
| ELK | 로그 저장, 탐지룰 실행, Alert 확인 위치 |

## 6. 이번 대시보드 반영 방향

이번에 새로 추가한 `검증 맵` 화면은 멘토님 피드백을 반영하기 위해 다음 구조로 설계했다.

- 자산을 단순 목록이 아니라 네트워크 구간 위에 배치
- Attacker, PC01, FS01, DC01, ELK를 공격 경로 노드로 표현
- External, User Endpoint, Server, Domain Core 구간을 분리
- 구간 사이에 Security Control Gate를 배치
- 각 Gate가 어떤 통제를 검증하는지 표시
- Agent 준비 상태와 path별 검증 가능성을 표시
- 추후 실행 결과와 연결할 수 있도록 path, gate, control 구조를 분리

이 화면의 의도는 "공격을 실행했다"가 아니라 "이 공격이 어느 구간을 통과했고, 어떤 통제가 그것을 막거나 봐야 했는가"를 보여주는 것이다.

## 7. 향후 고도화 방향

다음 단계에서는 UI만이 아니라 실제 결과 모델도 이 구조에 맞춰야 한다.

1. Agent 3개 online 상태를 실제 Controller와 연결
2. Technique 실행 시 `agent_role` 기준으로 올바른 Agent에 job 라우팅
3. 각 Technique을 attack path와 security gate에 매핑
4. 실행 결과를 다음 상태로 분리
   - executed
   - reached target
   - source log matched
   - alert detected
   - logged but not alerted
   - not logged
   - blocked by missing agent
5. 결과 보고서에 control coverage와 remediation backlog 포함
6. 향후 EDR, NDR, WAF, 방화벽 등 실제 보안 솔루션을 `security_controls`에 추가

## 8. 한 줄 요약

멘토님이 원하는 BAS는 공격을 실행하는 도구가 아니라, 자산과 네트워크 구간 위에서 공격 경로를 검증하고 보안 통제의 탐지·차단 능력을 평가하는 검증 플랫폼이다.

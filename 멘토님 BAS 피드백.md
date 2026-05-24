# 멘토님 BAS 피드백

> 5주차 2회차 멘토링 내용을 기반으로 정리한 BAS 방향성 문서입니다.  
> 지윤님이 pull 받은 뒤 바로 확인할 수 있도록 루트에 따로 배치했습니다.

## 0. 한 줄 결론

현재 Spacebar BAS는 **공격 시뮬레이터 + ELK 탐지 검증 도구**에 가깝고, 상용 BAS처럼 보이려면 **자산, 네트워크 구간, 보안 솔루션, 에이전트, 검증 결과 보고서** 구조가 추가되어야 합니다.

## 1. 멘토님이 직접 지적한 핵심 한계

- 현재 구현물은 엄밀히 말하면 상용 BAS 전체라기보다 `exploit framework`, 즉 공격 도구에 가깝다.
- BAS처럼 보이려면 어떤 자산이 있고, 네트워크 구간이 어떻게 나뉘며, 어떤 보안 솔루션을 점검하는지 보여야 한다.
- BAS는 에이전트가 필요하다.
- A 에이전트에서 B 에이전트로 공격 페이로드를 보냈을 때 B까지 도달하면, 중간의 보안 장비가 해당 공격을 막지 못했다는 의미로 해석할 수 있다.
- 현재 Spacebar는 보안 솔루션 차단 검증보다는 로그 기반 탐지 및 대응 검증에 더 가깝다.
- 프로젝트 기간상 상용 BAS 전체를 구현하기는 어렵기 때문에, 현재는 공격 시뮬레이션과 ELK 탐지 검증을 완성하고 향후 발전 방향으로 BAS 에이전트와 보안 장비 검증 구조를 제시하는 것이 현실적이다.

## 2. Spacebar에 적용할 방향

멘토님 피드백을 그대로 적용하면, 우리의 BAS는 다음 구조로 잡는 것이 좋습니다.

- 단기 목표: 공격 시나리오 실행, ELK 로그 확인, Kibana 탐지룰 Alert 검증, 결과 보고서 출력
- 중기 목표: PC01, FS01, Attacker Ubuntu에 Agent를 설치해 실행 주체를 분리
- 장기 목표: 자산, 네트워크 구간, 보안 솔루션, 공격 경로, 탐지/차단 결과를 한 화면에서 보여주는 BAS 검증 플랫폼

현재 프로젝트에는 EDR, NDR, WAF 같은 상용 보안 솔루션이 충분히 구축되어 있지 않으므로, 우선은 다음 요소를 “논리적 보안 통제”로 보고 검증합니다.

| 통제 | 역할 |
| --- | --- |
| Sysmon | 프로세스 실행, 파일 생성, 네트워크 연결, LSASS 접근 등 엔드포인트 행위 수집 |
| Windows Security Log | 로그온, 권한 사용, AD 객체 접근, DCSync 등 감사 로그 수집 |
| PowerShell Logging | PowerShell Script Block, WinRM 실행 흔적 수집 |
| Winlogbeat | Windows 로그를 ELK로 전달 |
| Kibana Detection Rules | 수집된 로그를 탐지 Alert로 전환 |
| AWS Security Group | 네트워크 접근 통제 |

## 3. Agent MVP 설치 기준

우선 다음 3개 Agent를 기준으로 구현하면 됩니다.

| 위치 | Agent role | 목적 |
| --- | --- | --- |
| PC01 | `pc01` | 사용자 PC 행위, PowerShell 실행, WinRM으로 FS01 접근 |
| FS01 | `fs01` | 파일 서버 내부 행위, LSASS dump 등 서버 로컬 행위 검증 |
| Attacker Ubuntu | `attacker` | Impacket, DCSync, HTTP 파일 서버, 업로드 서버 등 공격자 측 작업 |

DC01과 ELK는 Agent 설치 대상이 아니라 관찰 대상입니다.

| 위치 | 역할 |
| --- | --- |
| DC01 | AD 보안 이벤트와 DCSync 로그 발생 위치 |
| ELK | 로그 저장, 탐지룰 실행, Alert 확인 위치 |

## 4. 대시보드가 보여줘야 하는 것

Technique 실행 버튼만 보여주면 공격 도구처럼 보입니다. BAS처럼 보이려면 다음 정보가 같이 보여야 합니다.

- 어떤 자산에서 어떤 자산으로 공격이 이동했는가
- 공격이 어느 네트워크 구간을 통과했는가
- 그 구간에 어떤 보안 통제가 있었는가
- 공격 실행은 성공했는가
- 목표 자산까지 도달했는가
- 원천 로그가 남았는가
- Kibana Alert가 발생했는가
- 로그는 있는데 Alert가 없어서 탐지룰 보완이 필요한가
- 로그 자체가 없어 수집 정책 보완이 필요한가

따라서 현재 추가한 `검증 맵` 화면은 다음 흐름을 보여주는 방향으로 발전시키면 됩니다.

```text
Attacker Ubuntu -> PC01 -> FS01 -> DC01 -> ELK
        |            |       |       |
     공격 실행     사용자 PC  파일 서버  도메인 로그
        |            |       |       |
     네트워크 통제 / 엔드포인트 로그 / AD 감사 로그 / Kibana Alert
```

## 5. 결과 상태 모델

이 부분은 멘토님 발언을 Spacebar 구조에 맞게 적용한 해석입니다. 구현 시 결과 상태를 아래처럼 나누면 BAS 결과 보고서와 연결하기 좋습니다.

| 상태 | 의미 |
| --- | --- |
| `executed` | Agent가 공격 행위를 실행함 |
| `reached_target` | 공격 행위가 목표 자산까지 도달함 |
| `source_log_matched` | Sysmon, Security Log, PowerShell Log 등 원천 로그 확인 |
| `alert_detected` | Kibana Detection Rule Alert 발생 |
| `logged_but_not_alerted` | 로그는 있으나 Alert 미발생, 탐지룰 보완 필요 |
| `not_logged` | 로그가 없어 수집 정책 또는 에이전트 보완 필요 |
| `blocked_or_skipped` | 권한, Agent 미설치, 안전장치 등으로 실행 불가 |

## 6. 개발 우선순위

1. `targets/SB-AD.yaml`의 자산, 구간, 보안 통제, 공격 경로 구조 유지
2. Agent heartbeat로 PC01, FS01, Attacker online 상태 표시
3. Technique 실행 시 `agent_role` 기준으로 올바른 Agent에 job 라우팅
4. Technique별 실행 결과를 ELK 탐지룰 결과와 매핑
5. 검증 맵에서 공격 경로, 통제 지점, 탐지 여부를 시각화
6. HTML 결과 보고서에 탐지 커버리지와 보완 backlog 포함

## 7. 발표/문서에서 조심할 표현

- “상용 BAS를 완성했다”라고 말하면 과장입니다.
- “공격 시뮬레이터와 ELK 탐지 검증 구조를 BAS 방향으로 고도화하고 있다”가 더 정확합니다.
- “현재는 로그 기반 탐지 검증 중심이고, 향후 Agent와 보안 솔루션 검증 구조로 확장한다”라고 설명하면 멘토님 피드백과 맞습니다.

## 8. 관련 문서

- `docs/SB-AD-BAS-agent-mvp-spec.md`: Agent MVP 구현 명세
- `docs/SB-AD-BAS-agent-spec.md`: PC01, FS01, Attacker Agent 설치/라우팅 상세 명세
- `docs/SB-AD-BAS-dashboard-enhancement.md`: 대시보드 고도화 계획
- `docs/SB-AD-BAS-mentor-feedback-summary.md`: 멘토링 피드백 상세 요약
- `targets/SB-AD.yaml`: SB-AD 자산, 네트워크 구간, 보안 통제, 공격 경로 정의


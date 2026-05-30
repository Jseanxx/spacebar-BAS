# DC01 / ELK - BAS Agent 설치 제외 및 로그 소스 명세

## 결론

DC01과 ELK에는 BAS Agent를 설치하지 않는다.

| VM | BAS Agent | 이유 |
| --- | --- | --- |
| DC01 | 설치 안 함 | 도메인 컨트롤러는 공격 실행 위치가 아니라 핵심 로그 발생/관찰 대상 |
| ELK | 설치 안 함 | 로그 저장소/탐지 백엔드이며 Controller가 API로 조회하는 대상 |

## DC01 역할

DC01은 다음 이벤트를 남기는 핵심 로그 소스다.

| Technique | 대표 Event ID | 의미 |
| --- | --- | --- |
| T1087.002 | 4688, 4798 등 | 도메인 계정/그룹 조회 흔적 |
| T1018 | 4688, DNS/LDAP 관련 | 도메인/시스템 조회 |
| T1558.003 | 4769 | Kerberoasting TGS 요청 |
| T1003.006 | 4662 | DCSync/Replication 권한 접근 |

DC01에는 실행 Agent를 올리지 않고, Winlogbeat/Sysmon/Windows Security Log 수집 상태만 확인한다.

## DC01 확인 항목

PowerShell 관리자에서 확인:

```powershell
Get-Service winlogbeat
Get-WinEvent -LogName Security -MaxEvents 5
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4769} -MaxEvents 5
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} -MaxEvents 5
```

Winlogbeat 설정 파일 위치 예:

```text
C:\Program Files\Winlogbeat\winlogbeat.yml
```

필수 수집 채널:

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Windows PowerShell
  - name: Microsoft-Windows-PowerShell/Operational
  - name: Microsoft-Windows-Sysmon/Operational
```

## ELK 역할

ELK는 다음을 담당한다.

- Winlogbeat 이벤트 저장
- KQL 기반 Evidence 조회
- 탐지 룰 실행
- BAS Controller가 결과 검증 시 조회할 백엔드

## ELK 확인 항목

Kibana Discover에서 확인:

```kql
campaign.id: "SB-03" or campaign.id: "SB-AD"
```

DC01 로그:

```kql
host.name: "DC01.mycompany.local"
```

Kerberoasting:

```kql
host.name: "DC01.mycompany.local" and event.code: "4769"
```

DCSync:

```kql
host.name: "DC01.mycompany.local" and event.code: "4662"
```

## Controller와 ELK 연동 원칙

ELK 인증 정보는 PC01/FS01/Attacker Agent에 분산하지 않는다.

권장:

```text
Controller -> Elasticsearch/Kibana API
Agent -> Controller로 실행 결과만 제출
```

이유:

- Agent에 ELK credential을 뿌리지 않아도 된다.
- Evidence 조회 정책을 Controller 한 곳에서 관리할 수 있다.
- 탐지 검증 로직을 중앙화할 수 있다.

## 설치 금지 이유

DC01에 BAS Agent를 설치하지 않는 이유:

- 도메인 컨트롤러 오염 가능성 감소
- 테스트 코드가 DC에 올라가는 리스크 감소
- “실제 기업형 환경” 관점에서 DC는 최대한 관찰 대상으로 두는 편이 자연스러움

ELK에 BAS Agent를 설치하지 않는 이유:

- ELK는 실행 대상이 아니라 탐지/분석 대상
- Controller가 API로 조회하면 충분함

## 현재 부족한 점

- Controller의 ELK API 자동 검증은 더 보강해야 한다.
- Kibana Alert Rule 결과와 BAS Job 결과를 1:1로 연결하는 run_id marker 설계가 필요하다.
- DC01의 4662/4769 수집 설정은 환경에서 다시 확인해야 한다.

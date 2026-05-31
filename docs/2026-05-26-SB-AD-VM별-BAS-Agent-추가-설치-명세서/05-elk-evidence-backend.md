# ELK - Evidence Backend 명세

작성일: 2026-05-26

## 결론

ELK에는 BAS Agent를 설치하지 않는다.

ELK는 다음 역할을 담당한다.

```text
Winlogbeat/Sysmon/Security 로그 저장
KQL 기반 Evidence 확인
탐지 룰/Alert 결과 확인
SpaceBaS 결과 검증용 백엔드
```

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | ELK |
| Private IP | `10.0.4.30` |
| Elasticsearch | `http://10.0.4.30:9200` |
| Kibana | `http://10.0.4.30:5601` |
| Agent 설치 | 하지 않음 |

## 수집 대상

| 로그 소스 | 수집 Agent | 대표 로그 |
| --- | --- | --- |
| PC01 Security | Winlogbeat | 4624, 4688 |
| PC01 PowerShell | Winlogbeat | 4104 |
| PC01 Sysmon | Winlogbeat | 1, 3, 11 |
| FS01 Security | Winlogbeat | 4624, 4688 |
| FS01 PowerShell | Winlogbeat | 4104 |
| FS01 Sysmon | Winlogbeat | 1, 10, 11 |
| DC01 Security | Winlogbeat | 4769, 4662, 4672 |

## 현재 수동 Evidence 확인 방식

현재 SpaceBaS는 ELK Alert API와 완전히 자동 연동된 상태가 아니다.

따라서 1차 검증은 아래 흐름으로 진행한다.

```text
1. BasAgent가 Technique simulation 또는 real mode 실행
2. Winlogbeat/Sysmon/Security 로그가 ELK로 전송
3. Kibana Discover에서 KQL 확인
4. Evidence를 수동으로 기록
5. 이후 Controller 자동 판정 기능으로 고도화
```

## 대표 KQL

PC01 Agent 로그:

```text
campaign.id: "SB-03" and host.name: "PC01.mycompany.local"
```

FS01 Agent 로그:

```text
campaign.id: "SB-03" and host.name: "FS01.mycompany.local"
```

PowerShell Script Block:

```text
campaign.id: "SB-03" and winlog.event_id: 4104
```

Sysmon 파일 생성:

```text
campaign.id: "SB-03" and winlog.provider_name: "Microsoft-Windows-Sysmon" and winlog.event_id: 11
```

Kerberoasting:

```text
campaign.id: "SB-03" and host.role: "domain-controller" and winlog.event_id: 4769
```

DCSync:

```text
campaign.id: "SB-03" and host.role: "domain-controller" and winlog.event_id: 4662
```

## 나중에 구현할 자동 검증 구조

```text
BasAgent 실행 결과
  -> run_id / marker 생성
  -> ELK query 자동 실행
  -> matched / not_matched 판정
  -> Evidence 패널 표시
```

필요한 추가 개발:

```text
[ ] Controller에 ELK URL 설정
[ ] campaign/technique별 KQL 매핑
[ ] run_id marker 기반 1:1 검증
[ ] Alert API 또는 Elasticsearch Search API 연동
[ ] Evidence 결과를 BAS Run 결과에 저장
```

## 체크리스트

```text
[ ] Elasticsearch 9200 접근 가능
[ ] Kibana 5601 접근 가능
[ ] PC01 로그 수집 확인
[ ] FS01 로그 수집 확인
[ ] DC01 로그 수집 확인
[ ] 대표 KQL로 로그 조회 가능
[ ] 수동 Evidence 캡처 가능
```

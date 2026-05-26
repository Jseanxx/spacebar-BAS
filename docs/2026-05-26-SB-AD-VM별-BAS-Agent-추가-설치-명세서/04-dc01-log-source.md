# DC01 - BAS Agent 미설치 및 로그 소스 명세

작성일: 2026-05-26

## 결론

DC01에는 BAS Agent를 설치하지 않는다.

DC01의 역할은 다음이다.

```text
AD/Kerberos/Security 로그 발생
Winlogbeat를 통한 ELK 전송
탐지 룰 검증 대상
```

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | DC01 |
| 역할 | Domain Controller |
| Agent 설치 | 하지 않음 |
| 주요 수집 | Security, Kerberos, Directory Service, Sysmon 선택 |
| 전송 대상 | ELK `10.0.4.30:9200` |

## DC01에서 중요한 대표 로그

| Event ID | 의미 | 연결 Technique |
| --- | --- | --- |
| 4768 | Kerberos TGT 요청 | 인증 흐름 확인 |
| 4769 | Kerberos Service Ticket 요청 | Kerberoasting |
| 4771 | Kerberos 사전 인증 실패 | 비정상 인증 시도 |
| 4624 | 로그온 성공 | 원격 접근/계정 사용 |
| 4625 | 로그온 실패 | 비밀번호 대입/오류 |
| 4662 | Directory Service Object Access | DCSync 의심 |
| 4672 | Special Privileges Assigned | 관리자 권한 세션 |
| 4688 | Process Creation | DC 내부 프로세스 실행 |

## 설치하지 않는 이유

DC01은 공격 명령을 실행하는 노드가 아니라, AD 이벤트를 발생시키고 수집하는 핵심 로그 소스다.

```text
PC01/FS01/Attacker Agent가 행위 실행
        |
        v
DC01에서 AD/Kerberos/Security 이벤트 발생
        |
        v
Winlogbeat가 ELK로 전송
```

## 확인 명령

DC01 PowerShell 관리자:

```powershell
Get-Service winlogbeat
Get-WinEvent -LogName Security -MaxEvents 5
```

4769 확인 예:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 5
```

4662 확인 예:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -MaxEvents 5
```

## Kibana 확인 KQL 예시

```text
host.name: "DC01.mycompany.local" and winlog.event_id: 4769
```

```text
host.name: "DC01.mycompany.local" and winlog.event_id: 4662
```

```text
campaign.id: "SB-03" and host.role: "domain-controller"
```

## 체크리스트

```text
[ ] DC01에는 BAS Agent 설치하지 않음
[ ] Winlogbeat 서비스 동작 확인
[ ] Security 로그 수집 확인
[ ] 4769 Kerberos Service Ticket 로그 확인
[ ] 4662 Directory Service Access 로그 확인
[ ] Kibana에서 DC01 로그 조회 확인
```

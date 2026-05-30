# SB-AD BAS 탐지 룰 검증 결과

## 1. 목적

이 문서는 SB-AD BAS로 AD 공격 Technique을 실행했을 때, ELK/Kibana 탐지 룰이 왜 Alert를 발생시키지 못했는지 정리한 검증 문서다.

핵심 목적은 다음과 같다.

- BAS 실행 결과와 Kibana 탐지 룰 매칭 여부를 비교한다.
- 원천 로그는 수집됐지만 Alert가 발생하지 않은 이유를 분리한다.
- 탐지 룰 작성자가 어떤 조건을 보완해야 하는지 확인할 수 있게 한다.
- BAS 자체 문제와 탐지 룰 문제를 구분한다.

중요한 전제는 탐지 룰은 공격을 "막는" 기능이 아니라 Alert를 발생시키는 기능이라는 점이다. 공격 차단은 EDR 차단 정책, 방화벽, 계정 통제, AD 하드닝 등 별도 예방 통제가 필요하다. 따라서 이 문서에서 "탐지 실패"는 공격을 막지 못했다는 의미가 아니라, BAS 실행 후 Kibana Alert가 생성되지 않았다는 의미다.

## 2. 검증 기준

검증 기준은 다음과 같다.

- BAS 전체 실행 Operation: `op-20260531-030304-c70f96`
- 추가 단독 검증 Operation:
  - Golden Ticket: `op-20260531-030928-2f50b3`
  - Masquerading: `op-20260531-030019-e5e315`
- Kibana Detection Rule: 활성화된 17개 룰 기준
- 원천 로그 기준: `winlogbeat-*`, `logs-*`, `.alerts-security.alerts-*`

전체 실행 당시 13, 14, 19, 20, 21, 22, 23번 Technique은 BAS 안전 게이트 때문에 차단됐다. 이는 Kibana 탐지 룰 실패가 아니라, 위험 Technique 실행을 막기 위한 BAS 측 보호 장치였다. 이후 데모 환경에서는 위험 Technique 태그를 표시하고 실행 게이트를 열 수 있도록 BAS 쪽 설정을 보완했다.

## 3. 전체 요약

| 구분 | 결과 |
| --- | --- |
| 전체 Technique 수 | 23개 |
| 활성 Kibana 룰 수 | 17개 |
| BAS 전체 실행 성공 | 15개 |
| BAS 전체 실행 실패 | 1개 |
| BAS 안전 게이트 차단 | 7개 |
| 원천 로그는 수집됐지만 Alert 미발생 | 1, 4, 5, 6, 7, 8, 9, 11, 15, 17, 18 |
| 룰이 없어 Alert가 발생할 수 없는 Technique | 1, 14, 15, 17, 18, 23 |
| 룰 조건 보완이 필요한 Technique | 4, 5, 6, 7, 8, 9, 11 |
| 정상 탐지 확인 Technique | 2, 3, 12, 13, 16, 19, 20, 21, 22 |

## 4. Technique별 검증 결과

| 번호 | Technique | BAS 실행/로그 | Alert | 원인 | 보완 방향 |
| --- | --- | --- | --- | --- | --- |
| 1 | T1204.002 User Execution | 성공, 원천 로그 있음 | 미탐 | 전용 Kibana 룰 없음 | Mark-of-the-Web, 다운로드 경로 실행, 사용자 영역 실행 파일 기준 룰 추가 |
| 2 | T1059.003 Windows Command Shell | 성공, 원천 로그 있음 | 탐지 | cmd 실행 룰 정상 동작 | 현재 룰 유지. 단, 정상 운영 cmd와 구분하기 위한 allowlist 관리 필요 |
| 3 | T1095 Non-Application Layer Protocol | 성공, 원천 로그 많음 | 탐지 | 네트워크 연결 룰 정상 동작 | 탐지는 되지만 이벤트 수가 많아 노이즈 가능성 있음. 목적지/프로세스 조건 정교화 권장 |
| 4 | T1087.002 Domain Account Discovery | 성공, 원천 로그 있음 | 미탐 | 룰에서 `NT AUTHORITY\SYSTEM`을 제외하지만 BAS Agent가 SYSTEM 권한으로 실행됨 | 운영 환경용 SYSTEM 제외는 유지하되, 실습/BAS 검증용으로 의심 명령어는 SYSTEM도 탐지하는 조건 추가 |
| 5 | T1018 Remote System Discovery | 성공, 원천 로그 있음 | 미탐 | 4번과 동일하게 SYSTEM 계정 제외 조건에 걸림 | `nltest`, `net view`, `nslookup` 등 도메인/호스트 탐색 명령은 SYSTEM 실행도 별도 분기 탐지 |
| 6 | T1033 System Owner/User Discovery | 성공, 원천 로그 있음 | 미탐 | `whoami` 실행 주체가 SYSTEM이라 제외됨 | `whoami /groups`, `whoami /priv` 등 정보수집 패턴은 SYSTEM 제외 전 탐지 조건 추가 |
| 7 | T1135 Network Share Discovery | 성공, 원천 로그 있음 | 미탐 | SYSTEM 제외 조건 때문에 Alert 미발생 | `net view`, `Get-SmbShare`, `Get-SmbConnection` 실행은 계정보다 명령 의도를 우선하는 조건 필요 |
| 8 | T1069 Permission Groups Discovery | 성공, 원천 로그 있음 | 미탐 | SYSTEM 제외 조건 때문에 Alert 미발생 | `net group`, `net localgroup`, `Get-ADGroupMember` 계열 명령은 SYSTEM도 탐지 후보로 포함 |
| 9 | T1558.003 Kerberoasting | 성공, 원천 로그 있음 | 미탐 | 룰의 TargetUserName/ServiceName 조건이 실제 Kerberos 로그 필드와 맞지 않음 | 실제 이벤트의 `TargetUserName`, `ServiceName`, SPN 값을 기준으로 룰 조건 재작성 |
| 10 | T1021.006 WinRM Remote Execution | 실패 | 미확인 | BAS 실행 자체가 실패해 탐지 검증 불가 | WinRM 인증/서비스 상태/계정 권한 확인 후 재실행 필요 |
| 11 | T1059.001 PowerShell | 성공, 원천 로그 있음 | 미탐 | 룰은 `wsmprovhost.exe` 부모 프로세스를 기대하지만 BAS는 FS01 Agent가 PowerShell을 직접 실행함 | BAS를 WinRM 경로로 실행하거나, 직접 실행된 PowerShell 의심 명령도 탐지하는 보조 룰 추가 |
| 12 | T1105 Ingress Tool Transfer | 성공, 원천 로그 있음 | 탐지 | PowerShell 다운로드 명령 룰 정상 동작 | 현재 룰 유지 |
| 13 | T1003.001 LSASS Memory Dump | 전체 실행 당시 차단, 단독 검증 성공 | 탐지 | 위험 게이트 차단 이슈였고, 룰 자체는 동작 확인 | 현재 룰 유지. `GrantedAccess` 대소문자/표현 차이만 보완 가능 |
| 14 | T1218.011 Rundll32 Proxy Execution | 전체 실행 당시 차단 | 미확인 | 전용 Kibana 룰 없음 | `rundll32.exe` + `comsvcs.dll` + `MiniDump` 조합 룰 추가 |
| 15 | T1074.001 Local Data Staging | 성공, 원천 로그 있음 | 미탐 | 전용 Kibana 룰 없음 | 임시/공용 경로 파일 생성, 압축 전 단계 파일 집합 생성 조건 추가 |
| 16 | T1041 Exfiltration Over C2 Channel | 성공, 원천 로그 있음 | 탐지 | 외부 연결 룰 정상 동작 | 현재 룰 유지. 목적지/포트 조건 튜닝 가능 |
| 17 | T1036.005 Masquerading | 성공, 원천 로그 있음 | 미탐 | 전용 Kibana 룰 없음 | `svchost.exe`, `chrome.exe` 등 정상 파일명 위장 + 비정상 경로 실행 룰 추가 |
| 18 | T1560.001 Archive Collected Data | 성공, 원천 로그 있음 | 미탐 | 전용 Kibana 룰 없음 | `Compress-Archive`, `makecab`, `tar`, `zip` 계열 명령과 staging 경로 연결 룰 추가 |
| 19 | T1003.006 DCSync | 전체 실행 당시 차단, 별도 검증에서 탐지 확인 | 탐지 | 위험 게이트 차단 이슈였고, 룰 자체는 동작 확인 | 현재 룰 유지. 복제 권한 GUID 조건 설명을 룰 설명에 보강 |
| 20 | T1558.001 Golden Ticket | 전체 실행 당시 차단, 이후 BAS 수정 후 성공 | 탐지 | 초기에는 BAS 명령 문제와 게이트 차단이 있었음. 수정 후 룰 동작 확인 | 현재 룰 유지. 4768 없이 4769가 발생하는 흐름 설명 보강 |
| 21 | T1078.002 Valid Domain Account | 전체 실행 당시 차단, 별도 검증에서 탐지 확인 | 탐지 | 위험 게이트 차단 이슈였고, 룰 자체는 동작 확인 | 현재 룰 유지. 외부 IP 기준이 실습망 구조와 맞는지 확인 |
| 22 | T1569.002 Service Execution | 전체 실행 당시 차단, 별도 검증에서 탐지 확인 | 탐지 | 위험 게이트 차단 이슈였고, 룰 자체는 동작 확인 | 현재 룰 유지. 서비스 ImagePath 조건 확장 가능 |
| 23 | T1003.003 NTDS Dump | 전체 실행 당시 차단, 원천 로그 확인 가능 | 미탐 | 전용 Kibana 룰 없음 | DC 4662 복제 이벤트, 서비스 생성 7045, secretsdump/psexec 흔적을 연결하는 룰 추가 |

## 5. 주요 미탐 원인

### 5.1 룰이 없는 Technique

다음 Technique은 BAS가 실행되어 원천 로그가 남아도 현재 Kibana Alert가 발생하기 어렵다.

- 01. T1204.002 User Execution
- 14. T1218.011 Rundll32 Proxy Execution
- 15. T1074.001 Local Data Staging
- 17. T1036.005 Masquerading
- 18. T1560.001 Archive Collected Data
- 23. T1003.003 NTDS Dump

이 항목들은 "BAS가 실패했다"기보다 "탐지 룰 커버리지가 아직 없다"고 보는 것이 맞다.

### 5.2 SYSTEM 계정 제외 조건으로 인한 미탐

4, 5, 6, 7, 8번은 원천 로그가 수집됐지만 Alert가 발생하지 않았다. 공통 원인은 탐지 룰에서 `NT AUTHORITY\SYSTEM` 또는 관리자 계정을 제외하고 있기 때문이다.

현재 BAS Agent는 Windows 서비스/자동 실행 구조상 SYSTEM 권한으로 Technique을 실행할 수 있다. 따라서 탐지 룰이 SYSTEM 실행을 전부 제외하면 BAS 검증에서는 탐지 공백처럼 보인다.

운영 환경에서는 SYSTEM 제외가 노이즈를 줄이는 데 도움이 될 수 있다. 하지만 다음과 같은 정보수집 명령은 SYSTEM으로 실행돼도 의심 행위일 수 있다.

- `nltest`
- `net view`
- `net group`
- `whoami /groups`
- `Get-ADGroupMember`
- `Get-SmbShare`

권장 방향은 SYSTEM 제외를 무조건 제거하는 것이 아니라, "명령 의도가 명확한 정보수집 행위"는 SYSTEM 계정도 별도 분기로 탐지하는 것이다.

### 5.3 BAS 실행 경로와 룰 기대 경로 불일치

11번 PowerShell 룰은 FS01에서 `wsmprovhost.exe`를 부모 프로세스로 갖는 PowerShell 실행을 기대한다. 하지만 현재 BAS는 FS01 Agent가 직접 PowerShell을 실행하기 때문에 부모 프로세스 조건이 맞지 않는다.

이 경우 선택지는 두 가지다.

1. BAS 실행 방식을 WinRM 기반으로 바꿔 실제 공격 흐름과 부모 프로세스를 맞춘다.
2. 탐지 룰에 직접 실행된 PowerShell 의심 명령을 잡는 보조 조건을 추가한다.

프로젝트 시연 안정성만 보면 2번이 빠르다. 다만 공격 흐름 재현성을 높이려면 장기적으로 1번이 더 좋다.

### 5.4 Kerberoasting 룰 필드 불일치

9번 Kerberoasting은 BAS 실행 후 Kerberos 관련 원천 로그가 남았지만 Alert가 발생하지 않았다. 현재 룰은 `TargetUserName`과 `ServiceName` 조건이 실제 이벤트와 다르게 잡혀 있다.

실제 이벤트에서는 서비스 계정명, SPN, 호스트명, `FS01$`, `cifs` 계열 값이 기대와 다르게 들어갈 수 있다. 따라서 Discover에서 실제 4769 샘플 이벤트를 기준으로 다음 필드를 확인해야 한다.

- `winlog.event_data.TargetUserName`
- `winlog.event_data.ServiceName`
- `winlog.event_data.ServiceSid`
- `winlog.event_data.IpAddress`
- `winlog.event_data.TicketEncryptionType`

그 후 실제 값에 맞게 룰을 수정해야 한다.

## 6. Correlation Rule 관점 평가

현재 Kibana 룰 대부분은 단일 이벤트 Query Rule에 가깝다. 엄밀한 의미의 상관분석 룰은 20번 Golden Ticket처럼 여러 이벤트 조건을 묶어 판단하는 ESQL 룰에 더 가깝다.

심사나 발표에서 "상관분석"을 강조하려면 다음 흐름을 추가로 설계하는 것이 좋다.

| 상관분석 후보 | 연결할 이벤트 |
| --- | --- |
| Discovery Chain | 4, 5, 6, 7, 8번 정보수집 명령이 짧은 시간 안에 연속 발생 |
| Credential Access Chain | 13번 LSASS 접근 후 14번 Rundll32 실행 또는 dump 파일 생성 |
| Collection/Exfiltration Chain | 15번 staging 후 18번 압축, 이후 16번 외부 전송 |
| Domain Compromise Chain | 19번 DCSync, 20번 Golden Ticket, 21번 Admin Logon, 22번 Service Execution |
| NTDS Dump Chain | 23번 NTDS 접근, DC 서비스 생성, 비정상 파일 생성/전송 |

현재 단계에서는 단일 Technique 탐지 룰도 의미가 있지만, "침해사고 대응체계"라는 프로젝트 목적에는 Technique 단위 룰을 넘어서 공격 단계 간 연결을 보여주는 상관분석 룰이 더 설득력 있다.

## 7. 탐지 룰 작성자에게 전달할 수정 우선순위

### 1순위: 룰 조건이 있어도 BAS 로그를 못 잡는 항목

- 4, 5, 6, 7, 8번: SYSTEM 제외 조건 재검토
- 9번: Kerberoasting 4769 필드 조건 재확인
- 11번: PowerShell ParentImage 조건과 BAS 실행 경로 불일치 해결

이 항목들은 이미 원천 로그가 있으므로 룰 조건만 보완하면 Alert 발생 가능성이 높다.

### 2순위: 룰 자체가 없는 항목

- 1, 14, 15, 17, 18, 23번

특히 23번 NTDS Dump는 프로젝트 후반부 도메인 장악 흐름에서 중요도가 높기 때문에 전용 룰을 추가하는 것이 좋다.

### 3순위: 탐지는 되지만 노이즈가 큰 항목

- 3번 T1095

현재 3번은 Alert가 많이 발생한다. 발표에서는 탐지 성공으로 볼 수 있지만, 실제 운영 관점에서는 정상 네트워크 연결과 구분할 수 있도록 목적지, 포트, 프로세스, 사용자 조건을 더 정교화하는 것이 좋다.

## 8. 결론

이번 BAS 실행 결과는 "BAS가 공격을 못 했다"보다 "ELK 탐지 커버리지가 어디까지 되어 있고 어디가 비어 있는지"를 보여주는 자료로 활용하는 것이 적절하다.

현재 확인된 핵심 포인트는 다음과 같다.

- BAS 실행 자체는 다수 Technique에서 원천 로그를 남기는 데 성공했다.
- 일부 Technique은 BAS 안전 게이트 때문에 전체 실행 당시 차단됐지만, 데모 환경에서는 위험 Technique 태그와 실행 게이트 설정을 통해 재검증할 수 있다.
- 4, 5, 6, 7, 8번은 SYSTEM 제외 조건 때문에 BAS 검증 로그가 Alert로 이어지지 않았다.
- 9번은 Kerberos 이벤트 필드 조건이 실제 로그와 맞지 않아 룰 보완이 필요하다.
- 11번은 BAS 실행 경로와 탐지 룰이 기대하는 WinRM 실행 경로가 달라 Alert가 발생하지 않았다.
- 1, 14, 15, 17, 18, 23번은 전용 탐지 룰이 없어 커버리지 공백으로 정리해야 한다.

따라서 다음 작업은 BAS 쪽에서 Technique 실행 안정성을 높이는 것과 동시에, Kibana 탐지 룰 쪽에서는 "원천 로그가 있는데 Alert가 없는 항목"부터 조건을 보완하는 것이다.

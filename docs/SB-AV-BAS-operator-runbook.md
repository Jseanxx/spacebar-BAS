# SB-AV BAS Operator Runbook

작성일: 2026-05-31  
대상 캠페인: `SB-AV`  
원본 환경: Hanguel AD/PMS/AV Lab (`SB-07 / OZZY PMS Chain`)

## 1. 목적

이 문서는 Hanguel AD/PMS/AV 환경을 대상으로 SB-AV BAS Controller와 BasAgent를 설치하고, Technique 실행 결과를 ELK/Hanguel 탐지 흐름과 연결하기 위한 운영 절차다.

핵심 원칙은 다음과 같다.

- BAS 대시보드 캠페인은 `SB-AV`로 구분한다.
- Hanguel 기존 탐지룰/상관분석 호환을 위해 source event에는 `campaign.id: SB-07`도 함께 남긴다.
- 각 Technique은 `operation_id + step_order + execution_marker`로 추적한다.
- `hanguel-alerts-*`에는 BAS가 직접 alert를 쓰지 않는다. BAS는 실제 행위 또는 source event만 만들고, alert는 Hanguel correlator가 생성해야 한다.
- LSASS, Pass-the-Hash, loader/AV bypass 계열은 실제 credential dump나 hash injection이 아니라 gate가 열린 경우에만 통제된 telemetry 검증 모드로 실행한다.

추가 기준:

- `SB07_BAS_HANDOFF` 인계 자료를 SB-AV 안전 실행 기준으로 삼는다.
- BAS 기본 실행은 실제 LSASS dump, Mimikatz, AV/EDR bypass, PtH 재실행이 아니라 안전한 telemetry emulation과 correlation 검증이다.
- Windows 공격 흐름은 가능하면 인계 자료의 `sb07_emulation` event.action/schema를 따른다.
- LSASS 탐지 검증은 `smoke_test/simulate_lsass_process_access_smoke.ps1` 수준의 benign process access smoke-test만 사용한다.

## 2. 배치 구조

권장 구조:

| 구성 | 위치 | 역할 |
|---|---|---|
| BAS Controller | `hanguel-bastion` | Operation 생성, Agent job 라우팅, 결과 수집 |
| Bastion BasAgent | `hanguel-bastion` | Bastion 진입/내부 서비스 probe |
| PMS BasAgent | `hanguel-ops-pms` | PMS/JBoss/update path/patch marker |
| WIN01 BasAgent | `hanguel-win01` | PMS Agent endpoint 관점의 AD/DC discovery |
| DC01 BasAgent | `hanguel-dc01` | Loader/LSASS 계열 controlled telemetry 검증 |
| SOC01 | `hanguel-soc01` | ELK, Hanguel agent/correlator, Logstash HTTP input |

Private VM은 외부에서 직접 접근하지 않고 Bastion을 통해 접근한다. Controller는 Bastion의 `10.60.0.10:8000`에서 내부 Agent를 받는다.

## 3. Marker 설계

각 step은 다음 marker를 갖는다.

| 필드 | 예시 | 목적 |
|---|---|---|
| `_operation_id` | `op-20260531-xxxxxx` | BAS operation 전체 식별 |
| `_step_order` | `7` | Technique 순서 식별 |
| `_execution_marker` | `op-...-step-7` | ELK source event와 BAS step 매칭 |
| `SPACEBAR_BAS_MARKER` | `op-...-step-7` | 프로세스/명령 로그에 남기는 환경변수 marker |
| `spacebar.bas.marker` | `op-...-step-7` | Hanguel source event 구조화 필드 |
| `bas.marker` | `op-...-step-7` | BAS event 구조화 필드 |

ELK에서 step 단위로 확인할 때는 다음 조합을 우선 사용한다.

- `spacebar.bas.marker:"<marker>"`
- `bas.marker:"<marker>"`
- `labels.spacebar_marker:"<marker>"`
- `"SPACEBAR_BAS_MARKER=<marker>"`
- `"<marker>"`

## 4. Bastion Controller 실행

Bastion에 repo가 `/opt/spacebar-BAS`로 준비되어 있다고 가정한다.

```bash
cd /opt/spacebar-BAS
bash tools/sbav_start_bastion_stack.sh
```

이 스크립트는 다음을 수행한다.

- `.venv`가 없으면 생성
- `requirements.txt` 설치
- `uvicorn api:app --host 0.0.0.0 --port 8000` 실행
- `agent_runtime/config.sbav-bastion.yaml` 기준 Bastion BasAgent 실행
- `BAS_ALLOW_REAL_EXECUTION=1` 설정
- `BAS_DEFER_ELK_CHECKS=1` 설정

초기 검증:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/campaigns
curl http://127.0.0.1:8000/agents
```

## 5. PMS Agent 실행

PMS 서버에 repo가 `/opt/spacebar-BAS`로 준비되어 있다고 가정한다.

```bash
cd /opt/spacebar-BAS
bash tools/sbav_start_linux_agent.sh pms real
```

PMS Agent는 기본적으로 다음 gate를 연다.

- `BAS_AV_ALLOW_MARKER_FILES=1`
- `BAS_AV_ALLOW_PMS_PATCH_EMULATION=1`

두 gate는 `/tmp/spacebar-bas/SB-AV` marker 파일 생성과 patch 변경 emulation에만 사용한다. 실제 운영 파일 덮어쓰기는 하지 않는다.

## 6. WIN01 Agent 실행

WIN01에서는 PowerShell에서 실행한다.

```powershell
cd C:\SpacebarBAS
.\tools\sbav_start_windows_agent.ps1 -Role win01 -Mode real
```

DC C$/WinRM read-only 검증까지 수행하려면 명시적으로 gate를 연다.

```powershell
.\tools\sbav_start_windows_agent.ps1 -Role win01 -Mode real -AllowDcRemoteAccess
```

`dc_cred.xml` DPAPI 컨텍스트가 현재 실행 계정과 맞지 않는 경우 14, 15번이 실패할 수 있다. 이 경우에는 password를 로그나 파일에 남기지 않고 process memory에서만 credential을 구성하도록 다음 환경변수를 사용한다.

- `BAS_HANGUEL_DOMAIN_USER`
- `BAS_HANGUEL_DOMAIN_PASSWORD_B64`

권장 기준:

- `BAS_HANGUEL_DOMAIN_PASSWORD_B64`는 UTF-16LE 문자열을 base64 인코딩한 값으로 전달한다.
- 이 값은 wrapper 파일, 로그, Git, 문서에 저장하지 않는다.
- 검증 후 credential-bearing Agent process를 종료한다.
- 이 fallback은 `Import-Clixml` 원본 복호화가 불가능할 때만 사용하는 재현용 안전장치다.

주의:

- WIN01 BasAgent의 실행 계정이 탐지 결과에 영향을 준다.
- 원본 시나리오가 PMS Agent/SYSTEM 컨텍스트라면 일반 관리자 계정으로 실행했을 때 탐지룰이 안 걸릴 수 있다.
- 이 경우 BAS 실패가 아니라 탐지 커버리지/실행 컨텍스트 차이로 기록한다.

## 7. DC01 Agent와 고위험 계열 실행 기준

DC01 Agent는 16-18번 Technique의 controlled telemetry를 담당한다.

실행 기준:

- 16번 `T1027`: 실제 악성 loader/AV bypass가 아니라 `hgl_loader.exe`, encoded payload marker, loader run log 같은 forensic artifact를 생성한다.
- 17번 `T1620`: 실제 process injection이나 reflective loader 실행 없이 base64 decode와 manual mapping 추론 marker를 남긴다.
- 18번 `T1003.001`: 실제 LSASS dump, Mimikatz, pypykatz를 사용하지 않는다. `hgl_loader.exe`가 LSASS process handle을 열고 닫는 smoke-test만 수행해 Sysmon Event ID 10 계열 telemetry를 만든다.
- 19번 `T1550.002`: 실제 NTLM hash injection/PtH 도구 실행이 아니다. WIN01에서 인증 재사용 경로와 DC 접근 관련 telemetry를 검증하는 emulation event를 남긴다.

필수 gate:

| Order | Gate | 의미 |
|---:|---|---|
| 16 | `BAS_AV_ALLOW_LOADER_ARTIFACTS` | Loader forensic artifact 생성 허용 |
| 17 | `BAS_AV_ALLOW_LOADER_ARTIFACTS` | Reflective loading 추론 marker 생성 허용 |
| 18 | `BAS_AV_ALLOW_LSASS_TEST` | LSASS OpenProcess smoke-test 허용. dump 금지 |
| 19 | `BAS_AV_ALLOW_AUTH_MATERIAL_TEST` | 인증 재사용 검증 event 허용. 실제 PtH 금지 |

금지 사항:

- LSASS dump 파일 생성
- Mimikatz, pypykatz credential extraction
- NTLM hash injection 또는 실제 Pass-the-Hash 도구 실행
- AV/EDR 우회 loader 실행
- plaintext secret/hash 로그 저장

## 7.1 재부팅 후 자동 실행 상태

2026-05-31 KST 기준으로 SB-AV BAS Agent 재부팅 자동 실행을 등록했다.

구분:

| 구성 요소 | 현재 실행 방식 | 재부팅 후 상태 | 판단 |
|---|---|---|---|
| Bastion Controller | `spacebar-sbav-controller.service` | 자동 복구 됨 | systemd enabled/active 확인 |
| Bastion BasAgent | `spacebar-sbav-bastion-agent.service` | 자동 복구 됨 | systemd enabled/active 확인 |
| PMS BasAgent | `spacebar-sbav-pms-agent.service` | 자동 복구 됨 | systemd enabled/active 확인 |
| WIN01 BasAgent | `Spacebar-SBAV-WIN01-Agent` | 자동 복구 됨 | AtStartup Scheduled Task 등록, 직접 mini-agent 실행 |
| DC01 BasAgent | `Spacebar-SBAV-DC01-Agent` | 자동 복구 됨 | AtStartup Scheduled Task 등록, 직접 mini-agent 실행 |
| Hanguel AD Agent/collector | 별도 설치 패키지/Scheduled Task | 자동 실행 가능 | BAS Agent와 별개 |

등록된 Linux service:

```text
spacebar-sbav-controller.service
spacebar-sbav-bastion-agent.service
spacebar-sbav-pms-agent.service
```

등록된 Windows Scheduled Task:

```text
Spacebar-SBAV-WIN01-Agent
Spacebar-SBAV-DC01-Agent
```

Windows Task는 wrapper인 `sbav_start_windows_agent.ps1`가 아니라 `tools\sbav_windows_mini_agent.ps1`를 직접 실행한다. 이 방식은 startup 시 venv/python 준비 문제를 피하고, Windows mini-agent가 Controller에 바로 register/heartbeat 하도록 하기 위한 것이다.

VM 기동 후 확인:

```bash
curl http://127.0.0.1:8000/agents
```

기대 상태:

```text
sbav-bastion-bas-agent online
sbav-pms-bas-agent online
sbav-win01-bas-agent online
sbav-dc01-bas-agent online
```

주의:

- WIN01의 DC 원격 접근 fallback credential은 파일이나 Scheduled Task action에 직접 저장하지 않는다.
- 재부팅 자동 실행용 Agent는 기본 gate만 열 수 있다. loader/LSASS/auth-material gate는 수동 검증 때 명시적으로 열고, 실행 결과를 기록한다.
- Controller가 죽으면 웹 대시보드와 Agent job polling이 모두 멈춘다. Bastion Controller systemd 등록이 최우선이다.

## 8. 실행 대상

현재 실행 대상은 1-19번이다. 16-19번은 실제 credential theft가 아니라 controlled telemetry 검증으로 구현한다.

| Order | Technique | 실행 위치 | 상태 |
|---:|---|---|---|
| 1 | `T1133` Bastion SSH Entry | Bastion | 구현 |
| 2 | `T1046` Limited Internal Probe | Bastion | 구현 |
| 3 | `T1190` JBoss Invoker Probe | Bastion -> PMS | 구현 |
| 4 | `T1059.004` PMS Shell Marker | PMS | 구현 |
| 5 | `T1505.003` PMS Webshell Marker | PMS | 구현 |
| 6 | `T1083` PMS Update Path | PMS | 구현 |
| 7 | `T1195.002` PMS Patch Change Emulation | PMS | 구현 |
| 8 | `T1036.005` PMS Patch Name Marker | PMS | 구현 |
| 9 | `T1053.005` WIN01 PMS Agent Task Check | WIN01 | 구현 |
| 10 | `T1082` WIN01 Context | WIN01 | 구현 |
| 11 | `T1482` DC Discovery | WIN01 | 구현 |
| 12 | `T1018` DC Port Probe | WIN01 | 구현 |
| 13 | `T1552` dc_cred.xml Metadata | WIN01 | 구현 |
| 14 | `T1021.002` DC C$ Read Check | WIN01 | gate + credential context 필요 |
| 15 | `T1021.006` DC WinRM whoami | WIN01 | gate + credential context 필요 |
| 16 | `T1027` Loader Artifact Marker | DC01 | gate 필요, controlled artifact |
| 17 | `T1620` Reflective Loading Marker | DC01 | gate 필요, no injection |
| 18 | `T1003.001` LSASS Process Access Smoke | DC01 | gate 필요, no dump |
| 19 | `T1550.002` Auth Material Reuse Validation | WIN01 | gate 필요, no PtH |

## 9. 현재 미확정 값

환경 담당자 답변 후 수정할 항목:

- 실제 `hanguel_agent` alert rule id/name, correlation key, alert schema
- `hanguel-alerts-*`에 저장되는 rule 필드명: `rule.id`, `hanguel.rule_id`, `alert.rule_id`, `detection.rule_id` 중 무엇인지
- Logstash HTTP input endpoint와 schema
- PMS update manifest/patch 실제 경로
- WIN01 PMS Agent task/service 이름
- WIN01 BasAgent 실행 계정
- dc_cred.xml 실제 경로와 접근 권한: 현재 확인값은 `C:\ProgramData\HanguelPMS\dc_cred.xml`
- dc_cred.xml username: 현재 확인값은 `HANGUEL\Administrator`
- DC WinRM이 IP 기반으로 가능한지, hostname/domain 기반으로 해야 하는지: 현재 IP `10.60.20.10` 기준 검증 성공

## 10. 실패 분류 기준

| 상태 | 의미 |
|---|---|
| `success + alert detected` | BAS 실행과 Hanguel alert 모두 성공 |
| `success + logged only` | source event는 남았지만 alert 미발생. 탐지룰/상관룰 보완 후보 |
| `success + marker only` | BAS marker event만 남음. 실제 endpoint telemetry 부족 |
| `blocked` | safety gate 또는 Agent offline으로 차단 |
| `failed` | 명령 실행 실패. 경로/권한/네트워크/컨텍스트 확인 필요 |
| `simulation` | 실제 명령과 ELK 조회 없이 미리보기만 수행 |

## 11. 로컬 접근 상태

집 네트워크에서는 외부 `22/tcp` 접속이 불안정하므로, Bastion에 기존 SSH `22/tcp`를 유지한 채 `443/tcp`를 추가로 열어 접근한다.

현재 확인된 값:

- Bastion Public IP: `43.201.29.242`
- Bastion Private IP: `10.60.0.10`
- SSH user: `ec2-user`
- SSH port: `443`
- 집 Wi-Fi 공인 IP: `218.233.120.190/32`

접속 예:

```bash
ssh -p 443 -i hanguel-ad-lab-key.pem ec2-user@43.201.29.242
```

주의:

- 기존 팀원용 `22/tcp` 보안그룹 규칙은 삭제하지 않는다.
- 접속 경로를 추가할 때도 기존 규칙을 바꾸지 않고 필요한 IP/port만 추가한다.
- 실환경 배포는 Bastion, PMS, WIN01, DC01 순서로 진행하며, 고위험 gate는 기본적으로 닫아 둔다.

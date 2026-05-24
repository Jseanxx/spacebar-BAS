# SB-AD BAS Agent MVP Implementation Spec

이 문서는 SB-AD 환경에서 BAS를 공격 실행 도구가 아니라, 자산과 네트워크 구간, 탐지 체계를 함께 검증하는 형태로 확장하기 위한 에이전트 MVP 명세서다.

현재 프로젝트에는 상용 EDR, NDR, 방화벽, 이메일 보안 장비처럼 별도의 보안 솔루션이 충분히 구축되어 있지 않다. 따라서 1차 목표는 실제 보안 솔루션 성능 평가가 아니라, 다음 구조를 먼저 만드는 것이다.

- 어느 자산에서 공격 행위가 실행되었는지 식별한다.
- 어느 네트워크 구간을 통과하는 행위인지 표현한다.
- 어떤 로그 수집 체계와 Kibana 탐지룰이 해당 행위를 관찰했는지 검증한다.
- 향후 EDR, NDR, WAF, 방화벽 같은 보안 솔루션이 추가되어도 같은 구조에 연결할 수 있게 만든다.

## 1. MVP 범위

| 항목 | 포함 여부 | 설명 |
| --- | --- | --- |
| PC01 Agent | 포함 | 사용자 PC 역할. PowerShell 실행, WinRM 접근, 파일 전송 등 주요 행위 실행 주체 |
| FS01 Agent | 포함 | 파일 서버 내부 행위 검증. LSASS 덤프처럼 FS01에서 직접 실행되는 행위 담당 |
| Attacker Ubuntu Agent | 포함 | 공격자 서버 역할. Impacket, 파일 서버, 업로드 서버, 외부 전송 검증 담당 |
| DC01 Agent | 제외 | 도메인 컨트롤러는 1차 MVP에서 실행 주체가 아니라 로그 관찰 대상 |
| ELK Agent | 제외 | ELK는 에이전트 설치 대상이 아니라 Controller가 API로 조회하는 탐지 결과 저장소 |
| Multi-agent Routing | 포함 | 테크닉별로 실행할 Agent를 자동 선택 |
| Environment Map | 포함 | 자산, 네트워크 구간, 보안 통제 관계를 UI에 표시 |
| 실제 공격 자동화 | 부분 포함 | 위험한 행위는 safety gate를 두고 수동 승인 또는 dry-run 지원 |
| 상용 보안 솔루션 연동 | 제외 | 향후 고도화 항목. 현재는 Logical Security Control 모델로 대체 |

## 2. 핵심 설계 원칙

BAS Agent는 단순히 명령을 실행하는 프로그램이 아니다.

```text
Agent = 실행 주체 + 자산 식별자 + 네트워크 구간 검증 포인트 + 보안 통제 관찰 지점
```

따라서 Agent는 Controller에 등록될 때 다음 정보를 반드시 제공해야 한다.

```json
{
  "agent_id": "sbad-pc01-bas-agent",
  "campaign_agent_id": "SB-AD",
  "agent_role": "pc01",
  "asset_id": "pc01",
  "segment_id": "user-subnet",
  "hostname": "PC01.mycompany.local",
  "platform": "windows",
  "collector_type": "winlogbeat",
  "execution_mode": "simulation",
  "safety_mode": "approval_required",
  "capabilities": ["windows", "powershell", "winrm", "network"],
  "controls": ["sysmon", "windows_security_log", "powershell_logging", "winlogbeat", "kibana_rules"]
}
```

이 구조를 만들면 나중에 EDR이 추가되더라도 `controls`에 `edr`을 추가하고, 탐지 결과 조회 로직만 붙이면 된다.

## 3. 자산 모델

SB-AD MVP는 다음 자산을 기준으로 한다.

| Asset ID | Host | OS | Agent 설치 | 역할 |
| --- | --- | --- | --- | --- |
| `pc01` | `PC01.mycompany.local` | Windows Server | 예 | 사용자 PC, 초기 실행 및 lateral movement 출발지 |
| `fs01` | `FS01.mycompany.local` | Windows Server | 예 | 파일 서버, 내부 명령 실행 및 자격 증명 접근 검증 |
| `dc01` | `DC01.mycompany.local` | Windows Server | 아니오 | 도메인 컨트롤러, AD 보안 로그 관찰 대상 |
| `attacker` | `Attacker-Ubuntu` | Ubuntu | 예 | 공격자 서버, Impacket 및 파일 송수신 담당 |
| `elk` | `elk-gh` | Linux | 아니오 | Kibana/Elasticsearch, 탐지 결과 조회 대상 |

DC01에 Agent를 설치하지 않는 이유는 1차 MVP에서 DC01은 공격 실행 주체가 아니기 때문이다. DCSync 같은 행위는 Attacker에서 실행하고, DC01의 4662 이벤트를 ELK에서 확인한다.

## 4. 네트워크 구간 모델

멘토님 피드백에서 중요한 지점은 "공격이 어디에서 어디로 이동했는가"를 보는 것이다. 따라서 자산만 나열하지 않고 구간을 함께 표현해야 한다.

| Segment ID | 설명 | 포함 자산 |
| --- | --- | --- |
| `attacker-subnet` | 공격자 위치 | Attacker Ubuntu |
| `user-subnet` | 사용자 PC 구간 | PC01 |
| `server-subnet` | 서버 구간 | FS01, ELK |
| `domain-subnet` | 도메인 핵심 구간 | DC01 |

구간별 공격 흐름 예시는 다음과 같다.

```text
attacker-subnet -> user-subnet    : reverse shell, tool transfer
user-subnet     -> server-subnet  : WinRM, SMB, file share access
server-subnet   -> attacker-subnet: exfiltration, upload
attacker-subnet -> domain-subnet  : DCSync
```

## 5. Logical Security Control 모델

현재 환경에는 별도의 상용 보안 솔루션이 없으므로, 다음 항목을 "논리적 보안 통제"로 취급한다.

| Control ID | 통제 이름 | 의미 | 검증 방식 |
| --- | --- | --- | --- |
| `sysmon` | Sysmon | 프로세스, 네트워크, 파일 생성, 프로세스 접근 로그 | Winlogbeat로 수집된 Sysmon 이벤트 조회 |
| `windows_security_log` | Windows Security Log | 로그온, 권한 사용, 객체 접근 로그 | Windows Security 이벤트 조회 |
| `powershell_logging` | PowerShell Logging | Script Block, Module, Engine 로그 | Event ID 4104 등 조회 |
| `winlogbeat` | Log Forwarding | Windows 로그 전송 체계 | ELK 인덱스 적재 여부 확인 |
| `kibana_rules` | Detection Rule | Kibana Security 탐지룰 | Alert 발생 여부 확인 |
| `aws_security_group` | Network Boundary | AWS 보안그룹 기반 네트워크 경계 | 허용 포트 및 통신 가능 여부 확인 |
| `manual_response` | Manual Response | 수동 대응 절차 | 보고서에 확인 필요 상태로 표시 |

이 모델의 장점은 지금 당장 EDR이 없어도 BAS UI에서 "이 공격은 어떤 통제가 관찰해야 했는가"를 표현할 수 있다는 점이다.

## 6. Agent 역할별 명세

### 6.1 PC01 Agent

PC01 Agent는 사용자 PC 또는 침해된 내부 단말 역할을 담당한다.

주요 책임:

- PowerShell 기반 명령 실행
- WinRM을 통한 FS01 접근 검증
- 파일 다운로드 및 실행 행위 검증
- 내부 파일 공유 접근 행위 검증
- PC01에서 발생한 Sysmon, Security, PowerShell 로그와 Kibana alert 연결

필수 capability:

```yaml
capabilities: windows,cmd,powershell,winrm,network,active_directory,sysmon,windows_security
controls: sysmon,windows_security_log,powershell_logging,winlogbeat,kibana_rules
```

권장 실행 정책:

```yaml
execution_mode: simulation
safety_mode: approval_required
```

이유는 PC01이 실제 공격 명령의 시작점이 되는 경우가 많기 때문에, 위험한 명령은 사용자의 승인 후 실행하는 것이 안전하다.

### 6.2 FS01 Agent

FS01 Agent는 파일 서버 내부에서 직접 실행되어야 하는 행위를 담당한다.

주요 책임:

- FS01 내부 PowerShell 명령 실행
- LSASS 접근 같은 자격 증명 관련 행위 검증
- 파일 생성, 압축, staging 행위 검증
- FS01에서 발생한 Sysmon 이벤트와 Kibana alert 연결

필수 capability:

```yaml
capabilities: windows,powershell,sysmon,windows_security,credential_test
controls: sysmon,windows_security_log,winlogbeat,kibana_rules
```

위험 행위 제한:

- LSASS dump 같은 행위는 기본값으로 `dry_run` 또는 `approval_required` 처리한다.
- 실제 실행이 필요하면 사용자가 명시적으로 승인한 run에서만 수행한다.
- 생성 파일은 반드시 테스트 경로로 제한한다.

### 6.3 Attacker Ubuntu Agent

Attacker Agent는 외부 공격자 서버 역할을 담당한다.

주요 책임:

- Impacket 기반 명령 실행
- HTTP 파일 서버 실행
- 업로드 서버 실행
- DCSync 실행 주체 역할
- 공격자 서버 관점에서 실행 로그 기록

필수 capability:

```yaml
capabilities: linux,bash,impacket,attacker_host,http_server,upload_server
controls: aws_security_group,manual_response
```

권장 실행 정책:

```yaml
execution_mode: simulation
safety_mode: approval_required
```

주의:

- AWS 보안그룹 변경은 Agent가 직접 수행하지 않는다.
- 포트 오픈, 인스턴스 시작/중지 같은 인프라 작업은 별도 운영 절차로 분리한다.

## 7. Controller API 확장 명세

### 7.1 Agent 등록

현재 등록 구조는 최소 필드만 받는다. MVP에서는 다음 필드까지 확장한다.

```python
class AgentRegisterRequest(BaseModel):
    agent_id: str
    campaign_agent_id: str = "SB-AD"
    display_name: str | None = None
    collector_type: str | None = "endpoint"
    agent_role: str | None = None
    asset_id: str | None = None
    segment_id: str | None = None
    hostname: str | None = None
    platform: str | None = None
    execution_mode: str | None = "simulation"
    safety_mode: str | None = "approval_required"
    capabilities: list[str] = []
    controls: list[str] = []
```

현재 `bas_agent.py`의 YAML 파서는 단순 `key: value` 구조만 처리한다. 그래서 1차 구현에서는 `capabilities`와 `controls`를 쉼표로 구분한 문자열로 두고, Controller 등록 직전에 리스트로 정규화하는 방식이 가장 안전하다. 또한 현재 런타임은 `execution_mode`를 `simulation` 또는 `real`만 허용하므로, 승인 정책은 `safety_mode: approval_required`로 분리한다.

### 7.2 저장 구조

Controller는 등록 정보를 다음 형태로 저장한다.

```json
{
  "agent_id": "sbad-pc01-bas-agent",
  "campaign_agent_id": "SB-AD",
  "agent_role": "pc01",
  "asset_id": "pc01",
  "segment_id": "user-subnet",
  "status": "online",
  "last_seen": "2026-05-25T12:00:00+09:00",
  "capabilities": ["powershell", "winrm"],
  "controls": ["sysmon", "kibana_rules"]
}
```

### 7.3 Multi-agent Routing

현재 캠페인 명령에는 `agent_role`이 들어가 있지만, Controller의 실행 구조가 완전한 multi-agent routing을 지원하지 않는다. MVP에서는 다음 규칙을 사용한다.

1. 사용자가 Technique 실행을 요청한다.
2. Controller가 해당 Technique의 command 목록을 읽는다.
3. 각 command의 `agent_role`을 확인한다.
4. 같은 `agent_role`로 등록된 online Agent를 찾는다.
5. Agent가 없으면 `blocked_by_missing_agent` 상태로 종료한다.
6. Agent가 있으면 해당 Agent의 job queue에 명령을 넣는다.
7. Agent 실행 결과와 ELK 탐지 결과를 하나의 run result로 묶는다.

예시:

```yaml
commands:
  - agent_role: pc01
    executor: local
    shell: powershell
    command: Invoke-Command ...
```

이 경우 Controller는 `agent_role=pc01`인 Agent에게만 job을 전달해야 한다.

## 8. 탐지 결과 상태 모델

BAS 결과는 단순히 성공/실패로 끝나면 안 된다. 공격 실행과 탐지는 분리해서 표현한다.

| 상태 | 의미 |
| --- | --- |
| `executed` | Agent에서 명령 실행 자체는 성공 |
| `source_log_matched` | 원천 로그는 ELK에서 확인됨 |
| `alert_detected` | Kibana Security alert까지 발생 |
| `logged_but_not_alerted` | 로그는 있으나 탐지룰이 alert를 만들지 못함 |
| `not_logged` | 실행했지만 원천 로그가 확인되지 않음 |
| `blocked_by_safety_gate` | 위험 명령이라 실행 차단 |
| `blocked_by_missing_agent` | 필요한 Agent가 online 상태가 아님 |
| `not_checked` | 아직 ELK 조회를 수행하지 않음 |

최종 보고서에서는 technique별로 다음처럼 보여준다.

```json
{
  "technique_id": "T1003.001",
  "execution_agent": "sbad-fs01-bas-agent",
  "asset": "FS01",
  "source_log_status": "source_log_matched",
  "alert_status": "alert_detected",
  "controls_tested": ["sysmon", "kibana_rules"],
  "result": "covered"
}
```

## 9. UI 확장 계약

대시보드는 다음 세 화면을 우선 구현한다.

### 9.1 Agent Status

표시 항목:

- Agent 이름
- Host
- Segment
- Platform
- Online/Offline
- Last seen
- Capabilities
- Controls

### 9.2 Environment Map

표시 항목:

- 자산 노드: PC01, FS01, DC01, Attacker, ELK
- 네트워크 구간: attacker-subnet, user-subnet, server-subnet, domain-subnet
- 공격 흐름 화살표: Technique 실행 시 source asset -> target asset 강조
- 통제 지점: Sysmon, Windows Security Log, Kibana Rules

초기 구현은 interactive graph가 아니어도 된다. 정적 다이어그램과 run result 하이라이트만 있어도 MVP로 충분하다.

### 9.3 Technique Run Detail

표시 항목:

- Technique ID / 이름 / 순번
- 실행 Agent
- 대상 자산
- 실행 명령 요약
- 원천 로그 확인 여부
- Alert 발생 여부
- 검증된 control
- 보완 필요 사항
- HTML 보고서 보기 버튼

## 10. 설치 방식

### 10.1 Attacker Ubuntu

가능하면 SSH로 자동 설치한다.

권장 설치 경로:

```bash
/opt/spacebar-BAS
```

설치 절차:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/Jseanxx/spacebar-BAS.git /opt/spacebar-BAS
cd /opt/spacebar-BAS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agent_runtime/bas_agent.py --config agent_runtime/config.sbad-attacker.yaml
```

### 10.2 PC01 / FS01 Windows

가능한 경로는 두 가지다.

1. Attacker Ubuntu에서 WinRM 또는 SMB로 원격 설치
2. 사용자가 RDP로 접속한 뒤 PowerShell 설치 스크립트 1회 실행

MVP에서는 2번을 기본 경로로 둔다. 이유는 Windows RDP GUI 자동화보다 PowerShell 스크립트 실행이 훨씬 안전하고 재현 가능하기 때문이다.

권장 설치 경로:

```powershell
C:\SpacebarBAS
```

Windows 설치 스크립트가 수행해야 할 작업:

- Python 설치 여부 확인
- Git 설치 여부 확인
- BAS repo clone 또는 zip 다운로드
- 가상환경 생성
- 의존성 설치
- Agent config 배치
- Agent 실행 또는 예약 작업 등록

서비스 등록은 MVP에서는 선택 사항이다. 멘토링 시연 목적이면 터미널에서 foreground 실행만으로도 충분하다.

## 11. Safety Gate

다음 행위는 기본적으로 자동 실행하지 않는다.

- LSASS dump
- DCSync
- 자격 증명 덤프 파일 생성
- 실제 도메인 계정 비밀번호 변경
- AWS 보안그룹 수정
- 인스턴스 종료, 삭제, 디스크 변경
- 운영 데이터 삭제 또는 덮어쓰기

위험 행위는 다음 중 하나로 처리한다.

- `dry_run`: 실행하지 않고 명령과 예상 로그만 보여준다.
- `approval_required`: UI에서 명시적 승인 후 실행한다.
- `manual_step`: 사용자가 별도 절차로 실행하고 BAS는 탐지 확인만 수행한다.

## 12. 구현 체크리스트

### Phase 1. Agent Metadata 확장

- `bas_agent.py`에서 config의 `agent_role`, `asset_id`, `segment_id`, `hostname`, `platform`, `capabilities`, `controls`를 읽는다.
- `/agents/register` 요청에 해당 필드를 포함한다.
- `api.py`의 Agent 등록 모델과 저장 구조를 확장한다.
- 대시보드 Agent 목록에서 추가 필드를 표시한다.

### Phase 2. Config Template 정리

- `config.sbad-pc01.yaml`에 PC01 역할과 capability를 명시한다.
- `config.sbad-fs01.yaml`에 FS01 역할과 capability를 명시한다.
- `config.sbad-attacker.yaml`에 Attacker 역할과 capability를 명시한다.

### Phase 3. Multi-agent Operation

- Technique 실행 요청 시 `agent_role`을 기준으로 대상 Agent를 선택한다.
- 필요한 Agent가 offline이면 실행하지 않고 명확한 상태를 표시한다.
- 여러 Agent가 필요한 Technique은 command 단위로 순차 실행한다.
- 각 command 결과를 하나의 operation run으로 묶는다.

### Phase 4. Environment Map

- `targets/SB-AD.yaml` 또는 별도 `environment/SB-AD.yaml`에 자산, 구간, 통제 정보를 정의한다.
- UI에서 자산 노드와 공격 흐름을 표시한다.
- Technique 실행 시 관련 자산과 구간을 강조한다.

### Phase 5. Detection Result

- Technique별 원천 로그 KQL과 Alert KQL을 분리한다.
- 실행 후 ELK 조회 결과를 `source_log_matched`, `alert_detected`로 나눠 저장한다.
- 보고서에는 `covered`, `logged only`, `missed`, `not executed`로 요약한다.

## 13. 지윤 작업 우선순위

지윤이가 이어서 구현한다면 다음 순서가 가장 안전하다.

1. Agent 등록 메타데이터 확장
2. 세 Agent config template 정리
3. 대시보드에 Agent online 상태와 역할 표시
4. Technique 실행 시 `agent_role` 기반 라우팅
5. Environment Map read-only 화면 추가
6. 실행 결과와 ELK 탐지 결과 상태 분리
7. HTML 보고서에 agent, asset, control, detection coverage 반영

처음부터 완전한 상용 BAS를 만들려고 하면 범위가 너무 커진다. MVP에서는 "어떤 자산의 어떤 Agent가 어떤 공격을 실행했고, 어떤 로그/탐지룰이 그것을 봤는가"를 명확히 보여주는 데 집중한다.

## 14. MVP 완료 기준

다음이 되면 1차 Agent MVP는 완료로 본다.

- PC01, FS01, Attacker Agent 3개가 대시보드에서 online으로 보인다.
- 각 Agent가 asset, segment, capability, control 정보를 함께 표시한다.
- Technique 실행 시 올바른 Agent로 job이 전달된다.
- Agent가 없거나 offline이면 실행 버튼이 모래시계로 멈추지 않고 명확한 오류를 보여준다.
- 실행 결과와 Kibana 탐지 결과가 분리되어 표시된다.
- 보고서에 technique, 실행 자산, 검증 control, alert 여부가 남는다.

## 15. 한 줄 정의

SB-AD BAS Agent MVP는 공격 명령을 대신 실행하는 도구가 아니라, 자산별 공격 실행과 로그 기반 탐지 체계의 검증 결과를 연결하는 최소 BAS 검증 구조다.

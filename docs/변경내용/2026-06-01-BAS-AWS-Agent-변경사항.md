# 2026-06-01 BAS AWS Controller 및 Agent 변경사항

## 목적

어제 작업의 핵심 목적은 기존 로컬 중심 BAS를 `AWS 중앙 Controller + 원격 BAS Agent + ELK 검증` 구조로 확장하는 것이었다. 맥북에서 이어서 작업할 때는 로컬 개발 서버와 AWS 배포 서버의 역할을 구분해야 한다.

## 전체 구조

기존 구조는 로컬 Controller가 내부 Agent와 직접 통신하는 형태에 가까웠다.

```text
Local BAS UI/API -> Lab 내부 Agent -> 실행 결과 -> 로컬/터널 ELK 확인
```

변경 후 구조는 AWS Controller를 중심으로 한다.

```text
AWS BAS Controller
  -> SB-AD / SB-AV BAS Agent polling
  -> Job 실행
  -> Agent result submit
  -> Controller가 ELK tunnel로 source log / alert 조회
  -> Dashboard / report에 detection coverage 표시
```

현재 AWS BAS Controller 주소는 다음과 같다.

```text
http://54.116.166.183:443/
```

주의할 점은 443 포트를 쓰지만 HTTPS가 아니라 HTTP로 서비스 중이라는 점이다. 브라우저 주소는 `http://54.116.166.183:443/` 형태로 입력해야 한다.

## 주요 변경 파일

### 1. Agent 공통 런타임

파일:

- `agent_runtime/bas_agent.py`

변경 내용:

- `controller_token` 설정값을 추가했다.
- Agent가 Controller API를 호출할 때 `X-BAS-Agent-Token` 헤더를 보낼 수 있게 했다.
- `controller_urls` fallback 구조는 유지했다.

의미:

- AWS Controller가 외부에서 접근 가능해졌기 때문에 Agent API를 무인 공개 상태로 두지 않기 위한 최소 인증 장치다.
- `BAS_AGENT_TOKEN` 환경변수가 있으면 Agent가 그 값을 자동으로 사용한다.
- 로컬 개발 환경에서 `BAS_AGENT_TOKEN`을 설정하지 않으면 토큰 없이도 개발 가능하다.

### 2. Controller Agent API 인증

파일:

- `api.py`

변경 내용:

- `verify_agent_token()` 함수를 추가했다.
- 아래 Agent API에 토큰 검증을 추가했다.

```text
POST /agents/register
POST /agents/{agent_id}/heartbeat
GET  /agents/{agent_id}/jobs/next
POST /agents/{agent_id}/jobs/{job_id}/result
```

동작 방식:

- Controller 환경변수 `BAS_AGENT_TOKEN`이 비어 있으면 검증하지 않는다.
- 값이 있으면 요청 헤더에 다음 중 하나가 있어야 한다.

```text
X-BAS-Agent-Token: <token>
Authorization: Bearer <token>
```

주의:

- Dashboard Basic Auth와 Agent Token은 서로 다르다.
- Dashboard 접속 계정은 사람용이고, `BAS_AGENT_TOKEN`은 Agent polling API용이다.

### 3. Agent config의 Controller URL 변경

파일:

- `agent_runtime/config.sbad-attacker.yaml`
- `agent_runtime/config.sbad-pc01.yaml`
- `agent_runtime/config.sbad-fs01.yaml`
- `agent_runtime/config.sbav-bastion.yaml`
- `agent_runtime/config.sbav-pms.yaml`
- `agent_runtime/config.sbav-win01.yaml`
- `agent_runtime/config.sbav-dc01.yaml`

변경 전에는 내부망 또는 로컬 Controller 주소를 우선했다.

```text
http://127.0.0.1:8000
http://10.x.x.x:8000
```

변경 후에는 AWS Controller를 1순위로 둔다.

```text
http://54.116.166.183:443/api
```

예시:

```yaml
controller_url: http://54.116.166.183:443/api
controller_urls: http://54.116.166.183:443/api,http://10.60.0.10:8000
```

맥북에서 로컬 Controller로 테스트할 때는 `controller_url`을 `http://127.0.0.1:8000`으로 바꾸면 된다. AWS Controller에 붙일 때는 위 AWS 주소를 유지한다.

### 4. SB-AV Windows mini agent

파일:

- `tools/sbav_windows_mini_agent.ps1`

변경 내용:

- 기본 Controller URL을 AWS Controller로 변경했다.
- `ControllerToken` 파라미터를 추가했다.
- `BAS_AGENT_TOKEN` 환경변수를 읽도록 했다.
- Controller API 호출 시 `X-BAS-Agent-Token` 헤더를 붙이도록 했다.

중요한 운영 이슈:

- WIN01 Agent가 `SYSTEM` 계정으로 실행되면 `C:\ProgramData\HanguelPMS\dc_cred.xml` DPAPI credential을 읽지 못한다.
- 이 경우 SB-AV 14번 `T1021.002`, 15번 `T1021.006`이 실패한다.
- 검증 시에는 WIN01 scheduled task를 `Administrator` 컨텍스트로 실행해야 한다.

문제 증상:

```text
DPAPI_CONTEXT_MISMATCH
current_user=nt authority\system
```

정상 방향:

```text
CurrentUser = Administrator context
```

### 5. ELK 검증 계정 분리

파일:

- `bas/elk_checker.py`
- `targets/SB-AD.yaml`

변경 내용:

- 기존에는 ELK 계정을 전역 환경변수 `BAS_ELK_USERNAME`, `BAS_ELK_PASSWORD`만 참조했다.
- 이제 target YAML에 지정된 env 이름을 우선 참조할 수 있다.

SB-AD 예시:

```yaml
elk:
  enabled: true
  url: http://127.0.0.1:19201
  username_env: BAS_SBAD_ELK_USERNAME
  password_env: BAS_SBAD_ELK_PASSWORD
  index: winlogbeat-*
  alert_index: .alerts-security.alerts-default
```

의미:

- SB-AD / SB-AV가 서로 다른 ELK endpoint와 인증 정보를 써도 Controller에서 캠페인별로 분리해 검증할 수 있다.

현재 AWS Controller 기준 ELK tunnel:

```text
SB-AV ELK: 127.0.0.1:19200
SB-AD ELK: 127.0.0.1:19201
```

### 6. SB-AD Kibana 룰 이름 매핑

파일:

- `targets/SB-AD.yaml`

변경 내용:

- 가현 누나가 Kibana detection rule 이름을 번호형으로 바꿨기 때문에 BAS alert query도 같이 보강했다.

예시:

```kql
kibana.alert.rule.name:"10.T1021.006"
OR kibana.alert.rule.name:"[ANCHOR][T1021.006] WinRM Remote Execution via wsmprovhost"
OR kibana.alert.rule.tags:"T1021.006"
```

의미:

- 예전 `[ANCHOR]`, `[CONTEXT]` 이름도 보고, 새 번호형 이름도 본다.
- Kibana 룰 자체를 BAS가 수정한 것은 아니다.

검증 결과:

- SB-AD 실행은 23개 모두 성공했다.
- ELK source log는 23개 모두 matched였다.
- Alert는 0개였는데, 원인은 BAS 매핑 실패가 아니라 Kibana task manager에서 `alerting:siem.queryRule` task들이 disabled 상태였기 때문이다.

### 7. SB-AV 자산 역할명 정리

파일:

- `targets/SB-AV.yaml`

변경 내용:

- Bastion role을 `내부망 진입 및 BAS Controller`에서 `내부망 진입 배스천`으로 수정했다.

이유:

- BAS Controller가 AWS 중앙 서버로 옮겨졌기 때문에 SB-AV bastion을 Controller로 표현하면 구조가 헷갈린다.

### 8. Attack Map UI 정리

파일:

- `frontend/src/App.jsx`
- `frontend/src/styles.css`

변경 내용:

- Attack Map에서 모든 path를 무조건 표시하지 않고, 의미 있는 이동 경로 중심으로 표시하도록 필터를 추가했다.
- discovery, credential, staging, exfiltration, dump 등 노이즈성 path는 기본 숨김 처리했다.
- 화살표를 곡선 lane 형태로 바꿔 겹침을 줄였다.
- 자산 카드에 IP, OS, Type, Agent 상태, Log 상태가 보이도록 카드 높이와 fact 영역을 조정했다.
- Agent pill에 단순 `BAS Agent` 대신 현재 상태가 표시되도록 했다.

의미:

- 멘토님이 말한 BAS 핵심 요소인 자산/구간/공격 흐름 시각화를 더 명확히 보여주기 위한 변경이다.

## CI/CD 초안

추가 파일:

- `.github/workflows/deploy-aws.yml`
- `deploy/aws/update_remote.sh`
- `docs/AWS-BAS-deployment-runbook.md`

현재 상태:

- workflow와 deploy script는 작성되어 있다.
- 아직 GitHub에 push되기 전까지는 CI/CD가 활성화된 상태가 아니다.
- GitHub Actions secrets를 설정해야 `main` push 시 자동 배포된다.

필요한 GitHub Secrets:

```text
BAS_AWS_HOST
BAS_AWS_USER
BAS_AWS_SSH_PORT
BAS_AWS_SSH_KEY
BAS_DASHBOARD_USER
BAS_DASHBOARD_PASSWORD
BAS_AGENT_TOKEN
BAS_SBAD_ELK_USERNAME
BAS_SBAD_ELK_PASSWORD
```

배포 흐름:

```text
main push
  -> frontend npm ci
  -> VITE_API_BASE=/api npm run build
  -> tarball 생성
  -> EC2 /tmp 업로드
  -> deploy/aws/update_remote.sh 실행
  -> /opt/spacebar-BAS 갱신
  -> /var/www/spacebar-bas 정적 파일 갱신
  -> spacebar-bas-api restart
  -> nginx reload
```

## 최종 검증 결과

2026-06-01 기준 최종 검증 파일:

```text
C:\Users\sean\Documents\AWS\BAS\final-validation-20260601.json
```

요약:

```text
SB-AD
- 23/23 execution success
- 23/23 source log matched
- 0/23 alert detected
- 원인: AD Kibana detection rule task disabled

SB-AV
- 19/19 execution success
- 19/19 source log matched
- 15/19 alert detected
- 4개는 logged_only 상태
```

## 맥북에서 작업할 때 체크리스트

1. 최신 브랜치를 pull한다.

```bash
git fetch origin
git checkout codex/sb-ad-full-techniques
git pull
```

2. 로컬 개발 서버를 띄울 때는 local API 기준으로 본다.

```bash
cd frontend
npm install
npm run dev
```

3. AWS Controller를 바라보는 Agent를 만들 때는 config의 Controller URL을 유지한다.

```text
http://54.116.166.183:443/api
```

4. 로컬 Controller 테스트를 할 때는 config만 local로 바꾼다.

```text
http://127.0.0.1:8000
```

5. `BAS_AGENT_TOKEN`이 설정된 Controller에 붙을 때는 Agent에도 같은 토큰을 넣어야 한다.

6. SB-AV WIN01/DC01 Windows mini agent는 실행 계정을 확인한다.

```text
SYSTEM이면 DPAPI credential 읽기 실패 가능
Administrator 컨텍스트 권장
```

7. AWS 웹 화면이 로컬 dev 화면과 다르면 `frontend/dist` 빌드본이 오래된 것일 수 있다.

```bash
cd frontend
npm run build
```

이후 CI/CD가 완성되면 `main` push만으로 AWS 배포가 갱신된다.


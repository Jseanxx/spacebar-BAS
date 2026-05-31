# SB-AD AI IR Analyst 설계 검토

## 1. 목적

본 문서는 SB-AD 침해사고 대응체계 구축 프로젝트에 AI 분석 기능을 연동하기 위한 설계 검토 문서이다.

프로젝트의 핵심 흐름은 다음과 같다.

1. MITRE ATT&CK 기반 공격 Technique을 BAS로 실행한다.
2. ELK/SIEM에서 원천 로그와 탐지 Alert를 확인한다.
3. Technique별 실행 성공 여부, 로그 수집 여부, 탐지 룰 매칭 여부를 비교한다.
4. AI가 탐지 공백과 대응 방향을 분석해 침해사고 대응 관점의 해석을 제공한다.

이를 통해 단순히 “공격을 실행하고 탐지했다”에서 끝나는 것이 아니라, BAS 실행 결과와 ELK 로그를 기반으로 탐지 공백을 설명하고, 대응 플레이북과 탐지 룰 개선 방향까지 도출하는 AI 기반 침해사고 대응 보조 체계를 구성한다.

## 2. 배경

Elastic Security의 AI Assistant는 분석자가 Alert 또는 Discover 화면에서 AI Assistant를 열고, 저장된 프롬프트나 대화형 질문을 통해 보안 이벤트를 반자동으로 분석하는 기능에 가깝다.

그러나 해당 기능은 Elastic 유료 기능과 LLM Connector 구성이 필요할 수 있어, 현재 프로젝트의 오픈소스/실습형 ELK 환경에 그대로 적용하기 어렵다.

따라서 본 프로젝트에서는 Elastic AI Assistant를 직접 사용하는 대신, 다음 데이터를 활용한 자체 AI 분석 워크플로우를 설계한다.

- BAS Operation 실행 결과
- Technique별 MITRE ATT&CK ID
- 실행 성공/실패/차단 여부
- ELK 원천 로그 수집 여부
- Kibana Alert 탐지 여부
- Sample event
- 탐지 룰 Query
- IR workflow Markdown 지침

## 3. 결론

AI 연동은 가능하다.

가장 현실적인 1차 MVP는 Kibana를 직접 개조하는 것이 아니라, BAS 대시보드에 AI 분석 탭을 추가하고, BAS 백엔드에서 Operation 결과를 분석하는 방식이다.

이후 시간이 허용되면 Kibana Plugin 형태로 `SpaceBar AI` 페이지를 추가할 수 있다. 단, Kibana Plugin은 버전 호환성, 빌드, 설치, 재시작, 권한 문제가 있어 발표 전 안정성을 고려하면 2차 목표로 두는 것이 적절하다.

## 4. 권장 아키텍처

### 4.1 1차 MVP: BAS 대시보드 AI 탭

```text
BAS Frontend
  -> /ai/analyze-operation
  -> BAS FastAPI Backend
  -> Operation JSON + ELK check result + IR workflow md
  -> AI Provider
       - codex_cli
       - openai_api
       - ollama
       - mock
  -> AI 분석 결과 반환
  -> BAS 대시보드 AI 탭에 표시
```

장점:

- ELK/Kibana 설정을 변경하지 않아 안전하다.
- 기존 BAS Operation 결과를 바로 활용할 수 있다.
- 구현 난이도가 낮다.
- 실패해도 BAS 핵심 기능에 영향을 주지 않는다.
- 발표용으로 “AI 기반 탐지 공백 분석”을 명확히 보여줄 수 있다.

### 4.2 2차 목표: AI 분석 결과를 Elasticsearch에 저장

```text
/ai/analyze-operation
  -> AI 분석 결과 생성
  -> spacebar-ai-analysis-* index에 저장
  -> Kibana Data View/Dashboard에서 결과 확인
```

장점:

- Kibana Dashboard에서 AI 분석 결과를 시각화할 수 있다.
- “ELK 기반 분석 결과 저장 및 추적”이라는 SIEM 관점의 완성도가 높아진다.

주의:

- Elasticsearch에 write 작업이 추가된다.
- index template, data view, 권한 설정이 필요할 수 있다.

### 4.3 3차 목표: Kibana Plugin `SpaceBar AI`

```text
Kibana Plugin
  -> /app/spacebar_ai 페이지 등록
  -> /api/spacebar_ai/analyze route
  -> spacebar-ai-worker 호출
  -> Codex CLI 또는 LLM API 호출
  -> 분석 결과를 Kibana UI에 표시
```

이 구조에서는 Kibana Plugin이 직접 모든 일을 하지 않고, 별도 `spacebar-ai-worker`가 AI 실행을 담당하는 것이 안전하다.

권장 분리:

- Kibana Plugin: UI, Kibana 내부 페이지, 요청 Proxy
- spacebar-ai-worker: BAS API 조회, ELK 조회, IR workflow 로딩, LLM 호출
- Codex CLI: 로컬/서버에 로그인된 ChatGPT OAuth 세션을 이용한 분석 엔진

## 5. AI Provider 선택지

### 5.1 Codex CLI Provider

현재 로컬 환경에서 `codex exec`를 비대화형으로 실행할 수 있음을 확인했다.

특징:

- ChatGPT OAuth 로그인 세션을 활용한다.
- 별도 OpenAI API Key 없이 Codex Pro 세션을 활용할 수 있다.
- `--output-last-message` 옵션으로 마지막 응답을 파일로 받을 수 있다.
- `--ephemeral`, `--sandbox read-only`, `approval_policy="never"` 조합으로 안전하게 실행할 수 있다.

예상 실행 방식:

```bash
codex exec \
  --ephemeral \
  --sandbox read-only \
  -c approval_policy='"never"' \
  --output-last-message /tmp/spacebar-ai-result.md \
  "IR 분석 프롬프트"
```

장점:

- 별도 API 비용 없이 시도 가능하다.
- Codex 모델의 분석 품질을 활용할 수 있다.
- 프로젝트의 “AI 분석 보조” 기능을 빠르게 구현할 수 있다.

주의:

- 공식 서버용 API가 아니라 CLI 호출 방식이다.
- 응답 시간이 길 수 있다.
- 로그인 세션 만료 가능성이 있다.
- 동시 요청이 많으면 불안정할 수 있다.
- Codex 인증 정보는 서버 또는 사용자 환경에 남으므로 관리가 필요하다.

권장 사용 범위:

- 발표용 MVP
- 로컬 또는 제한된 실습 서버
- 동시 사용자 1명 수준의 데모

### 5.2 OpenAI API Provider

가장 안정적인 운영형 방식이다.

장점:

- 백엔드 서비스에 적합하다.
- 응답 JSON schema 등을 활용하기 쉽다.
- timeout, retry, logging 구성이 명확하다.

단점:

- API Key와 비용이 필요하다.
- 프로젝트 시연 환경에서 키 관리가 필요하다.

### 5.3 Ollama 또는 Local LLM Provider

API 비용 없이 로컬 LLM을 사용할 수 있다.

장점:

- 오프라인 또는 폐쇄망 시나리오에 적합하다.
- 오픈소스 기반 자체 분석 워크플로우로 설명하기 좋다.

단점:

- 모델 품질이 Codex/OpenAI API보다 낮을 수 있다.
- 서버 리소스가 필요하다.
- 한국어 분석 품질이 모델에 따라 크게 달라진다.

### 5.4 Mock/Rule-based Provider

LLM이 실패했을 때의 fallback이다.

규칙 예시:

- `source log 있음 + alert 없음` -> 탐지 룰 공백
- `source log 없음 + alert 없음` -> 로그 수집 또는 센서 공백
- `execution failed` -> BAS 실행 조건/권한/Agent 문제
- `critical technique` -> 우선순위 높음

이 Provider는 실제 LLM은 아니지만, 발표 중 AI 호출 실패 시 최소한의 결과를 유지하는 보험 역할을 한다.

## 6. `/ai/analyze-operation` 설계

### 6.1 입력

```json
{
  "operation_id": "op-20260531-013437-75a977",
  "analysis_mode": "ir_summary",
  "question": "이번 Operation의 탐지 공백과 대응 방향을 요약해줘"
}
```

### 6.2 백엔드 처리 흐름

1. `outputs/operations/{operation_id}.json` 로드
2. Operation summary 추출
3. step별 실행/탐지 상태 정규화
4. sample event와 query에서 민감정보 마스킹
5. IR workflow md 로드
6. AI prompt 생성
7. AI Provider 호출
8. 결과 반환

### 6.3 출력

```json
{
  "operation_id": "op-20260531-013437-75a977",
  "provider": "codex_cli",
  "status": "success",
  "analysis": {
    "summary": "...",
    "detection_gaps": ["..."],
    "recommended_rules": ["..."],
    "playbook": ["..."],
    "presentation_summary": "..."
  }
}
```

## 7. IR Workflow Markdown 설계

AI가 매번 임의로 분석하지 않도록, 분석 기준을 Markdown으로 고정한다.

예상 파일:

- `docs/ai-workflows/ir-analysis.md`
- `docs/ai-workflows/detection-gap-review.md`
- `docs/ai-workflows/playbook-generation.md`

### 7.1 분석 기준

AI는 다음 기준으로 Operation을 분석한다.

1. Technique 실행이 성공했는지 확인한다.
2. 원천 로그가 수집되었는지 확인한다.
3. Kibana Alert가 발생했는지 확인한다.
4. 원천 로그는 있으나 Alert가 없으면 탐지 룰 공백으로 분류한다.
5. 원천 로그도 없으면 로그 수집 또는 센서 공백으로 분류한다.
6. 실행 실패는 BAS Agent, 권한, 환경 변수, 네트워크 조건 문제로 분류한다.
7. Credential Access, Lateral Movement, Defense Evasion, Impact 계열은 우선순위를 높게 둔다.
8. 결과는 대응 담당자가 이해할 수 있는 형태로 요약한다.

### 7.2 AI 출력 형식

AI는 다음 섹션으로 답변한다.

1. 전체 요약
2. Technique별 실행/탐지 결과
3. 탐지 공백
4. 개선해야 할 탐지 룰
5. 후속 조사 방향
6. 블루팀 대응 플레이북
7. 발표용 한 문단 요약

## 8. Kibana Plugin 가능성 검토

Kibana에 `SpaceBar AI` 페이지를 추가하는 것은 가능하다.

예상 기능:

- 왼쪽 메뉴에 `SpaceBar AI` 등록
- Operation ID 입력 또는 최근 Operation 선택
- AI 분석 요청 버튼
- 탐지 공백/플레이북/발표 요약 표시

권장 구조:

```text
Kibana Plugin UI
  -> Kibana server route
  -> spacebar-ai-worker
  -> BAS API / Elasticsearch API / Codex CLI
```

Kibana Plugin에서 직접 `codex exec`를 호출하는 것보다, 별도 worker를 호출하는 방식이 더 안전하다.

### 8.1 예상 충돌 지점

- Kibana 버전과 Plugin 버전이 정확히 맞아야 한다.
- Production Kibana는 plugin optimizer가 없을 수 있어 사전 빌드가 필요하다.
- Plugin 설치 시 Kibana 재시작이 필요할 수 있다.
- Node.js 버전이 Kibana 요구 버전과 맞지 않으면 빌드 실패 가능성이 있다.
- Kibana 서비스 유저가 Codex CLI 또는 Codex auth 파일을 읽지 못할 수 있다.
- Codex CLI 호출 시간이 길어 Kibana route timeout에 걸릴 수 있다.
- 여러 사용자가 동시에 요청하면 Codex CLI 실행이 충돌할 수 있다.
- Kibana CSP/CORS 정책으로 외부 worker 직접 호출이 막힐 수 있다.
- Elasticsearch 권한이 부족하면 로그 조회가 실패할 수 있다.
- `.kibana` index를 직접 수정하면 Kibana saved object가 깨질 수 있으므로 피해야 한다.

### 8.2 결론

Kibana Plugin은 가능하지만, 발표 전 핵심 기능으로 삼기에는 리스크가 크다.

따라서 우선 BAS 대시보드 AI 탭으로 기능을 완성하고, 이후 Kibana Plugin은 확장 목표로 진행하는 것이 적절하다.

## 9. 보안 고려사항

AI 분석에 전달하는 데이터는 반드시 마스킹한다.

마스킹 대상:

- 비밀번호
- API Key
- Authorization header
- NTLM hash
- AES key
- Kerberos ticket
- 쿠키
- 개인 식별 정보
- 내부 IP 전체 목록이 불필요한 경우 일부 축약

Codex CLI 사용 시:

- `--sandbox read-only` 사용
- `--ephemeral` 사용
- shell 명령 실행이 필요 없는 프롬프트 구성
- timeout 설정
- 동시 실행 lock 적용
- 실패 시 mock provider fallback

## 10. 발표용 설명 문장

Elastic AI Assistant는 유료 기능이기 때문에, 본 프로젝트에서는 BAS 실행 결과와 ELK 로그를 연동한 자체 AI 분석 워크플로우를 설계했다.

AI IR Analyst는 각 Technique의 실행 성공 여부, 원천 로그 수집 여부, Kibana Alert 탐지 여부를 바탕으로 탐지 공백을 분류하고, 후속 조사 방향과 블루팀 대응 플레이북을 제안한다.

이를 통해 BAS는 단순 공격 검증 도구를 넘어, 탐지 룰의 커버리지와 침해사고 대응 절차를 개선하기 위한 분석 보조 시스템으로 확장된다.

## 11. 권장 구현 순서

1. `docs/ai-workflows/ir-analysis.md` 작성
2. Operation JSON을 요약하는 Python 함수 작성
3. `codex_cli`, `mock` Provider 구현
4. `/ai/analyze-operation` API 추가
5. BAS Frontend에 AI Analysis 탭 추가
6. 실제 Operation 결과로 분석 품질 확인
7. 필요 시 `spacebar-ai-analysis-*` index 저장 기능 추가
8. 시간이 남으면 Kibana Plugin `SpaceBar AI` 검토

## 12. 최종 판단

AI 연동은 가능하다.

단기적으로는 BAS 대시보드에 AI 분석 기능을 붙이는 방식이 가장 안전하고 빠르다.

Codex CLI 기반 OAuth 활용도 가능하다. 다만 이는 공식 API 서버 방식이 아니라 로컬/실습 서버의 CLI를 이용한 분석 엔진 방식이므로, 발표용 MVP와 제한된 실습 환경에 적합하다.

Kibana Plugin은 기술적으로 가능하지만, 버전 호환성과 배포 리스크가 있어 2차 확장 목표로 두는 것이 적절하다.

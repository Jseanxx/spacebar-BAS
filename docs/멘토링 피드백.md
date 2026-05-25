# SpaceBaS Attack Path Map 공유 문서

## 목표

SpaceBaS를 단순 공격 실행 도구가 아니라, 자산/네트워크 구간/Agent/보안 통제/ELK 증거를 연결해서 보여주는 BAS형 검증 콘솔로 고도화한다.

## 현재 브랜치 상태

- 브랜치: `bas-operation-builder`
- 현재 구현 범위: 1차 MVP 일부 구현 완료
- 공유 목적: 팀원이 현재 BAS 대시보드가 어떤 방향으로 바뀌었는지 빠르게 확인하기 위함

## 현재 구현된 것

- `검증 맵` 화면에서 SB-AD 자산과 공격 경로를 표시한다.
- `targets/SB-AD.yaml`의 아래 데이터를 UI에 연결한다.
  - `assets`
  - `segments`
  - `security_controls`
  - `attack_paths`
  - `log_queries`
  - `alert_queries`
- 공격 경로를 선택하면 오른쪽 Evidence 패널에 관련 Technique 근거를 표시한다.
  - Technique ID
  - Technique 이름
  - KQL
  - Alert Rule Query
  - 실행 후 샘플 로그
- 실행 결과가 있으면 path 상태가 바뀌도록 구조를 추가했다.
  - 계획됨
  - 큐 대기
  - 실행됨
  - 탐지됨
  - 탐지 갭

## 아직 명세/다음 작업인 것

- React Flow 기반 자유 배치형 노드 UI
- 노드 드래그, 확대/축소
- Agent heartbeat 실시간 표시
- ELK Alert API 실제 연동
- 실행 결과 리포트 자동 생성

## 1차 MVP

- 정적 Attack Path Map 표시
- Technique 실행 결과에 따라 공격 경로 색상 변경
  - 계획됨: 회색
  - 큐 대기: 노랑
  - 실행됨: 파랑
  - 탐지됨: 초록
  - 탐지 갭: 빨강
- 선택한 공격 경로의 Evidence 패널 표시
  - Technique ID
  - KQL
  - Alert Rule Query
  - 실행 후 샘플 로그

## 2차

- React Flow 도입
- 노드 드래그/확대/축소 지원
- Agent heartbeat 실시간 표시
- 자산별 Agent 상태와 보안 통제 상태를 노드에 직접 표시

## 3차

- ELK Alert API 연동
- 실행 결과와 Alert 매칭 자동화
- 검증 결과 보고서 자동 생성
- 캠페인별 탐지 커버리지 리포트 생성

## 현재 반영 상태

- `targets/SB-AD.yaml`의 `assets`, `segments`, `security_controls`, `attack_paths`, `log_queries`, `alert_queries`를 UI에서 사용한다.
- `검증 맵` 화면에서 SB-AD 공격 경로를 표시한다.
- 선택한 경로에 연결된 Technique별 KQL/Alert 근거를 Evidence 패널로 표시한다.
- 실행 결과가 있으면 경로 상태가 `탐지됨`, `탐지 갭`, `실행됨` 등으로 바뀐다.

## 팀원이 확인할 부분

1. `npm install` 후 백엔드와 프론트엔드를 실행한다.
2. 브라우저에서 `http://127.0.0.1:5173/#validation` 접속한다.
3. `검증 맵` 화면에서 SB-AD 공격 경로와 Evidence 패널을 확인한다.
4. 앞으로 각 캠페인도 `targets/<campaign>.yaml`에 자산/구간/보안통제/공격경로/KQL을 채우면 같은 구조로 확장할 수 있다.

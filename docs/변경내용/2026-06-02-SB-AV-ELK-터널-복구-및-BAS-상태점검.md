# 2026-06-02 SB-AV ELK 터널 복구 및 BAS 상태 점검

## 1. 점검 목적

발표 전 BAS 상태를 다음 관점에서 점검했다.

- SB-AV BAS 실행이 실제로 가능한지
- Agent가 online 상태인지
- ELK/SIEM source log 검증이 정상인지
- alert까지 발생하는 Technique과 logged-only Technique이 구분되는지
- 발표 중 받을 수 있는 지적 포인트가 무엇인지
- 운영적으로 다시 터질 수 있는 부분이 무엇인지

이번 점검의 핵심 결론은 다음과 같다.

> SB-AV 실행 라인은 정상이며, 최신 전체 실행에서 24개 step이 모두 성공했다.  
> ELK source log와 marker 검증도 24개 모두 매칭되었다.  
> 다만 alert matched는 18/24로, 일부 Technique은 "로그는 남지만 alert 룰 보완이 필요한 상태"다.

## 2. 장애 원인

### 2.1 증상

초기 점검 시 최신 SB-AV Operation에서 다음 문제가 확인되었다.

- SB-AV 24개 step 실행은 success
- 하지만 `elk_check`는 전부 실패
- 실패 메시지:

```text
Elasticsearch live check failed: <urlopen error [Errno 111] Connection refused>
```

중앙 BAS Controller에서 확인한 결과:

```text
127.0.0.1:19200 접속 실패
127.0.0.1:19201 접속 실패
```

즉, BAS 실행 자체의 문제가 아니라 Controller가 ELK로 질의하기 위한 SSH tunnel이 깨진 상태였다.

### 2.2 실제 원인

Hanguel SB-AV 환경이 재기동되면서 Bastion public IP가 바뀌었는데, 중앙 BAS 서버의 systemd SSH tunnel 설정에는 과거 Bastion IP가 남아 있었다.

확인된 값:

| 항목 | 값 |
|---|---|
| 현재 `hanguel-bastion` public IP | `3.35.149.83` |
| 현재 `hanguel-bastion` private IP | `10.60.0.10` |
| 현재 `hanguel-soc01` private IP | `10.60.40.10` |
| 기존 service 원본에 남아 있던 IP | `43.201.29.242` |
| 기존 override에 남아 있던 IP | `15.165.74.101` |

따라서 `spacebar-sbav-elk-tunnel.service`가 예전 Bastion으로 붙으려다 timeout/restart를 반복했다.

## 3. 복구 내용

### 3.1 AWS 상태 확인

IAM CSV를 사용해 SB-AV Hanguel 실습 환경의 running 인스턴스를 확인했다.

| Name | Private IP | Public IP | Type | 상태 |
|---|---:|---:|---|---|
| `hanguel-bastion` | `10.60.0.10` | `3.35.149.83` | `t3.micro` | running |
| `hanguel-ops-pms` | `10.60.0.20` | `3.35.206.154` | `t3.small` | running |
| `hanguel-dc01` | `10.60.20.10` | 없음 | `t3.medium` | running |
| `hanguel-win01` | `10.60.30.10` | 없음 | `t3.micro` | running |
| `hanguel-soc01` | `10.60.40.10` | 없음 | `t3.large` | running |

### 3.2 ELK 직접 확인

Bastion을 경유해 `hanguel-soc01`에 접속한 뒤 Elasticsearch health를 확인했다.

```text
http://127.0.0.1:9200/_cluster/health
```

결과:

```json
{
  "cluster_name": "hanguel-soc",
  "status": "yellow",
  "number_of_nodes": 1,
  "active_shards_percent_as_number": 98.07692307692307
}
```

`yellow`는 단일 노드/replica 구성에서 자연스럽게 나올 수 있는 상태다. 이번 장애의 원인은 ELK 자체 down이 아니라 중앙 Controller의 SSH tunnel 경로 불일치였다.

### 3.3 중앙 Controller SSH tunnel 복구

처음에는 systemd `ExecStart`에 긴 `ProxyCommand`를 직접 넣어 수정하려 했지만, systemd/ssh의 `%h:%p` 이스케이프 문제로 다음 오류가 발생했다.

```text
Bad stdio forwarding specification '%h:%p'
```

따라서 긴 `ProxyCommand`를 service 파일에 직접 넣지 않고, 별도 SSH config로 분리했다.

생성한 파일:

```text
/etc/spacebar-bas/sbav_ssh_config
```

구성 의도:

- `hanguel-bastion`: 현재 Bastion public IP와 443 포트 사용
- `hanguel-soc`: Bastion을 `ProxyJump`로 경유해 private IP `10.60.40.10` 접근
- 중앙 Controller의 `127.0.0.1:19200`을 SOC Elasticsearch `127.0.0.1:9200`에 포워딩

복구 후 확인:

```text
spacebar-sbav-elk-tunnel.service active
127.0.0.1:19200 LISTEN
http://127.0.0.1:19200/_cluster/health 응답 정상
```

## 4. 최종 검증 결과

### 4.1 안전한 normal step 단독 검증

먼저 공격성이 없는 normal step만 실행했다.

| 항목 | 값 |
|---|---|
| Operation | `op-20260602-111838-7d4a45` |
| Campaign | `SB-AV` |
| Step | `Normal. Bastion Health Marker` |
| 실행 결과 | success |
| ELK checked | true |
| ELK matched | true |
| event_count | 1 |

### 4.2 SB-AV 전체 24개 step 재실행

터널 복구 후 SB-AV 전체 24개 step을 다시 실행했다.

| 항목 | 값 |
|---|---|
| Operation | `op-20260602-112015-8fce4b` |
| Campaign | `SB-AV` |
| 실행 step | 24 |
| 실행 성공 | 24/24 |
| source log matched | 24/24 |
| marker matched | 24/24 |
| alert matched | 18/24 |
| report score | 88 |
| telemetry coverage | 1.0 |
| detection coverage | 0.7273 |
| missed | 0 |
| logged only | 6 |

해석:

- BAS가 각 Technique을 실행하는 흐름은 정상이다.
- 각 step마다 source log와 marker가 ELK에서 확인되므로, "방금 실행한 BAS 행위가 ELK에 남았다"는 증거가 있다.
- 18개는 alert까지 발생했다.
- 6개는 source log는 남았지만 alert로 전환되지 않아 탐지 룰/상관 룰 보완 대상이다.

## 5. 발표 시 표현 가이드

### 5.1 안전한 표현

발표에서는 다음처럼 말하는 것이 안전하다.

```text
SB-AV 캠페인의 24개 step을 실행했고, 24개 모두 실행에 성공했습니다.
또한 각 step에 대해 ELK source log와 BAS marker가 모두 매칭되어,
BAS 실행 행위가 실제 로그로 남는 것을 확인했습니다.
다만 alert까지 발생한 항목은 18개이며,
나머지 6개는 로그는 남지만 탐지 룰 보완이 필요한 logged-only 항목으로 분류했습니다.
```

### 5.2 피해야 할 표현

다음 표현은 과장으로 보일 수 있다.

```text
24개 공격을 전부 탐지했습니다.
모든 탐지 룰이 정상 작동했습니다.
ELK 탐지 체계가 완벽합니다.
```

정확한 표현은 다음이다.

```text
24개 모두 실행했고, 24개 모두 로그 수집과 marker 검증은 성공했습니다.
이 중 alert로 전환된 것은 18개이며, 6개는 탐지 룰 개선 대상으로 남았습니다.
```

## 6. 현재 상태 체크리스트

### 6.1 정상 확인된 항목

- [x] 중앙 BAS API health 정상
- [x] nginx 정상
- [x] SB-AV Bastion BasAgent online
- [x] SB-AV PMS BasAgent online
- [x] SB-AV WIN01 BasAgent online
- [x] SB-AV DC01 BasAgent online
- [x] `hanguel-soc01` Elasticsearch health 응답
- [x] 중앙 Controller `127.0.0.1:19200` tunnel 복구
- [x] SB-AV 24개 step 실행 성공
- [x] SB-AV 24개 step source log matched
- [x] SB-AV 24개 step marker matched
- [x] SB-AV report 생성

### 6.2 아직 미흡한 항목

- [ ] SB-AV alert coverage가 18/24로 100%가 아니다.
- [ ] Bastion public IP가 바뀌면 ELK tunnel이 다시 깨질 수 있다.
- [ ] 중앙 서버 `/opt/spacebar-BAS`가 git repo가 아니라 배포 commit 추적이 약하다.
- [ ] Operation 상태가 일부 blocked/failed를 포함해도 `completed`로 보일 수 있는 구조가 남아 있다.
- [ ] SB-AD Agent는 현재 stale/offline 상태라 전체 대시보드 시연 시 태클 받을 수 있다.
- [ ] 로컬 repo에 untracked `BAS/` 중복 폴더가 남아 있어 실수로 staging될 위험이 있다.

## 7. 우선 개선점

### 1순위. Bastion Elastic IP 또는 터널 자동 갱신

현재 가장 위험한 운영 리스크다.

문제:

- Hanguel 환경 재생성/재기동 시 Bastion public IP가 바뀐다.
- 중앙 BAS의 `spacebar-sbav-elk-tunnel.service`는 IP를 고정값으로 들고 있다.
- IP가 바뀌면 ELK source check가 다시 `Connection refused`로 실패한다.

개선 방향:

- Bastion에 Elastic IP를 붙인다.
- 또는 systemd 시작 전 AWS CLI로 현재 `hanguel-bastion` public IP를 조회해 SSH config를 갱신한다.
- 또는 SSM Session Manager / private networking / VPN 기반으로 IP 의존도를 낮춘다.

발표 대비 답변:

```text
현재는 실습 환경 특성상 Bastion public IP 변경 시 tunnel 설정을 갱신해야 합니다.
이번 점검에서 이를 확인해 SSH config 방식으로 복구했고,
장기적으로는 Elastic IP 또는 AWS 조회 기반 자동 갱신으로 개선할 계획입니다.
```

### 2순위. alert coverage 18/24 분석

현재 source telemetry는 전부 확인되지만, alert 전환은 18/24다.

이건 실패라기보다 탐지 체계 개선 대상이다.

해야 할 일:

- 6개 logged-only step 목록 추출
- 각 step의 source event action, marker, expected rule id 확인
- Hanguel correlator 또는 Kibana rule 조건이 없는지 확인
- rule interval 때문에 늦게 생긴 alert인지 재조회
- backlog CSV와 발표 자료를 맞춘다.

발표 대비 답변:

```text
모든 행위가 source log와 marker로 수집되는 것은 확인했습니다.
다만 alert로 전환되지 않은 6개 항목은 탐지 룰 커버리지 갭으로 분류했고,
이를 detection backlog로 남겨 보완 대상으로 정리했습니다.
```

### 3순위. Operation 상태 표현 개선

현재 코드 구조상 일부 step이 blocked/failed여도 전체 Operation이 `completed`로 보일 수 있다.

문제:

- 발표자가 Operation 목록을 보여줄 때 `completed`인데 내부 step이 blocked인 과거 기록이 보일 수 있다.
- 심사위원이 "완료인데 왜 blocked가 있냐"고 물을 수 있다.

개선 방향:

- `completed_with_gaps`
- `partial_success`
- `completed_with_blocked`

같은 상태를 추가한다.

단기 발표 대응:

```text
전체 Operation 상태는 실행 종료 여부를 나타내고,
세부 성공/차단/미탐 여부는 summary와 step별 상태에서 확인하도록 설계했습니다.
다만 표현이 혼동될 수 있어 partial 상태를 추가하는 개선이 필요합니다.
```

### 4순위. 배포본 commit 추적

중앙 서버의 `/opt/spacebar-BAS`는 git repo가 아니다.

문제:

- 서버에서 `git log`로 배포 commit을 바로 확인할 수 없다.
- 발표/운영 중 "서버에 올라간 코드가 어느 버전이냐"는 질문에 약하다.

개선 방향:

- 배포 시 `REVISION` 파일 생성
- `/api/version` endpoint 추가
- GitHub Actions run id, commit hash, deployed_at 저장

예시:

```text
/opt/spacebar-BAS/REVISION
commit=664e0e0...
deployed_at=2026-06-02T...
github_run_id=...
```

### 5순위. SB-AD stale/offline 상태 정리

SB-AV 시연만 하면 문제가 없지만, 전체 대시보드를 보여주면 SB-AD Agent offline이 보인다.

개선 방향:

- 발표 범위를 SB-AV로 명확히 제한
- 또는 SB-AD Agent를 다시 살려 online으로 맞춘다.
- 전체 Agent 화면을 보여줄 때는 "현재 시연 대상은 SB-AV"라고 먼저 말한다.

### 6순위. untracked `BAS/` 중복 폴더 정리

현재 로컬 repo에 `BAS/` 중복 폴더가 untracked로 남아 있다.

문제:

- 실수로 staging하면 오래된 코드가 섞일 수 있다.
- `git status`가 항상 지저분해진다.

개선 방향:

- 실제로 필요한 폴더인지 확인
- 필요 없으면 archive 후 삭제
- 삭제 전에는 `BAS/` 내부가 현재 코드와 중복인지 diff 확인

## 8. 발표 태클 예상 질문과 답변

### Q1. 이 BAS는 실제 공격을 실행한 건가요, 아니면 로그만 만든 건가요?

답변:

```text
위험한 destructive 행위는 직접 수행하지 않고 controlled telemetry 방식으로 제한했습니다.
다만 각 Technique별로 실제 환경에서 관찰 가능한 source event와 marker를 남기고,
ELK에서 해당 로그와 alert 전환 여부를 검증하도록 구성했습니다.
```

### Q2. 24개를 다 탐지했다고 볼 수 있나요?

답변:

```text
24개 모두 source log와 BAS marker는 확인했습니다.
하지만 alert까지 전환된 것은 18개이므로, 모든 Technique이 탐지 룰로 완전히 커버됐다고 말하지는 않습니다.
나머지 6개는 logged-only로 분류해 탐지 룰 보완 backlog에 넣었습니다.
```

### Q3. 방금 실행한 로그라는 걸 어떻게 보장하나요?

답변:

```text
각 step마다 operation_id 기반 execution marker를 부여하고,
ELK에서 source query와 marker query를 함께 확인합니다.
이번 실행에서도 24개 step 모두 marker가 매칭되었습니다.
```

### Q4. ELK tunnel이 끊기면 어떻게 되나요?

답변:

```text
실행 결과는 남지만 탐지 검증 상태는 not_checked 또는 connection failed로 분리됩니다.
이번에도 Bastion public IP 변경으로 tunnel이 끊긴 것을 확인했고,
SSH config 기반 tunnel로 복구했습니다.
장기적으로는 Elastic IP 또는 AWS 조회 기반 자동 갱신이 필요합니다.
```

### Q5. 상용 BAS와 비교하면 부족한 점은 무엇인가요?

답변:

```text
상용 BAS처럼 EDR, NDR, 방화벽, WAF 차단 효과까지 모두 검증하는 수준은 아닙니다.
현재 프로젝트 범위는 ELK/SIEM 기반 탐지 체계를 대상으로,
MITRE ATT&CK Technique 실행과 로그/alert 커버리지를 검증하는 Mini BAS입니다.
```

## 9. 다음 작업 체크리스트

발표 전 최소 작업:

- [ ] 최신 Operation `op-20260602-112015-8fce4b`를 발표용 기준 실행으로 고정
- [ ] 18/24 alert matched, 6 logged-only를 표로 정리
- [ ] logged-only 6개가 왜 alert 미발생인지 rule gap으로 설명 준비
- [ ] 대시보드에서 SB-AD offline이 보이는 화면은 피하거나 설명 준비
- [ ] 발표 직전 `127.0.0.1:19200/_cluster/health` 확인
- [ ] 발표 직전 SB-AV agents 4개 online 확인

발표 후 개선:

- [ ] Bastion Elastic IP 적용 또는 tunnel 자동 갱신 스크립트 작성
- [ ] `/api/version` 및 `REVISION` 파일 추가
- [ ] Operation status에 `partial` 계열 상태 추가
- [ ] alert coverage 100%를 목표로 Hanguel rule/correlator 보완
- [ ] untracked `BAS/` 중복 폴더 정리
- [ ] SB-AD Agent 상태 복구 또는 캠페인별 Agent 필터링 UI 추가


# Attacker Ubuntu - Controller 및 Attacker BasAgent 설치 명세

## 역할

Attacker Ubuntu는 SB-AD BAS 구조의 중심이다.

- SpaceBaS Controller API 실행
- 필요 시 SpaceBaS Frontend 실행
- Attacker BasAgent 실행
- PC01/FS01 Agent의 register/heartbeat/job polling 수신
- T1105용 파일 제공 서버
- T1041용 업로드 수신 서버
- DCSync/Impacket 계열 테스트 실행 위치

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | Attacker-Ubuntu |
| Private IP | `10.0.1.194` |
| Public IP | `54.180.55.229` |
| Agent role | `attacker` |
| 설치 경로 | `/opt/spacebar-BAS` |
| Controller URL | `http://10.0.1.194:8000` |

IP는 재기동 후 바뀔 수 있으므로 설치 직전 AWS에서 다시 확인한다.

## 1. 접속

```bash
ssh -i /path/to/attacker-key.pem ubuntu@54.180.55.229
```

## 2. OS 패키지 설치

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl unzip
```

## 3. 코드 배치

권장 경로:

```bash
sudo mkdir -p /opt/spacebar-BAS
sudo chown -R ubuntu:ubuntu /opt/spacebar-BAS
cd /opt/spacebar-BAS
```

코드 배치 방식은 둘 중 하나를 선택한다.

### 방법 A. Git clone

```bash
git clone https://github.com/Jseanxx/spacebar-BAS.git .
git checkout bas-operation-builder
```

### 방법 B. 로컬에서 압축 파일 복사

```bash
# Mac에서 실행 예시
scp -i /path/to/attacker-key.pem spacebar-BAS.zip ubuntu@54.180.55.229:/tmp/

# Attacker Ubuntu에서 실행
cd /opt/spacebar-BAS
unzip /tmp/spacebar-BAS.zip
```

## 4. Python 가상환경

```bash
cd /opt/spacebar-BAS
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Attacker Agent 설정 확인

설정 파일:

```bash
cat agent_runtime/config.sbad-attacker.yaml
```

권장 값:

```yaml
agent_id: sbad-attacker-bas-agent
campaign_agent_id: SB-AD
agent_role: attacker
asset_id: attacker
segment_id: attacker-subnet
display_name: SB-AD Attacker BasAgent
hostname: Attacker-Ubuntu
platform: linux
collector_type: manual
controller_url: http://127.0.0.1:8000
interval_seconds: 2
execution_mode: simulation
```

Attacker Agent는 Controller와 같은 서버에서 실행하므로 `controller_url`은 `http://127.0.0.1:8000`으로 둬도 된다.

## 6. Controller 실행

테스트용 수동 실행:

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000
```

다른 터미널에서 확인:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/agents
```

## 7. Attacker BasAgent 실행

새 터미널에서:

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
export BAS_AGENT_ROLE=attacker
python agent_runtime/bas_agent.py --config agent_runtime/config.sbad-attacker.yaml --execution-mode simulation
```

Controller에서 확인:

```bash
curl http://127.0.0.1:8000/agents
```

정상 기대값:

```text
sbad-attacker-bas-agent
status: online
last_heartbeat_at: 최근 시간
```

## 8. real mode 실행 조건

처음에는 절대 real mode로 바로 실행하지 않는다.

real mode는 다음 조건을 모두 확인한 뒤 사용한다.

```bash
export BAS_AGENT_ROLE=attacker
export BAS_ALLOW_REAL_EXECUTION=1
```

DCSync 같은 도메인 침해급 테스트는 추가 승인 변수를 요구하도록 설계한다.

```bash
export BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1
```

주의:

- 해시/암호를 `.env`, config, git에 저장하지 않는다.
- shell history에 민감값이 남지 않게 한다.
- DC01 대상 테스트는 반드시 사전 동의 후 수행한다.

## 9. 보조 서버

T1105/T1041 테스트를 위해 Attacker에서 임시 서버가 필요할 수 있다.

파일 제공:

```bash
cd /home/ubuntu
sudo python3 -m http.server 80
```

업로드 수신은 별도 구현 필요:

```text
TODO: upload_server.py 또는 FastAPI upload endpoint 구현
```

## 10. 확인 체크리스트

```text
[ ] Controller가 0.0.0.0:8000에서 실행됨
[ ] curl http://127.0.0.1:8000/health 성공
[ ] Attacker BasAgent가 등록됨
[ ] /agents에서 sbad-attacker-bas-agent online 확인
[ ] PC01/FS01에서 10.0.1.194:8000 접근 가능
[ ] 필요 시 80/8080 포트가 VPC 내부에서 접근 가능
```

## 현재 부족한 점

- Attacker Agent가 HTTP/upload server를 자동으로 켜는 기능은 아직 미구현이다.
- DCSync real execution은 안전장치와 operator approval을 더 보강해야 한다.
- multi-agent routing이 아직 없으므로 campaign 전체 자동 분배는 구현 전이다.

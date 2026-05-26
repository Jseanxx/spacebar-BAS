# Attacker Ubuntu - Controller 및 Attacker BasAgent 설치 명세

작성일: 2026-05-26

## 역할

Attacker Ubuntu는 SB-AD 환경에서 SpaceBaS의 중심 노드다.

```text
Attacker Ubuntu
  - SpaceBaS Controller API
  - SpaceBaS Frontend
  - Attacker BasAgent
  - 파일 다운로드/업로드 테스트 서버 후보
```

## 기준 정보

| 항목 | 값 |
| --- | --- |
| VM | Attacker Ubuntu |
| Private IP | `10.0.1.194` |
| Public IP | 변동 가능 |
| Agent role | `attacker` |
| 설치 경로 | `/opt/spacebar-BAS` |
| Controller URL | `http://127.0.0.1:8000` |

## 1. 접속

```bash
ssh -i /path/to/key.pem ubuntu@<attacker-public-ip>
```

## 2. 필수 패키지 설치

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl
```

## 3. 코드 배치

```bash
sudo mkdir -p /opt/spacebar-BAS
sudo chown -R ubuntu:ubuntu /opt/spacebar-BAS
cd /opt/spacebar-BAS
git clone https://github.com/Jseanxx/spacebar-BAS.git .
git checkout bas-operation-builder
```

## 4. Python 환경

```bash
cd /opt/spacebar-BAS
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Controller 실행

개발/검증용:

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000
```

새 터미널에서 확인:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/agents
```

## 6. Frontend 실행

```bash
cd /opt/spacebar-BAS/frontend
npm install
npm run dev -- --host 0.0.0.0
```

운영자 Mac에서 SSH 터널을 열어 확인한다.

```bash
ssh -i /path/to/key.pem -L 5173:127.0.0.1:5173 -L 8000:127.0.0.1:8000 ubuntu@<attacker-public-ip>
```

브라우저:

```text
http://127.0.0.1:5173
```

## 7. Attacker BasAgent 실행

```bash
cd /opt/spacebar-BAS
. .venv/bin/activate
python agent_runtime/bas_agent.py \
  --config agent_runtime/config.sbad-attacker.yaml \
  --execution-mode simulation
```

기대 출력:

```text
[+] Registered BasAgent: sbad-attacker-bas-agent
```

## 8. 네트워크 확인

PC01/FS01에서 Attacker Controller로 붙어야 한다.

Attacker에서 API가 떠 있는지 확인:

```bash
ss -lntp | grep ':8000'
curl http://127.0.0.1:8000/health
```

PC01/FS01에서 아래가 성공해야 한다.

```powershell
Test-NetConnection 10.0.1.194 -Port 8000
```

실패하면 AWS SG 또는 OS 방화벽을 확인한다.

## 9. systemd 등록은 다음 단계

현재 명세는 수동 실행 기준이다. 터미널을 닫으면 Controller 또는 Agent가 종료될 수 있다.

실제 운영형으로 바꾸려면 다음 서비스를 추가한다.

```text
spacebas-controller.service
spacebas-attacker-agent.service
```

이 부분은 Agent online 검증 후 별도 고도화한다.

## 체크리스트

```text
[ ] /opt/spacebar-BAS 코드 배치 완료
[ ] .venv 생성 완료
[ ] pip install -r requirements.txt 완료
[ ] uvicorn api:app --host 0.0.0.0 --port 8000 실행
[ ] curl /health 성공
[ ] frontend dev server 실행
[ ] attacker BasAgent simulation 실행
[ ] /agents에서 sbad-attacker-bas-agent 확인
[ ] PC01/FS01에서 10.0.1.194:8000 접근 가능
```

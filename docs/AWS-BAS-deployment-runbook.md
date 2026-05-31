# AWS BAS Deployment Runbook

## Current Controller

- Host: `54.116.166.183`
- Web/API: `http://54.116.166.183:443`
- SSH: `ubuntu@54.116.166.183:2222`
- Runtime path: `/opt/spacebar-BAS`
- Static frontend path: `/var/www/spacebar-bas`
- Runtime secrets path: `/etc/spacebar-bas/spacebar-bas.env`

## CI/CD

`main` 브랜치에 push되면 GitHub Actions가 프론트엔드를 `VITE_API_BASE=/api`로 빌드하고, 배포 tarball을 EC2로 전송한 뒤 `/tmp/update_spacebar_bas.sh`를 실행한다.

필요한 GitHub Actions secrets:

- `BAS_AWS_HOST`
- `BAS_AWS_USER`
- `BAS_AWS_SSH_PORT`
- `BAS_AWS_SSH_KEY`
- `BAS_DASHBOARD_USER`
- `BAS_DASHBOARD_PASSWORD`
- `BAS_AGENT_TOKEN`
- `BAS_SBAD_ELK_USERNAME`
- `BAS_SBAD_ELK_PASSWORD`

## Agent Endpoint

Agent는 다음 Controller URL을 사용한다.

```text
http://54.116.166.183:443/api
```

Agent API는 `BAS_AGENT_TOKEN` 기반 헤더 인증을 사용한다.

```text
X-BAS-Agent-Token: <token>
```

## ELK Tunnels

중앙 Controller EC2에서 systemd SSH tunnel로 ELK를 로컬 포트에 연결한다.

- SB-AD ELK: `127.0.0.1:19201`
- SB-AV ELK: `127.0.0.1:19200`

상대 환경 보안그룹은 중앙 Controller EIP `54.116.166.183/32`의 TCP 443 접근만 허용한다.

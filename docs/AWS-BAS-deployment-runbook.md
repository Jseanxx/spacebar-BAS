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
- `BAS_AGENT_TOKEN`
- `BAS_SBAD_ELK_USERNAME`
- `BAS_SBAD_ELK_PASSWORD`

Dashboard Basic Auth 기준값:

- Username: `bas`
- Password: 운영자가 EC2의 `/etc/spacebar-bas/htpasswd`에 설정한 값

운영 원칙:

- Dashboard Basic Auth는 GitHub Actions Secret이 아니라 EC2의 `/etc/spacebar-bas/htpasswd`를 기준으로 유지한다.
- `main` 브랜치에 push되더라도 GitHub Actions는 dashboard user/password를 배포 env로 넘기지 않는다.
- 따라서 배포 스크립트는 기존 `/etc/spacebar-bas/htpasswd`를 보존한다.
- 비밀번호를 변경해야 할 때만 EC2에서 아래 방식으로 수동 갱신한다.

```text
sudo bash -lc 'python3 - <<'"'"'PY'"'"' > /etc/spacebar-bas/htpasswd
import crypt
print("bas:" + crypt.crypt("<new password>", "ba"))
PY'
sudo chown root:www-data /etc/spacebar-bas/htpasswd
sudo chmod 0640 /etc/spacebar-bas/htpasswd
sudo systemctl reload nginx
```

## Agent Endpoint

Agent는 다음 Controller URL을 사용한다.

```text
https://kisia.kro.kr/api
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

SB-AV는 Hanguel Bastion을 경유해 `hanguel-soc01`의 Elasticsearch에 접근한다. Bastion public IP가 바뀌면 `spacebar-sbav-elk-tunnel.service`가 예전 IP로 붙으려다 실패할 수 있으므로, 발표/시연 전에는 다음을 확인한다.

```bash
systemctl is-active spacebar-sbav-elk-tunnel.service
ss -lntp | grep 19200
curl -sS --max-time 5 http://127.0.0.1:19200/_cluster/health
```

2026-06-02 복구 기준으로 SB-AV tunnel은 `/etc/spacebar-bas/sbav_ssh_config`를 사용한다. 긴 `ProxyCommand`를 systemd `ExecStart`에 직접 넣으면 `%h:%p` 이스케이프가 꼬일 수 있으므로 SSH config로 분리하는 방식을 유지한다.

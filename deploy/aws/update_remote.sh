#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/spacebar-BAS}"
WEB_DIR="${WEB_DIR:-/var/www/spacebar-bas}"
ENV_DIR="${ENV_DIR:-/etc/spacebar-bas}"
ARCHIVE="${SPACEBAR_BAS_ARCHIVE:-/tmp/spacebar-bas-deploy.tar.gz}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ ! -f "${ARCHIVE}" ]]; then
  echo "Deploy archive not found: ${ARCHIVE}" >&2
  exit 1
fi

install -d -m 0755 "${APP_DIR}" "${WEB_DIR}" "${ENV_DIR}"
tar -xzf "${ARCHIVE}" -C "${APP_DIR}"

cd "${APP_DIR}"
if [[ ! -d .venv ]]; then
  "${PYTHON_BIN}" -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip >/tmp/spacebar-bas-pip.log 2>&1
.venv/bin/python -m pip install -r requirements.txt >>/tmp/spacebar-bas-pip.log 2>&1

if [[ -d frontend/dist ]]; then
  find "${WEB_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  cp -a frontend/dist/. "${WEB_DIR}/"
else
  echo "frontend/dist is missing from deploy archive" >&2
  exit 1
fi

touch "${ENV_DIR}/spacebar-bas.env"
chmod 0600 "${ENV_DIR}/spacebar-bas.env"

set_env_value() {
  local key="$1"
  local value="$2"
  [[ -z "${value}" ]] && return 0
  sed -i "/^${key}=/d" "${ENV_DIR}/spacebar-bas.env"
  printf '%s=%s\n' "${key}" "${value}" >> "${ENV_DIR}/spacebar-bas.env"
}

set_env_value "BAS_AGENT_TOKEN" "${BAS_AGENT_TOKEN:-}"
set_env_value "BAS_SBAD_ELK_USERNAME" "${BAS_SBAD_ELK_USERNAME:-elastic}"
set_env_value "BAS_SBAD_ELK_PASSWORD" "${BAS_SBAD_ELK_PASSWORD:-}"
set_env_value "BAS_ELK_ALERT_WINDOW_MINUTES" "${BAS_ELK_ALERT_WINDOW_MINUTES:-90}"
set_env_value "BAS_ELK_FALLBACK_WINDOW_MINUTES" "${BAS_ELK_FALLBACK_WINDOW_MINUTES:-120}"

if [[ -n "${DASHBOARD_USER:-}" && -n "${DASHBOARD_PASSWORD:-}" ]]; then
  printf '%s:%s\n' "${DASHBOARD_USER}" "$(openssl passwd -apr1 "${DASHBOARD_PASSWORD}")" > "${ENV_DIR}/htpasswd"
  chown root:www-data "${ENV_DIR}/htpasswd"
  chmod 0640 "${ENV_DIR}/htpasswd"
fi

if command -v nginx >/dev/null 2>&1; then
  NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/spacebar-bas}"
  cat > "${NGINX_SITE}" <<'NGINX'
server {
    listen 443 default_server;
    server_name _;
    root /var/www/spacebar-bas;
    index index.html;
    client_max_body_size 20m;

    location = /api/agents {
        auth_basic "Spacebar BAS";
        auth_basic_user_file /etc/spacebar-bas/htpasswd;
        proxy_pass http://127.0.0.1:8000/agents;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;
    }

    location /api/agents {
        proxy_pass http://127.0.0.1:8000/agents;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;
    }

    location /api/ {
        auth_basic "Spacebar BAS";
        auth_basic_user_file /etc/spacebar-bas/htpasswd;
        proxy_pass http://127.0.0.1:8000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;
    }

    location / {
        auth_basic "Spacebar BAS";
        auth_basic_user_file /etc/spacebar-bas/htpasswd;
        try_files $uri $uri/ /index.html;
    }
}
NGINX
  ln -sf "${NGINX_SITE}" /etc/nginx/sites-enabled/spacebar-bas
  nginx -t
fi

systemctl daemon-reload
systemctl restart spacebar-bas-api.service
systemctl reload nginx

if systemctl list-unit-files | grep -q '^spacebar-sbad-elk-tunnel.service'; then
  systemctl restart spacebar-sbad-elk-tunnel.service || true
fi
if systemctl list-unit-files | grep -q '^spacebar-sbav-elk-tunnel.service'; then
  systemctl restart spacebar-sbav-elk-tunnel.service || true
fi

systemctl is-active --quiet spacebar-bas-api.service
systemctl is-active --quiet nginx
echo "Spacebar BAS deploy completed."

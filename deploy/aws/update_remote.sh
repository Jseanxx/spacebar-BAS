#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/spacebar-BAS}"
WEB_DIR="${WEB_DIR:-/var/www/spacebar-bas}"
LANDING_DIR="${LANDING_DIR:-/var/www/spacebar-landing}"
ACME_DIR="${ACME_DIR:-/var/www/letsencrypt}"
ENV_DIR="${ENV_DIR:-/etc/spacebar-bas}"
ARCHIVE="${SPACEBAR_BAS_ARCHIVE:-/tmp/spacebar-bas-deploy.tar.gz}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PUBLIC_DOMAIN="${BAS_PUBLIC_DOMAIN:-kisia.kro.kr}"
CERT_PATH="/etc/letsencrypt/live/${PUBLIC_DOMAIN}/fullchain.pem"
CERT_KEY_PATH="/etc/letsencrypt/live/${PUBLIC_DOMAIN}/privkey.pem"

if [[ ! -f "${ARCHIVE}" ]]; then
  echo "Deploy archive not found: ${ARCHIVE}" >&2
  exit 1
fi

install -d -m 0755 "${APP_DIR}" "${WEB_DIR}" "${LANDING_DIR}" "${ACME_DIR}" "${ENV_DIR}"
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

if [[ -d deploy/aws/landing ]]; then
  LANDING_PREVIEWS_BACKUP=""
  if [[ -d "${LANDING_DIR}/previews" && ! -d deploy/aws/landing/previews ]]; then
    LANDING_PREVIEWS_BACKUP="$(mktemp -d)"
    cp -a "${LANDING_DIR}/previews" "${LANDING_PREVIEWS_BACKUP}/"
  fi
  find "${LANDING_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  cp -a deploy/aws/landing/. "${LANDING_DIR}/"
  if [[ -n "${LANDING_PREVIEWS_BACKUP}" && -d "${LANDING_PREVIEWS_BACKUP}/previews" && ! -d "${LANDING_DIR}/previews" ]]; then
    cp -a "${LANDING_PREVIEWS_BACKUP}/previews" "${LANDING_DIR}/previews"
  fi
  [[ -n "${LANDING_PREVIEWS_BACKUP}" ]] && rm -rf "${LANDING_PREVIEWS_BACKUP}"
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
elif [[ ! -s "${ENV_DIR}/htpasswd" ]]; then
  echo "Dashboard htpasswd is missing. Create ${ENV_DIR}/htpasswd before deploying without dashboard credentials." >&2
  exit 1
else
  echo "Preserving existing dashboard htpasswd."
fi

if command -v nginx >/dev/null 2>&1; then
  NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/spacebar-bas}"
  if [[ -f "${CERT_PATH}" && -f "${CERT_KEY_PATH}" ]]; then
  cat > "${NGINX_SITE}" <<'NGINX'
server {
    listen 80 default_server;
    server_name _;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl default_server;
    server_name _;
    root /var/www/spacebar-landing;
    index index.html;
    client_max_body_size 20m;

    ssl_certificate /etc/letsencrypt/live/kisia.kro.kr/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kisia.kro.kr/privkey.pem;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }

    location = /dashboard {
        return 301 /dashboard/;
    }

    location /dashboard/ {
        auth_basic "Spacebar BAS v2";
        auth_basic_user_file /etc/spacebar-bas/htpasswd;
        alias /var/www/spacebar-bas/;
        try_files $uri $uri/ /dashboard/index.html;
    }

    location /assets/ {
        alias /var/www/spacebar-bas/assets/;
    }

    location = /favicon.svg {
        alias /var/www/spacebar-bas/favicon.svg;
    }

    location = /icons.svg {
        alias /var/www/spacebar-bas/icons.svg;
    }

    location = /api/agents {
        auth_basic "Spacebar BAS v2";
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
        auth_basic "Spacebar BAS v2";
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
        try_files $uri $uri/ =404;
    }
}
NGINX
  else
  cat > "${NGINX_SITE}" <<'NGINX'
server {
    listen 80 default_server;
    listen 443 default_server;
    server_name _;
    root /var/www/spacebar-landing;
    index index.html;
    client_max_body_size 20m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }

    location = /dashboard {
        return 301 /dashboard/;
    }

    location /dashboard/ {
        auth_basic "Spacebar BAS v2";
        auth_basic_user_file /etc/spacebar-bas/htpasswd;
        alias /var/www/spacebar-bas/;
        try_files $uri $uri/ /dashboard/index.html;
    }

    location /assets/ {
        alias /var/www/spacebar-bas/assets/;
    }

    location = /favicon.svg {
        alias /var/www/spacebar-bas/favicon.svg;
    }

    location = /icons.svg {
        alias /var/www/spacebar-bas/icons.svg;
    }

    location = /api/agents {
        auth_basic "Spacebar BAS v2";
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
        auth_basic "Spacebar BAS v2";
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
        try_files $uri $uri/ =404;
    }
}
NGINX
  fi
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

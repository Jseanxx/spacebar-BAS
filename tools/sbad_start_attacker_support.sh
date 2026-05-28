#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/spacebar-BAS}"
SUPPORT_ROOT="${SUPPORT_ROOT:-/tmp/spacebar-bas-support}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "${SUPPORT_ROOT}/uploads"
printf 'Spacebar BAS benign T1105 probe file.\n' > "${SUPPORT_ROOT}/bas_t1105_probe.txt"

start_server() {
  local port="$1"
  local role="$2"
  local log_file="${SUPPORT_ROOT}/${role}-${port}.log"
  local pid_file="${SUPPORT_ROOT}/${role}-${port}.pid"

  if [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
    echo "[=] ${role} server already running on ${port} pid=$(cat "${pid_file}")"
    return
  fi

  nohup "${PYTHON_BIN}" "${PROJECT_DIR}/tools/sbad_support_server.py" \
    --port "${port}" \
    --root "${SUPPORT_ROOT}" \
    --upload-dir "${SUPPORT_ROOT}/uploads" \
    --log "${log_file}" \
    --role "${role}" \
    > "${log_file}" 2>&1 &
  echo "$!" > "${pid_file}"
  echo "[+] started ${role} server on ${port} pid=$(cat "${pid_file}")"
}

start_server "${BAS_ATTACKER_HTTP_PORT:-80}" "file"
start_server "${BAS_ATTACKER_UPLOAD_PORT:-8080}" "upload"

echo "[+] health checks"
curl -fsS "http://127.0.0.1:${BAS_ATTACKER_HTTP_PORT:-80}/health" || true
echo
curl -fsS "http://127.0.0.1:${BAS_ATTACKER_UPLOAD_PORT:-8080}/health" || true
echo

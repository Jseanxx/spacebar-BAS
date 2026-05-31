#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/home/ubuntu/spacebar-BAS-codex}"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_DIR}/.venv/bin/python}"
CONTROLLER_PORT="${BAS_CONTROLLER_PORT:-8000}"
AGENT_CONFIG="${AGENT_CONFIG:-agent_runtime/config.sbad-attacker.yaml}"
SUPPORT_ROOT="${SUPPORT_ROOT:-/tmp/spacebar-bas-support}"

cd "${PROJECT_DIR}"

export BAS_AGENT_ROLE="${BAS_AGENT_ROLE:-attacker}"
export BAS_ALLOW_REAL_EXECUTION="${BAS_ALLOW_REAL_EXECUTION:-1}"
export BAS_ELK_URL="${BAS_ELK_URL:-http://10.0.4.30:9200}"
export BAS_ELK_USERNAME="${BAS_ELK_USERNAME:-elastic}"
export BAS_STEP_ALERT_WAIT_SECONDS="${BAS_STEP_ALERT_WAIT_SECONDS:-45}"

mkdir -p outputs/logs "${SUPPORT_ROOT}"

if ! pgrep -f "uvicorn api:app.*--port ${CONTROLLER_PORT}" >/dev/null 2>&1; then
  nohup "${PYTHON_BIN}" -m uvicorn api:app --host 0.0.0.0 --port "${CONTROLLER_PORT}" \
    > outputs/logs/sbad-controller.log 2>&1 &
  echo "[+] controller started pid=$!"
else
  echo "[=] controller already running"
fi

PROJECT_DIR="${PROJECT_DIR}" SUPPORT_ROOT="${SUPPORT_ROOT}" PYTHON_BIN="${PYTHON_BIN}" \
  bash tools/sbad_start_attacker_support.sh

pkill -f "agent_runtime/bas_agent.py --config ${AGENT_CONFIG}" 2>/dev/null || true
nohup "${PYTHON_BIN}" agent_runtime/bas_agent.py --config "${AGENT_CONFIG}" --execution-mode real \
  > outputs/logs/sbad-attacker-agent.log 2>&1 &

echo "[+] attacker BasAgent started pid=$!"
echo "[+] mode=real elk=${BAS_ELK_URL}"
echo "[!] Set BAS_ELK_PASSWORD, BAS_DA_NTLM_HASH, BAS_KRBTGT_AES256, and BAS_DOMAIN_SID in the environment before approved domain-compromise tests."

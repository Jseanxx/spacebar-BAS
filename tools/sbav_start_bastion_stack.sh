#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/spacebar-BAS}"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_DIR}/.venv/bin/python}"
CONTROLLER_PORT="${BAS_CONTROLLER_PORT:-8000}"
AGENT_CONFIG="${AGENT_CONFIG:-agent_runtime/config.sbav-bastion.yaml}"

cd "${PROJECT_DIR}"

if [ ! -x "${PYTHON_BIN}" ]; then
  python3 -m venv .venv
  PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
fi

"${PYTHON_BIN}" -m pip install -r requirements.txt

export BAS_AGENT_ROLE="${BAS_AGENT_ROLE:-bastion}"
export BAS_ALLOW_REAL_EXECUTION="${BAS_ALLOW_REAL_EXECUTION:-1}"
export BAS_AV_LOGSTASH_URL="${BAS_AV_LOGSTASH_URL:-http://10.60.40.10:8088}"
export BAS_ELK_URL="${BAS_ELK_URL:-http://10.60.40.10:9200}"
export BAS_STEP_ALERT_WAIT_SECONDS="${BAS_STEP_ALERT_WAIT_SECONDS:-25}"
export BAS_DEFER_ELK_CHECKS="${BAS_DEFER_ELK_CHECKS:-1}"

mkdir -p outputs/logs

if ! pgrep -f "uvicorn api:app.*--port ${CONTROLLER_PORT}" >/dev/null 2>&1; then
  nohup "${PYTHON_BIN}" -m uvicorn api:app --host 0.0.0.0 --port "${CONTROLLER_PORT}" \
    > outputs/logs/sbav-controller.log 2>&1 &
  echo "[+] SB-AV controller started pid=$!"
else
  echo "[=] SB-AV controller already running"
fi

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "http://127.0.0.1:${CONTROLLER_PORT}/health" >/dev/null 2>&1; then
  echo "[!] SB-AV controller did not become healthy; see outputs/logs/sbav-controller.log" >&2
  exit 1
fi

pkill -f "agent_runtime/bas_agent.py --config ${AGENT_CONFIG}" 2>/dev/null || true
nohup "${PYTHON_BIN}" agent_runtime/bas_agent.py --config "${AGENT_CONFIG}" --execution-mode real \
  > outputs/logs/sbav-bastion-agent.log 2>&1 &

echo "[+] SB-AV bastion BasAgent started pid=$!"
echo "[+] controller=http://10.60.0.10:${CONTROLLER_PORT}"
echo "[!] High-risk gates remain disabled unless explicitly exported."

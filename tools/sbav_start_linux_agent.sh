#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-pms}"
MODE="${2:-real}"
PROJECT_DIR="${PROJECT_DIR:-/opt/spacebar-BAS}"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_DIR}/.venv/bin/python}"
CONFIG="agent_runtime/config.sbav-${ROLE}.yaml"

if [ "${ROLE}" != "bastion" ] && [ "${ROLE}" != "pms" ]; then
  echo "Usage: $0 [bastion|pms] [simulation|real]" >&2
  exit 2
fi

cd "${PROJECT_DIR}"

if [ -x "${PYTHON_BIN}" ] && ! "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
  echo "[!] existing venv has no pip; falling back to system python3" >&2
  PYTHON_BIN="$(command -v python3)"
fi

if [ ! -x "${PYTHON_BIN}" ]; then
  if python3 -m venv .venv; then
    PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
  else
    echo "[!] python3 venv creation failed; falling back to system python3" >&2
    PYTHON_BIN="$(command -v python3)"
  fi
fi

if [ "${PYTHON_BIN}" = "${PROJECT_DIR}/.venv/bin/python" ]; then
  "${PYTHON_BIN}" -m pip install -r requirements.txt
else
  "${PYTHON_BIN}" - <<'PY'
import yaml  # noqa: F401
PY
fi

export BAS_AGENT_ROLE="${ROLE}"
export BAS_AV_LOGSTASH_URL="${BAS_AV_LOGSTASH_URL:-http://10.60.40.10:8088}"
export BAS_ELK_URL="${BAS_ELK_URL:-http://10.60.40.10:9200}"
export BAS_STEP_ALERT_WAIT_SECONDS="${BAS_STEP_ALERT_WAIT_SECONDS:-0}"
export BAS_DEFER_ELK_CHECKS="${BAS_DEFER_ELK_CHECKS:-1}"

if [ "${MODE}" = "real" ]; then
  export BAS_ALLOW_REAL_EXECUTION="${BAS_ALLOW_REAL_EXECUTION:-1}"
fi

if [ "${ROLE}" = "pms" ]; then
  export BAS_AV_ALLOW_MARKER_FILES="${BAS_AV_ALLOW_MARKER_FILES:-1}"
  export BAS_AV_ALLOW_PMS_PATCH_EMULATION="${BAS_AV_ALLOW_PMS_PATCH_EMULATION:-1}"
fi

if [ ! -f "${CONFIG}" ]; then
  echo "Agent config not found: ${CONFIG}" >&2
  exit 1
fi

mkdir -p outputs/logs
pkill -f "agent_runtime/bas_agent.py --config ${CONFIG}" 2>/dev/null || true
nohup "${PYTHON_BIN}" agent_runtime/bas_agent.py --config "${CONFIG}" --execution-mode "${MODE}" \
  > "outputs/logs/sbav-${ROLE}-agent.log" 2>&1 &

echo "[+] SB-AV ${ROLE} BasAgent started pid=$! mode=${MODE}"

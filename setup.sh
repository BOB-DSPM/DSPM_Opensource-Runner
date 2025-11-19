#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/log.txt"

cd "$SCRIPT_DIR"

echo "[INFO] Starting OSS Runner in background..."
nohup bash run.sh > "$LOG_FILE" 2>&1 &
PID=$!

echo "[INFO] OSS Runner started with PID ${PID}."
echo "[INFO] Logs are being written to ${LOG_FILE}."
echo "${PID}" > "${SCRIPT_DIR}/oss_runner.pid"

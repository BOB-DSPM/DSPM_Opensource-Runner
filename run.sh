# run.sh
#!/usr/bin/env bash
set -euo pipefail

python -V
export PYTHONUNBUFFERED=1
export UVICORN_WORKERS="${UVICORN_WORKERS:-1}"
export UVICORN_PORT="${UVICORN_PORT:-8000}"
export UVICORN_HOST="${UVICORN_HOST:-0.0.0.0}"

# 가벼운 IO 스트리밍이므로 worker=1 + --loop asyncio 권장
exec uvicorn app.main:app --host "$UVICORN_HOST" --port "$UVICORN_PORT" --reload

# app/routers/health.py
from __future__ import annotations
import time
from fastapi import APIRouter
from app.core.config import settings
from app.services.runner import runner_service

router = APIRouter()

@router.get("/health")
def health():
    runs = runner_service.list()
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "uptime_sec": int(time.process_time()),
        "runs_total": len(runs),
        "runs_running": sum(1 for r in runs if r.status == "RUNNING"),
    }

# =========================
# file: app/routers/oss.py
# =========================
from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
import json

from ..services.oss_service import (
    get_catalog as svc_get_catalog,
    get_detail as svc_get_detail,
    simulate_use as svc_simulate_use,
    run_tool as svc_run_tool,
    iter_run_stream as svc_iter_run_stream,
)

router = APIRouter(prefix="/api/oss", tags=["oss"])

@router.get("", summary="오픈소스 카탈로그 조회")
def get_catalog(q: Optional[str] = Query(None, description="검색어 (선택)")) -> Dict[str, Any]:
    return svc_get_catalog(q)

@router.get("/{code}", summary="오픈소스 상세 정보(정적)")
def get_detail(code: str) -> Dict[str, Any]:
    data = svc_get_detail(code)
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return data

@router.post("/{code}/use", summary="오픈소스 '사용하기' 시뮬레이션 (명령만 생성)")
def simulate_use(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = svc_simulate_use(code, payload or {})
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return data

@router.post("/{code}/run", summary="오픈소스 실행 (실제 커맨드 실행 후 결과 반환)")
def run_use(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = svc_run_tool(code, payload or {})
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return data

# ✅ 실시간 로그 스트리밍(텍스트 스트림)
@router.post("/{code}/run/stream", summary="오픈소스 실행 (실시간 스트림)")
async def run_stream(code: str, request: Request) -> StreamingResponse:
    # ⚠️ 빈 바디/비-JSON도 안전 처리
    payload: Dict[str, Any] = {}
    try:
        ct = (request.headers.get("content-type") or "").lower()
        if "application/json" in ct:
            raw = await request.body()
            if raw and raw.strip():
                payload = json.loads(raw.decode("utf-8"))
        elif "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
            form = await request.form()
            # FormData -> dict로 단순 변환
            payload = {k: v for k, v in form.items()}
        else:
            payload = {}
    except Exception:
        # 파싱 실패해도 스트림은 기본 옵션으로 진행
        payload = {}

    gen = svc_iter_run_stream(code, payload or {})
    return StreamingResponse(gen, media_type="text/plain; charset=utf-8")

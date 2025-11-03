# app/routers/oss.py
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query
from ..services import get_catalog as svc_get_catalog, get_detail as svc_get_detail, simulate_use as svc_simulate_use

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

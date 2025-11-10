# =========================
# file: app/routers/oss.py
# =========================
from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, FileResponse
import json
from pathlib import Path
from urllib.parse import quote

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

def _augment_with_download_urls(resp: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """run 응답에 files[].download_url 추가."""
    try:
        run_dir = resp.get("run_dir")
        files = resp.get("files", [])
        for f in files:
            p = f.get("path")
            if not (run_dir and p):
                continue
            # /api/oss/files?run_dir=...&path=... 로 다운로드
            url = str(request.url_for("download_file")) + f"?run_dir={quote(run_dir)}&path={quote(p)}"
            f["download_url"] = url
    except Exception:
        pass
    return resp

@router.post("/{code}/run", summary="오픈소스 실행 (실제 커맨드 실행 후 결과 반환)")
def run_use(code: str, payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    data = svc_run_tool(code, payload or {})
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return _augment_with_download_urls(data, request)

@router.post("/{code}/run/stream", summary="오픈소스 실행 (실시간 스트림)")
async def run_stream(code: str, request: Request) -> StreamingResponse:
    payload: Dict[str, Any] = {}
    try:
        ct = (request.headers.get("content-type") or "").lower()
        if "application/json" in ct:
            raw = await request.body()
            if raw and raw.strip():
                payload = json.loads(raw.decode("utf-8"))
        elif "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
            form = await request.form()
            payload = {k: v for k, v in form.items()}
        else:
            payload = {}
    except Exception:
        payload = {}
    gen = svc_iter_run_stream(code, payload or {})
    return StreamingResponse(gen, media_type="text/plain; charset=utf-8")

# ---------- [NEW] 안전한 파일 다운로드 엔드포인트 ----------
@router.get("/files", name="download_file", summary="실행 산출물 다운로드")
def download_file(run_dir: str = Query(..., description="runs/... 하위 경로"),
                  path: str = Query(..., description="run_dir 기준 상대 파일 경로")):
    # runs 루트 고정
    runs_root = (Path.cwd() / "runs").resolve()
    base = (Path(run_dir)).resolve()
    # run_dir가 runs 하위인지 검사
    if not str(base).startswith(str(runs_root)):
        raise HTTPException(400, "invalid run_dir")

    # 파일 경로 정규화 및 디렉터리 탈출 방지
    file_path = (base / path).resolve()
    if not str(file_path).startswith(str(base)):
        raise HTTPException(400, "invalid path")
    if not (file_path.exists() and file_path.is_file()):
        raise HTTPException(404, "file not found")

    # 파일 다운로드
    return FileResponse(str(file_path), filename=file_path.name, media_type="application/octet-stream")

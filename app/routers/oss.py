# =========================
# file: app/routers/oss.py
# =========================
from __future__ import annotations

from typing import Any, Dict, Optional, List
import json
import os
from pathlib import Path
from urllib.parse import quote
from mimetypes import guess_type

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, FileResponse

from ..services.oss_service import (
    get_catalog as svc_get_catalog,
    get_detail as svc_get_detail,
    simulate_use as svc_simulate_use,
    run_tool as svc_run_tool,
    iter_run_stream as svc_iter_run_stream,
    find_latest_result_for_code as svc_find_latest_result_for_code,
    collect_executed_contents as svc_collect_executed_contents,
)

router = APIRouter(prefix="/api/oss", tags=["oss"])

# runs/<YYYYMM>/<uuid> 구조 가정
RUNS_ROOT = Path("runs")


# -------------------------------------------------------------------
# 내부 헬퍼
# -------------------------------------------------------------------
def _augment_with_download_urls(resp: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """
    run 응답에 files[].download_url 추가.
    * 주의: files[].path 는 download_file에서 run_dir 기준 상대 경로로 해석됨.
    """
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
        # URL 주입에 실패해도 본문 자체는 반환
        pass
    return resp


def _iter_run_dirs() -> List[Path]:
    """runs/<YYYYMM>/<uuid> 를 최신순으로 나열 (로그/outputs mtime 기준)."""
    if not RUNS_ROOT.exists():
        return []
    dirs: List[Path] = []
    for month_dir in sorted(RUNS_ROOT.iterdir()):
        if not month_dir.is_dir():
            continue
        for run_dir in month_dir.iterdir():
            if run_dir.is_dir():
                dirs.append(run_dir)

    def key(p: Path) -> float:
        outdir = p / "outputs"
        logf = outdir / "log.txt"
        if logf.exists():
            return logf.stat().st_mtime
        if outdir.exists():
            return outdir.stat().st_mtime
        return p.stat().st_mtime

    dirs.sort(key=key, reverse=True)
    return dirs


def _collect_files_for_run(run_dir: Path) -> List[dict]:
    """
    run_dir/outputs 하위 파일을 스캔하여 files 배열 생성.
    download_file 엔드포인트가 run_dir 기준 상대경로를 요구하므로,
    path는 반드시 run_dir 기준으로 계산(= 'outputs/...' 포함)한다.
    """
    output_dir = run_dir / "outputs"
    files: List[dict] = []
    if not output_dir.exists():
        return files

    for p in output_dir.rglob("*"):
        if p.is_file():
            rel = p.relative_to(run_dir)  # run_dir 기준 상대경로
            files.append(
                {
                    "path": str(rel.as_posix()),  # 예: outputs/log.txt, outputs/compliance/....
                    "size": p.stat().st_size,
                    "mtime": int(p.stat().st_mtime),
                }
            )
    return files


def _load_result_from_json(run_dir: Path) -> Optional[dict]:
    """run_dir/result.json 이 있으면 로드."""
    f = run_dir / "result.json"
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _guess_code_from_files(files: List[dict]) -> Optional[str]:
    """파일 패턴으로 code 추정 (간단 휴리스틱)."""
    for f in files:
        path = f.get("path", "")
        if "prowler-output" in path:
            return "prowler"
    return None


def _read_tail(path: Path, max_bytes: int = 64 * 1024) -> str:
    """로그 마지막 일부만 읽어 요약 STDOUT로 제공."""
    try:
        if not path.exists():
            return ""
        data = path.read_bytes()
        if len(data) > max_bytes:
            return data[-max_bytes:].decode(errors="ignore")
        return data.decode(errors="ignore")
    except Exception:
        return ""


def _build_summary_from_fs(run_dir: Path, code_hint: Optional[str]) -> dict:
    """
    result.json이 없는 실행 디렉토리에 대해 파일시스템을 스캔해
    최소 정보(로그 tail, 파일 목록)를 구성.
    """
    output_dir = run_dir / "outputs"
    log_tail = _read_tail(output_dir / "log.txt")
    files = _collect_files_for_run(run_dir)
    code = code_hint or _guess_code_from_files(files) or "unknown"

    return {
        "code": code,
        "command": None,
        "run_dir": str(run_dir.as_posix()),
        "output_dir": str(output_dir.as_posix()),
        "rc": None,
        "duration_ms": None,
        "stdout": log_tail,  # 콘솔 감성으로 tail 제공
        "stderr": "",
        "files": files,
        "note": "result.json이 없어 파일시스템을 스캔해 구성한 요약 응답입니다.",
        "preinstall": None,
    }


# -------------------------------------------------------------------
# 카탈로그 (정적)
# -------------------------------------------------------------------
@router.get("", summary="오픈소스 카탈로그 조회")
def get_catalog(q: Optional[str] = Query(None, description="검색어 (선택)")) -> Dict[str, Any]:
    return svc_get_catalog(q)


# -------------------------------------------------------------------
# [정적 경로 우선 선언] 파일 다운로드 / Scout Suite 정적 자산 / 최근 실행 / 실행 API
#  - 동적 경로("/{code}")보다 위에 선언하여 경로 충돌 방지
# -------------------------------------------------------------------
@router.get("/files", name="download_file", summary="실행 산출물 다운로드")
def download_file(
    run_dir: str = Query(..., description="runs/... 또는 YYYYMM/uuid 형태도 허용"),
    path: str = Query(..., description="run_dir 기준 상대 파일 경로 (예: outputs/xxx.csv)"),
):
    """
    안전한 파일 다운로드:
    - run_dir은 'runs/...' 또는 'YYYYMM/uuid' 형태 모두 허용
    - 디렉터리 탈출 방지
    - MIME 타입 추정 + inline/attachment 결정
    """
    runs_root = (Path.cwd() / "runs").resolve()

    # 1) run_dir 보정: 'runs/' 접두사가 없어도 허용
    rd = run_dir.lstrip("/").replace("\\", "/")
    if not rd.startswith("runs/"):
        rd = f"runs/{rd}"

    # 2) 항상 runs_root 기준으로 절대 경로 계산
    try:
        base = (runs_root / Path(rd).relative_to("runs")).resolve()
    except Exception:
        raise HTTPException(400, "invalid run_dir")

    # 3) runs 루트 밖 탈출 방지
    if not str(base).startswith(str(runs_root)):
        raise HTTPException(400, "invalid run_dir")

    # 4) 파일 경로 조립 및 탈출 방지
    file_path = (base / path).resolve()
    if not str(file_path).startswith(str(base)):
        raise HTTPException(400, "invalid path")
    if not (file_path.exists() and file_path.is_file()):
        raise HTTPException(404, "file not found")

    # 5) MIME / 다운로드 정책
    mime, _ = guess_type(str(file_path))
    media_type = mime or "application/octet-stream"
    inline_exts = {".html", ".htm", ".txt", ".log", ".csv", ".json"}
    disp = "inline" if file_path.suffix.lower() in inline_exts else "attachment"

    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type=media_type,
        headers={"Content-Disposition": f'{disp}; filename="{file_path.name}"'},
    )


# ──────────────────────────────────────────────────────────────
# Scout Suite HTML이 참조하는 정적 리소스 서빙
#  - /inc-bootstrap/... /inc-scoutsuite/... /inc-fontawesome/... 등
#  - /scoutsuite-results/scoutsuite_results_*.js 등
# 최신 Scout 실행의 output_dir 기준으로 파일을 찾아 반환
# ──────────────────────────────────────────────────────────────
@router.get("/inc-{family}/{path:path}", summary="Scout Suite 정적 리소스")
def get_scout_inc_static(family: str, path: str):
    """
    Scout Suite HTML 리포트가 로딩하는 정적 자산(inc-bootstrap, inc-scoutsuite 등)을
    '가장 최근 Scout 실행 결과'의 output_dir 기준으로 서빙한다.
    예) /oss/api/oss/inc-bootstrap/css/bootstrap.min.css
    """
    meta = svc_find_latest_result_for_code("scout")
    if not meta:
        raise HTTPException(status_code=404, detail="No scout run found")

    out_dir = meta.get("output_dir")
    if not out_dir:
        raise HTTPException(status_code=404, detail="No output_dir in metadata")

    base = os.path.abspath(out_dir)
    rel_path = os.path.join(f"inc-{family}", path)
    abs_path = os.path.abspath(os.path.join(base, rel_path))

    # 디렉터리 탈출 방지 & 존재 여부 확인
    if not abs_path.startswith(base + os.sep) or not os.path.isfile(abs_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(abs_path)


@router.get("/scoutsuite-results/{filename}", summary="Scout Suite 결과 JS")
def get_scout_results_static(filename: str):
    """
    Scout Suite 결과 JS 파일(scoutsuite_results_*.js, scoutsuite_exceptions_*.js)을
    최신 Scout 실행 결과의 output_dir 기준으로 서빙한다.
    예) /oss/api/oss/scoutsuite-results/scoutsuite_results_aws-xxxx.js
    """
    meta = svc_find_latest_result_for_code("scout")
    if not meta:
        raise HTTPException(status_code=404, detail="No scout run found")

    out_dir = meta.get("output_dir")
    if not out_dir:
        raise HTTPException(status_code=404, detail="No output_dir in metadata")

    base = os.path.abspath(out_dir)
    rel_path = os.path.join("scoutsuite-results", filename)
    abs_path = os.path.abspath(os.path.join(base, rel_path))

    if not abs_path.startswith(base + os.sep) or not os.path.isfile(abs_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(abs_path)


# -------------------------------------------------------------------
# 최근 실행 / 실행 API
# -------------------------------------------------------------------
@router.get("/{code}/runs/latest", summary="가장 최근 실행 결과(단건)를 반환")
def get_latest_run(code: str, request: Request) -> Dict[str, Any]:
    """
    요구사항:
    1) result.json에서 최근 실행을 우선 확인하여 저장된 위치(run_dir/output_dir)와 메타를 가져온다.
    2) 해당 실행에서 사용된 파일/로그 등 '실행했던 내용들'을 함께 수집해 반환한다.
    - 반환 직전 files[].download_url 을 주입
    """
    # 1) result.json 기반으로 최신 실행 탐색
    latest = svc_find_latest_result_for_code(code)
    if latest:
        # 실행했던 내용(로그/정책 등) 수집
        executed = svc_collect_executed_contents(
            latest.get("run_dir"),
            latest.get("output_dir"),
            latest.get("code"),
        )
        latest["executed"] = executed or {}
        return _augment_with_download_urls(latest, request)

    # 2) 폴백: 파일시스템만으로 최근 실행 요약
    run_dirs = _iter_run_dirs()
    if not run_dirs:
        raise HTTPException(404, "No runs found")
    for run_dir in run_dirs:
        summary = _build_summary_from_fs(run_dir, code_hint=None)
        if summary.get("code") == code:
            executed = svc_collect_executed_contents(
                summary.get("run_dir"),
                summary.get("output_dir"),
                summary.get("code"),
            )
            summary["executed"] = executed or {}
            return _augment_with_download_urls(summary, request)

    # 3) 그래도 없으면 404
    raise HTTPException(404, f"No recent runs for code={code}")


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


@router.post("/{code}/use", summary="오픈소스 '사용하기' 시뮬레이션 (명령만 생성)")
def simulate_use(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = svc_simulate_use(code, payload or {})
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return data


# -------------------------------------------------------------------
# [동적 경로] 상세 정보 (맨 아래에 선언해 충돌 방지)
# -------------------------------------------------------------------
@router.get("/{code}", summary="오픈소스 상세 정보(정적)")
def get_detail(code: str) -> Dict[str, Any]:
    data = svc_get_detail(code)
    if "error" in data:
        raise HTTPException(status_code=data.get("error", 400), detail=data.get("message", "Unknown error"))
    return data

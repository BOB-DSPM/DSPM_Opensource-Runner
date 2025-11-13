# ============================================
# file: app/services/evidence_report_service.py
# (새 파일)
# ============================================
from __future__ import annotations

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

from .oss_service import find_latest_result_for_code
from ..utils.loader import get_item_by_code

EVIDENCE_ROOT = "./runs/evidence_pdf"


def _safe_evidence_dir(base_dir: str = EVIDENCE_ROOT) -> str:
    """PDF 보고서를 저장할 디렉터리 생성 (예: runs/evidence_pdf/20251113_153012)."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(base_dir, ts))
    os.makedirs(path, exist_ok=True)
    return path


def _wrap_text(text: str, max_chars: int) -> List[str]:
    """
    아주 단순한 단어 기준 줄바꿈 유틸.
    - ReportLab에서 긴 문자열을 섹션별로 줄바꿈하기 위함.
    """
    lines: List[str] = []
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line:
            lines.append("")
            continue
        current = ""
        for word in line.split(" "):
            if not current:
                current = word
            elif len(current) + 1 + len(word) <= max_chars:
                current += " " + word
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines


def _draw_section_title(c: canvas.Canvas, text: str, x: float, y: float):
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, text)
    c.setFont("Helvetica", 10)


def _draw_kv(c: canvas.Canvas, x: float, y: float, key: str, value: str) -> float:
    """
    key: value 형태 한 줄 출력. 여러 줄로 감싸질 수 있음.
    반환값: 다음 줄 y 좌표.
    """
    max_chars = 90
    lines = _wrap_text(value, max_chars)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(x, y, f"{key}:")
    c.setFont("Helvetica", 9)
    offset_x = x + 40  # value 들여쓰기

    first = True
    for line in lines:
        if first:
            c.drawString(offset_x, y, line)
            first = False
        else:
            y -= 11
            c.drawString(offset_x, y, line)
    return y - 14  # 다음 항목 y


def _ensure_page_space(c: canvas.Canvas, y: float, min_y: float = 40 * mm) -> float:
    """y가 너무 아래로 내려갔으면 새 페이지 시작."""
    if y < min_y:
        c.showPage()
        return A4[1] - 30 * mm
    return y


def _summarize_files(files: List[Dict[str, Any]], max_files: int = 8) -> List[Dict[str, Any]]:
    """
    파일이 너무 많기 때문에 상위 N개만 요약에 넣음.
    (size 기준 정렬 or mtime 기준 정렬 등 옵션 가능, 여기서는 mtime desc)
    """
    if not files:
        return []
    sorted_files = sorted(files, key=lambda f: f.get("mtime", 0), reverse=True)
    return sorted_files[:max_files]


def generate_evidence_pdf(
    codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    주어진 tool code들(Prowler/Custodian/Steampipe/Scout)의
    '가장 최근 실행 결과'를 기반으로 PDF 증적 보고서 생성.

    반환:
    {
      "pdf_path": 절대경로,
      "run_dir_rel": "runs/evidence_pdf/20251113_153012",
      "file_rel": "evidence_report.pdf"
    }
    """
    if not codes:
        codes = ["prowler", "custodian", "steampipe", "scout"]

    out_dir = _safe_evidence_dir(EVIDENCE_ROOT)
    pdf_filename = "evidence_report.pdf"
    pdf_path = os.path.join(out_dir, pdf_filename)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    # 1. 표지/헤더
    margin_x = 20 * mm
    y = height - 30 * mm

    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin_x, y, "SAGE OSS Evidence Report")
    y -= 15 * mm

    c.setFont("Helvetica", 11)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(margin_x, y, f"Generated at: {now_str}")
    y -= 8 * mm
    c.drawString(margin_x, y, "Scope: Latest runs of Prowler / Cloud Custodian / Steampipe / Scout Suite")
    y -= 15 * mm

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(
        margin_x,
        y,
        "※ 이 보고서는 SAGE Dashboard의 오픈소스 보안/컴플라이언스 툴 실행 결과를 요약한 증적 문서입니다.",
    )
    y -= 10 * mm

    c.showPage()
    y = height - 30 * mm

    # 2. 각 Tool 섹션
    for code in codes:
        meta = find_latest_result_for_code(code)
        item = get_item_by_code(code) or {}

        tool_name = item.get("name", code)
        tool_desc = item.get("desc", "")
        tool_category = item.get("category", "")
        tool_homepage = item.get("homepage", "")

        if not meta:
            # 실행 이력 없음
            y = _ensure_page_space(c, y)
            _draw_section_title(c, f"[{tool_name}] (no recent run)", margin_x, y)
            y -= 12 * mm
            y = _draw_kv(c, margin_x, y, "Status", "최근 실행 결과가 존재하지 않습니다.")
            y -= 5 * mm
            continue

        y = _ensure_page_space(c, y)
        _draw_section_title(c, f"[{tool_name}] {code}", margin_x, y)
        y -= 8 * mm

        # 기본 메타 정보
        y = _draw_kv(c, margin_x, y, "Category", tool_category or "-")
        y = _draw_kv(c, margin_x, y, "Homepage", tool_homepage or "-")
        if tool_desc:
            y = _draw_kv(c, margin_x, y, "Description", tool_desc)

        y = _ensure_page_space(c, y)

        # 실행 메타
        run_dir = meta.get("run_dir", "-")
        output_dir = meta.get("output_dir", "-")
        rc = meta.get("rc")
        duration_ms = meta.get("duration_ms")
        note = meta.get("note") or ""
        files = meta.get("files") or []

        rc_str = "-" if rc is None else str(rc)
        dur_str = "-" if duration_ms is None else f"{duration_ms} ms"

        y = _draw_kv(c, margin_x, y, "Run dir", str(run_dir))
        y = _draw_kv(c, margin_x, y, "Output dir", str(output_dir))
        y = _draw_kv(c, margin_x, y, "Exit code", rc_str)
        y = _draw_kv(c, margin_x, y, "Duration", dur_str)
        if note:
            y = _draw_kv(c, margin_x, y, "Note", note)

        # 파일 요약 (상위 N개)
        y = _ensure_page_space(c, y)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(margin_x, y, "Generated Artifacts (Top N)")
        y -= 6 * mm
        c.setFont("Helvetica", 8)

        top_files = _summarize_files(files, max_files=8)
        if not top_files:
            c.drawString(margin_x, y, "- No files recorded in latest run.")
            y -= 10 * mm
        else:
            for f in top_files:
                y = _ensure_page_space(c, y)
                path = str(f.get("path"))
                size = f.get("size")
                mtime = f.get("mtime")
                size_kb = "-" if size is None else f"{round(size/1024, 1)} KB"
                mtime_str = "-" if not mtime else datetime.fromtimestamp(mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                # path + size/mtime 1~2줄
                lines = _wrap_text(path, 90)
                c.drawString(margin_x + 5 * mm, y, f"- {lines[0]}")
                y -= 4 * mm
                for extra in lines[1:]:
                    c.drawString(margin_x + 9 * mm, y, extra)
                    y -= 4 * mm
                c.drawString(
                    margin_x + 9 * mm,
                    y,
                    f"(size={size_kb}, mtime={mtime_str})",
                )
                y -= 8 * mm

        # 섹션 간 여백
        y -= 10 * mm
        y = _ensure_page_space(c, y)

    # 마지막 페이지 저장
    c.save()

    run_dir_rel = os.path.relpath(out_dir, os.getcwd())
    file_rel = os.path.relpath(pdf_path, out_dir)  # "evidence_report.pdf"

    # 추후 원하면 manifest 같은 것도 out_dir에 떨어뜨릴 수 있음
    meta_path = os.path.join(out_dir, "meta.json")
    meta_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "pdf_file": file_rel,
        "codes": codes,
    }
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return {
        "pdf_path": pdf_path,
        "run_dir_rel": run_dir_rel,
        "file_rel": file_rel,
    }


# ============================================
# file: app/routers/evidence_report.py
# (새 파일)
# ============================================
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import FileResponse

from ..services import evidence_report_service as svc

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.get(
    "/report.pdf",
    summary="OSS 최신 실행 결과를 하나의 PDF 증적 보고서로 생성/다운로드",
    response_class=FileResponse,
)
def download_evidence_report(
    codes: Optional[str] = Query(
        None,
        description="쉼표로 구분된 도구 code 목록 (예: 'prowler,custodian,steampipe,scout'). 생략 시 기본 4종.",
    )
):
    """
    - 각 코드별 latest run 메타/파일 정보를 모아
      runs/evidence_pdf/<timestamp>/evidence_report.pdf 생성
    - 생성된 PDF를 바로 FileResponse로 내려준다.
    """
    if codes:
        code_list = [c.strip() for c in codes.split(",") if c.strip()]
    else:
        code_list = None

    try:
        result = svc.generate_evidence_pdf(code_list)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF 생성 실패: {e}")

    pdf_path = result.get("pdf_path")
    if not pdf_path or not os.path.isfile(pdf_path):
        raise HTTPException(status_code=500, detail="PDF 파일이 생성되지 않았습니다.")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename="SAGE_Evidence_Report.pdf",
    )


# ============================================
# file: app/main.py
# (기존 파일에 evidence_report 라우터 추가)
# ============================================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, oss, evidence_report  # ← evidence_report 추가

app = FastAPI(title="SAGE OSS API", version="0.1.0")

ALLOWED_ORIGINS = [
    "http://211.44.183.248",
    "http://211.44.183.248:80",
    "http://211.44.183.248:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(oss.router, prefix="/oss", tags=["oss"])
# 새 evidence PDF 라우터 (prefix /oss 재사용)
app.include_router(evidence_report.router, prefix="/oss", tags=["evidence"])

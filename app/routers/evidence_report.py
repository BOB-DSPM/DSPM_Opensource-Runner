# ============================================
# file: app/routers/evidence_report.py
# (새 파일)
# ============================================
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import FileResponse

from ..services import evidence_report_service as svc
import os

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
# ============================================
# file: app/services/evidence_report_service.py
# (KISA 스타일 섹션 + 스크린샷 증적 포함 버전)
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
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import ImageReader  # 스크린샷 증적 삽입용

from .oss_service import find_latest_result_for_code
from ..utils.loader import get_item_by_code

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
EVIDENCE_ROOT = "./runs/evidence_pdf"

# 폰트 경로 (app/services 기준 ../fonts/GowunDodum-Regular.ttf)
BASE_DIR = Path(__file__).resolve().parent
FONT_PATH = BASE_DIR.parent / "fonts" / "GowunDodum-Regular.ttf"

# 한글 폰트 등록
KOREAN_FONT_NAME = "GowunDodum"

try:
    pdfmetrics.registerFont(TTFont(KOREAN_FONT_NAME, str(FONT_PATH)))
except Exception as e:
    # 실패해도 기본 폰트로라도 생성되도록만 함
    print(f"[WARN] Failed to register Korean font '{KOREAN_FONT_NAME}': {e}")


# ──────────────────────────────────────────────
# 유틸 함수
# ──────────────────────────────────────────────
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
    # 제목은 약간 크게
    c.setFont(KOREAN_FONT_NAME, 14)
    c.drawString(x, y, text)
    c.setFont(KOREAN_FONT_NAME, 10)


def _draw_kv(c: canvas.Canvas, x: float, y: float, key: str, value: str) -> float:
    """
    key: value 형태 한 줄 출력. 여러 줄로 감싸질 수 있음.
    반환값: 다음 줄 y 좌표.
    """
    max_chars = 90
    lines = _wrap_text(str(value or ""), max_chars)

    # key
    c.setFont(KOREAN_FONT_NAME, 9)
    c.drawString(x, y, f"{key}:")
    # value
    offset_x = x + 40  # value 들여쓰기
    c.setFont(KOREAN_FONT_NAME, 9)

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
    (mtime desc 기준)
    """
    if not files:
        return []
    sorted_files = sorted(files, key=lambda f: f.get("mtime", 0), reverse=True)
    return sorted_files[:max_files]


def _load_metas_for_codes(codes: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
    metas: Dict[str, Optional[Dict[str, Any]]] = {}
    for code in codes:
        try:
            meta = find_latest_result_for_code(code)
        except Exception:
            meta = None
        metas[code] = meta
    return metas


# ──────────────────────────────────────────────
# 1장. 표지
# ──────────────────────────────────────────────
def _draw_cover_page(
    c: canvas.Canvas,
    codes: List[str],
    metas: Dict[str, Optional[Dict[str, Any]]],
):
    width, height = A4
    margin_x = 25 * mm
    y = height - 60 * mm

    c.setFont(KOREAN_FONT_NAME, 24)
    c.drawString(margin_x, y, "SAGE 클라우드 보안 / 컴플라이언스")
    y -= 16 * mm
    c.drawString(margin_x, y, "취약점 분석·평가 증적 보고서")
    y -= 25 * mm

    c.setFont(KOREAN_FONT_NAME, 12)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(margin_x, y, f"작성일시: {now_str}")
    y -= 10 * mm

    aws_profile = os.environ.get("AWS_PROFILE", "default")
    c.drawString(margin_x, y, f"AWS Profile: {aws_profile}")
    y -= 10 * mm

    # 사용 도구
    tool_names: List[str] = []
    for code in codes:
        item = get_item_by_code(code) or {}
        tool_names.append(item.get("name", code))
    c.drawString(margin_x, y, "사용 도구: " + ", ".join(tool_names))
    y -= 10 * mm

    c.setFont(KOREAN_FONT_NAME, 10)
    c.drawString(
        margin_x,
        y,
        "※ 본 문서는 SAGE Dashboard에서 실행된 오픈소스 보안/컴플라이언스 도구의 최신 결과를 기반으로 생성되었습니다.",
    )

    c.showPage()


# ──────────────────────────────────────────────
# 2장. 개요
# ──────────────────────────────────────────────
def _draw_overview_page(
    c: canvas.Canvas,
    codes: List[str],
    metas: Dict[str, Optional[Dict[str, Any]]],
):
    width, height = A4
    margin_x = 20 * mm
    y = height - 30 * mm

    _draw_section_title(c, "1. 개요", margin_x, y)
    y -= 10 * mm

    aws_profile = os.environ.get("AWS_PROFILE", "default")
    regions: List[str] = []
    for meta in metas.values():
        if not meta:
            continue
        payload = meta.get("payload") or {}
        region = payload.get("region")
        if region and region not in regions:
            regions.append(region)

    region_str = ", ".join(regions) if regions else "(실행 옵션에 region 미지정)"

    y = _draw_kv(c, margin_x, y, "대상 계정(AWS Profile)", aws_profile)
    y = _draw_kv(c, margin_x, y, "대상 리전", region_str)
    y = _draw_kv(
        c,
        margin_x,
        y,
        "사용 도구",
        ", ".join([get_item_by_code(code).get("name", code) if get_item_by_code(code) else code for code in codes]),
    )

    # 각 도구별 최신 실행 시간/상태 요약
    for code in codes:
        meta = metas.get(code)
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)

        y = _ensure_page_space(c, y)
        _draw_section_title(c, f"- {tool_name} 최신 실행 요약", margin_x, y)
        y -= 8 * mm

        if not meta:
            y = _draw_kv(c, margin_x, y, "상태", "최근 실행 결과가 존재하지 않습니다.")
            y -= 4 * mm
            continue

        rc = meta.get("rc")
        rc_str = "-" if rc is None else str(rc)
        out_dir = meta.get("output_dir", "-")
        run_dir = meta.get("run_dir", "-")
        stdout = (meta.get("stdout") or "")[:200]
        duration_ms = meta.get("duration_ms")
        dur_str = "-" if duration_ms is None else f"{duration_ms} ms"

        y = _draw_kv(c, margin_x, y, "Run dir", str(run_dir))
        y = _draw_kv(c, margin_x, y, "Output dir", str(out_dir))
        y = _draw_kv(c, margin_x, y, "Exit code", rc_str)
        y = _draw_kv(c, margin_x, y, "Duration", dur_str)
        if stdout:
            y = _draw_kv(c, margin_x, y, "Console excerpt", stdout.replace("\n", " "))

        y -= 4 * mm

    c.showPage()


# ──────────────────────────────────────────────
# 3장. 클라우드 취약점 분석·평가 요약 (표 형식)
# ──────────────────────────────────────────────
def _build_cloud_summary_rows(
    codes: List[str],
    metas: Dict[str, Optional[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """
    KISA 스타일 '분류/코드/점검 항목/도구/결과 요약' 표용 Row 생성.
    - 여기서는 도구 단위로 간단 요약 (추후 KISA 코드 매핑을 추가해도 됨)
    """
    rows: List[Dict[str, Any]] = []
    for idx, code in enumerate(codes, start=1):
        meta = metas.get(code)
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        category = item.get("category", "cloud-security")

        if not meta:
            result = "최근 실행 결과 없음"
            artifact_cnt = 0
        else:
            files = meta.get("files") or []
            artifact_cnt = len(files)
            rc = meta.get("rc")
            if rc is None or rc == 0:
                result = f"성공 (rc={rc}), 산출물 {artifact_cnt}개"
            else:
                result = f"오류 (rc={rc}), 산출물 {artifact_cnt}개"

        rows.append(
            {
                "category": category,
                "code": f"OSS-{idx:02d}",
                "title": f"{tool_name} 기반 클라우드 구성/컴플라이언스 점검",
                "tools": tool_name,
                "result": result,
            }
        )
    return rows


def _draw_cloud_summary_table(
    c: canvas.Canvas,
    summary_rows: List[Dict[str, Any]],
):
    width, height = A4
    margin_x = 20 * mm
    y = height - 30 * mm

    _draw_section_title(c, "2. 클라우드 취약점 분석·평가 요약", margin_x, y)
    y -= 10 * mm

    c.setFont(KOREAN_FONT_NAME, 9)
    headers = ["분류", "코드", "점검 항목", "도구", "결과 요약"]
    col_x = [
        margin_x,
        margin_x + 25 * mm,
        margin_x + 45 * mm,
        margin_x + 120 * mm,
        margin_x + 140 * mm,
    ]

    # 헤더
    for i, h in enumerate(headers):
        c.drawString(col_x[i], y, h)
    y -= 6 * mm
    c.line(margin_x, y, width - margin_x, y)
    y -= 4 * mm

    for row in summary_rows:
        y = _ensure_page_space(c, y)
        c.setFont(KOREAN_FONT_NAME, 8)

        c.drawString(col_x[0], y, str(row.get("category", ""))[:16])
        c.drawString(col_x[1], y, row.get("code", ""))
        # 점검 항목 / 도구 / 결과는 줄바꿈 처리
        title_lines = _wrap_text(row.get("title", ""), 40)
        tool_lines = _wrap_text(row.get("tools", ""), 18)
        result_lines = _wrap_text(row.get("result", ""), 40)
        max_lines = max(len(title_lines), len(tool_lines), len(result_lines))

        for i in range(max_lines):
            if i > 0:
                y -= 4 * mm
                y = _ensure_page_space(c, y)
            if i < len(title_lines):
                c.drawString(col_x[2], y, title_lines[i])
            if i < len(tool_lines):
                c.drawString(col_x[3], y, tool_lines[i])
            if i < len(result_lines):
                c.drawString(col_x[4], y, result_lines[i])

        y -= 6 * mm

    c.showPage()


# ──────────────────────────────────────────────
# 4장. 세부 취약점 항목 (KISA 스타일 템플릿)
# ──────────────────────────────────────────────
def _draw_vuln_detail_section(
    c: canvas.Canvas,
    ca_code: str,
    title: str,
    overview: str,
    check_content: str,
    purpose: str,
    threat: str,
    criteria_good: str,
    criteria_bad: str,
    tools: str,
    steps: List[str],
):
    width, height = A4
    margin_x = 20 * mm
    y = height - 30 * mm

    _draw_section_title(c, f"3. 세부 취약점 항목 - {ca_code} {title}", margin_x, y)
    y -= 8 * mm

    y = _draw_kv(c, margin_x, y, "취약점 개요", overview)
    y = _draw_kv(c, margin_x, y, "점검내용", check_content)
    y = _draw_kv(c, margin_x, y, "점검목적", purpose)
    y = _draw_kv(c, margin_x, y, "보안위협", threat)
    y = _draw_kv(c, margin_x, y, "점검대상 도구", tools)
    y = _draw_kv(c, margin_x, y, "판단기준(양호)", criteria_good)
    y = _draw_kv(c, margin_x, y, "판단기준(취약)", criteria_bad)

    c.setFont(KOREAN_FONT_NAME, 10)
    c.drawString(margin_x, y, "점검 및 조치 사례")
    y -= 6 * mm
    c.setFont(KOREAN_FONT_NAME, 9)

    for idx, step in enumerate(steps, start=1):
        y = _ensure_page_space(c, y)
        y = _draw_kv(c, margin_x, y, f"Step {idx}", step)

    c.showPage()


def _draw_vuln_detail_pages(
    c: canvas.Canvas,
    codes: List[str],
):
    """
    완전 자동 데이터 연동은 아니고,
    KISA 기술적 취약점 상세 가이드 스타일의 정적 템플릿을 2~3개 넣어줌.
    (실제 결과는 OSS 산출물과 연동되어 별도 검토 가능)
    """
    tool_names = ", ".join(
        [get_item_by_code(code).get("name", code) if get_item_by_code(code) else code for code in codes]
    )

    # 1) 루트/관리자 계정 관리 취약점 예시
    _draw_vuln_detail_section(
        c,
        ca_code="CA-03",
        title="클라우드 계정 루트·관리자 권한 관리",
        overview=(
            "클라우드 계정의 루트 또는 관리자 권한이 최소 권한 원칙에 맞게 관리되지 않거나, "
            "불필요하게 활성화되어 있는 경우를 점검한다."
        ),
        check_content=(
            "Prowler, Scout Suite 등의 도구를 활용해 루트 계정 사용 여부, MFA 적용 여부, "
            "관리자 권한을 가진 IAM 사용자/역할의 현황을 점검한다."
        ),
        purpose=(
            "과도한 권한을 가진 계정을 식별하고, 권한 축소·MFA 적용·비사용 계정 비활성화 등을 통해 "
            "계정 탈취 시 피해를 최소화한다."
        ),
        threat=(
            "루트/관리자 계정이 탈취되면 전체 클라우드 리소스에 대한 제어권이 공격자에게 넘어가 "
            "대규모 정보 유출 및 서비스 중단으로 이어질 수 있다."
        ),
        criteria_good=(
            "루트 계정은 비상용으로만 사용되고, 일상적 운영에는 별도 최소 권한 계정이 사용된다. "
            "루트 및 관리자 계정에는 MFA가 적용되어 있으며, 사용 이력도 주기적으로 점검한다."
        ),
        criteria_bad=(
            "루트 계정이 일상적인 운영에 사용되거나, 관리자 권한 계정에 MFA가 미적용되어 있고, "
            "비사용 계정이 장기간 방치되어 있는 경우."
        ),
        tools=tool_names,
        steps=[
            "Prowler로 AWS 계정 전반에 대한 계정·IAM 관련 체크를 수행하고 High/Medium 이상 "
            "결과를 추출한다.",
            "Scout Suite HTML 리포트에서 계정 보안(Identity & Access Management) 관련 대시보드를 "
            "확인하여 위험 계정을 목록화한다.",
            "Cloud Custodian 정책으로 비사용·과도 권한 계정에 대한 자동 알림 또는 차단 정책을 적용한다.",
        ],
    )

    # 2) 로깅·모니터링 미흡 취약점 예시
    _draw_vuln_detail_section(
        c,
        ca_code="LG-01",
        title="클라우드 감사 로그(CloudTrail 등) 설정 미흡",
        overview=(
            "클라우드 환경에서 API 호출 이력, 콘솔 로그인 이력 등 감사 로그가 적절히 수집·보존되지 "
            "않는 경우를 점검한다."
        ),
        check_content=(
            "Prowler, Steampipe 모드(aws_compliance.benchmark.cis_v300 등)를 이용해 CloudTrail, "
            "Config, S3 서버 액세스 로그 등의 활성화 여부 및 보호 설정을 점검한다."
        ),
        purpose=(
            "보안 사고 발생 시 행위 추적 및 원인 분석이 가능하도록 감사 로그를 충분히 수집·보존하고, "
            "위·변조 방지 설정을 통해 로그 신뢰성을 확보하기 위함이다."
        ),
        threat=(
            "감사 로그가 없거나 불충분하면 침해 사고 발생 시 공격 경로와 영향 범위를 파악하기 어렵고, "
            "법적·규제 준수 측면에서도 증적 부족으로 제재를 받을 수 있다."
        ),
        criteria_good=(
            "CloudTrail, Config 등 핵심 감사 로그가 모든 리전에 대해 활성화되어 있고, "
            "로그는 별도의 보안 계정/S3 버킷 등에 장기 보존된다."
        ),
        criteria_bad=(
            "일부 리전/서비스에 대해서만 로그가 활성화되어 있거나, 로그 보존 기간이 짧고, "
            "버전 관리/불변 스토리지 등의 보호 설정이 되어 있지 않은 경우."
        ),
        tools=tool_names,
        steps=[
            "Steampipe의 AWS Compliance 모드를 실행해 로그·감사 관련 규칙(CloudTrail, Config, "
            "S3 log 등) 결과를 CSV/JSON으로 수집한다.",
            "Prowler의 로그/모니터링 관련 체크 결과 중 실패한 항목을 정리해 우선순위에 따라 개선 계획을 수립한다.",
            "Cloud Custodian 또는 Terraform 등을 활용해 로그 활성화 및 보존 정책을 코드화한다.",
        ],
    )


# ──────────────────────────────────────────────
# 5장. 도구별 실행 상세 (기존 섹션 확장)
# ──────────────────────────────────────────────
def _draw_tool_sections(
    c: canvas.Canvas,
    codes: List[str],
    metas: Dict[str, Optional[Dict[str, Any]]],
):
    width, height = A4
    margin_x = 20 * mm
    y = height - 30 * mm

    _draw_section_title(c, "4. 도구별 실행 상세", margin_x, y)
    y -= 12 * mm

    for code in codes:
        meta = metas.get(code)
        item = get_item_by_code(code) or {}

        tool_name = item.get("name", code)
        tool_desc = item.get("desc", "")
        tool_category = item.get("category", "")
        tool_homepage = item.get("homepage", "")

        y = _ensure_page_space(c, y)
        _draw_section_title(c, f"[{tool_name}] {code}", margin_x, y)
        y -= 8 * mm

        # ─ 기본 메타 정보 ─
        y = _draw_kv(c, margin_x, y, "Category", tool_category or "-")
        y = _draw_kv(c, margin_x, y, "Homepage", tool_homepage or "-")
        if tool_desc:
            y = _draw_kv(c, margin_x, y, "Description", tool_desc)

        if not meta:
            y = _draw_kv(c, margin_x, y, "Status", "최근 실행 결과가 존재하지 않습니다.")
            y -= 6 * mm
            continue

        y = _ensure_page_space(c, y)

        # ─ 실행 메타 ─
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

        # ─ 파일 요약 (상위 N개) ─
        y = _ensure_page_space(c, y)
        c.setFont(KOREAN_FONT_NAME, 10)
        c.drawString(margin_x, y, "Generated Artifacts (Top N)")
        y -= 6 * mm
        c.setFont(KOREAN_FONT_NAME, 8)

        top_files = _summarize_files(files, max_files=8)
        if not top_files:
            c.drawString(margin_x + 5 * mm, y, "- No files recorded in latest run.")
            y -= 10 * mm
        else:
            for f in top_files:
                y = _ensure_page_space(c, y)
                path = str(f.get("path"))
                size = f.get("size")
                mtime = f.get("mtime")
                size_kb = "-" if size is None else f"{round(size / 1024, 1)} KB"
                mtime_str = (
                    "-"
                    if not mtime
                    else datetime.fromtimestamp(mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                # path 줄바꿈
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

    c.showPage()


# ──────────────────────────────────────────────
# 6장. 증적 화면(스크린샷)
# ──────────────────────────────────────────────
def _collect_screenshot_files(meta: Optional[Dict[str, Any]], limit: int = 4) -> List[str]:
    """
    result.json 의 files 배열 중 이미지(screenshots/*, *.png/jpg/jpeg)를 찾아 상대경로 목록 반환.
    """
    if not meta:
        return []
    files = meta.get("files") or []
    imgs: List[str] = []
    for f in files:
        p = str(f.get("path", ""))
        lower = p.lower()
        if not lower.endswith((".png", ".jpg", ".jpeg")):
            continue
        # screenshots 디렉터리 우선, 아니면 그냥 이미지 전체 허용
        if "screenshots" in lower or True:
            imgs.append(p)
        if len(imgs) >= limit:
            break
    return imgs


def _draw_screenshot_page(
    c: canvas.Canvas,
    title: str,
    run_dir: str,
    img_rel_paths: List[str],
):
    """
    주어진 run_dir 기준 상대 이미지 경로 목록을 한 장(혹은 여러 장)에 배치.
    """
    if not img_rel_paths:
        return

    width, height = A4
    margin_x = 15 * mm
    base = os.path.abspath(run_dir)

    y = height - 30 * mm
    _draw_section_title(c, f"5. 증적 화면 - {title}", margin_x, y)
    y -= 12 * mm

    for rel in img_rel_paths:
        img_path = os.path.abspath(os.path.join(base, rel))
        if not os.path.isfile(img_path):
            continue

        # 이미지 하나당 여유 공간 확보
        y = _ensure_page_space(c, y, min_y=80 * mm)

        try:
            img = ImageReader(img_path)
        except Exception:
            continue

        img_w, img_h = img.getSize()
        max_w = width - 2 * margin_x
        max_h = 60 * mm
        scale = min(max_w / img_w, max_h / img_h)
        draw_w, draw_h = img_w * scale, img_h * scale

        c.drawImage(img, margin_x, y - draw_h, width=draw_w, height=draw_h)
        y -= draw_h + 4 * mm
        c.setFont(KOREAN_FONT_NAME, 8)
        c.drawString(margin_x, y, f"파일: {rel}")
        y -= 10 * mm

    c.showPage()


def _draw_all_screenshot_pages(
    c: canvas.Canvas,
    codes: List[str],
    metas: Dict[str, Optional[Dict[str, Any]]],
):
    """
    코드별로 스크린샷이 있으면 각 도구 당 1페이지씩 증적 화면 섹션을 만든다.
    """
    for code in codes:
        meta = metas.get(code)
        if not meta:
            continue
        imgs = _collect_screenshot_files(meta, limit=4)
        if not imgs:
            continue
        run_dir = meta.get("run_dir")
        if not run_dir:
            continue
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        _draw_screenshot_page(c, tool_name, run_dir, imgs)


# ──────────────────────────────────────────────
# 메인 함수
# ──────────────────────────────────────────────
def generate_evidence_pdf(
    codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    주어진 tool code들(Prowler/Custodian/Steampipe/Scout 등)의
    '가장 최근 실행 결과'를 기반으로 KISA 스타일 PDF 증적 보고서 생성.

    반환:
    {
      "pdf_path": 절대경로,
      "run_dir_rel": "runs/evidence_pdf/20251113_153012",
      "file_rel": "evidence_report.pdf"
    }
    """
    if not codes:
        # 기본 OSS 4종
        codes = ["prowler", "custodian", "steampipe", "scout"]

    metas = _load_metas_for_codes(codes)

    out_dir = _safe_evidence_dir(EVIDENCE_ROOT)
    pdf_filename = "evidence_report.pdf"
    pdf_path = os.path.join(out_dir, pdf_filename)

    c = canvas.Canvas(pdf_path, pagesize=A4)

    # 1. 표지
    _draw_cover_page(c, codes, metas)

    # 2. 개요
    _draw_overview_page(c, codes, metas)

    # 3. 클라우드 취약점 분석·평가 요약 (표)
    summary_rows = _build_cloud_summary_rows(codes, metas)
    _draw_cloud_summary_table(c, summary_rows)

    # 4. 세부 취약점 항목 (KISA 스타일 템플릿 2개 예시)
    _draw_vuln_detail_pages(c, codes)

    # 5. 도구별 실행 상세 (기존 섹션 확장)
    _draw_tool_sections(c, codes, metas)

    # 6. 증적 화면(스크린샷)
    _draw_all_screenshot_pages(c, codes, metas)

    # ─ 마지막 페이지 저장 ─
    c.save()

    run_dir_rel = os.path.relpath(out_dir, os.getcwd())
    file_rel = os.path.relpath(pdf_path, out_dir)  # "evidence_report.pdf"

    # 간단 메타 정보
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

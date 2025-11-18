# ============================================
# file: app/services/evidence_report_service.py
# (SAGE 보고서 전용 새 구조 버전)
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

from .oss_service import find_latest_result_for_code
from ..utils.loader import get_item_by_code

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
EVIDENCE_ROOT = "./runs/evidence_pdf"
DEFAULT_TOOL_CODES = ["prowler", "custodian", "steampipe", "scout"]

# 폰트 경로 (app/services 기준 ../fonts/GowunDodum-Regular.ttf)
BASE_DIR = Path(__file__).resolve().parent
FONT_PATH = BASE_DIR.parent / "fonts" / "GowunDodum-Regular.ttf"
KOREAN_FONT_NAME = "GowunDodum"

try:
    pdfmetrics.registerFont(TTFont(KOREAN_FONT_NAME, str(FONT_PATH)))
except Exception as e:
    # 실패해도 기본 폰트로라도 생성되도록만 함
    print(f"[WARN] Failed to register Korean font '{KOREAN_FONT_NAME}': {e}")

# 레이아웃 상수 (줄 간격 넉넉하게)
TOP_MARGIN_MM = 30
BOTTOM_MARGIN_MM = 25
TITLE_FONT = 22
SECTION_TITLE_FONT = 16
SUBTITLE_FONT = 13
BODY_FONT = 11
SMALL_FONT = 9


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
    for raw_line in (text or "").split("\n"):
        line = raw_line.rstrip()
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


def _new_page_y() -> float:
    return A4[1] - TOP_MARGIN_MM * mm


def _ensure_page_space(
    c: canvas.Canvas,
    y: float,
    lines: int,
    font_size: int = BODY_FONT,
) -> float:
    """
    필요한 줄 수 기준으로 여백이 부족하면 새 페이지로 넘김.
    """
    bottom = BOTTOM_MARGIN_MM * mm
    leading = font_size + 6  # 줄 간격 넉넉하게
    if y - lines * leading < bottom:
        c.showPage()
        return _new_page_y()
    return y


def _draw_paragraph(
    c: canvas.Canvas,
    text: str,
    x: float,
    y: float,
    max_chars: int = 80,
    font_size: int = BODY_FONT,
) -> float:
    """
    여러 줄 문단 출력.
    반환값: 마지막 줄 다음 y 좌표
    """
    lines = _wrap_text(text, max_chars)
    if not lines:
        return y

    y = _ensure_page_space(c, y, len(lines), font_size=font_size)
    c.setFont(KOREAN_FONT_NAME, font_size)
    leading = font_size + 6

    for line in lines:
        c.drawString(x, y, line)
        y -= leading
    return y


def _draw_heading(
    c: canvas.Canvas,
    text: str,
    x: float,
    y: float,
    level: int = 1,
) -> float:
    """
    level 1: 큰 섹션 제목
    level 2: subsecion 제목
    """
    if level == 1:
        font_size = SECTION_TITLE_FONT
    else:
        font_size = SUBTITLE_FONT

    y = _ensure_page_space(c, y, 2, font_size=font_size)
    c.setFont(KOREAN_FONT_NAME, font_size)
    c.drawString(x, y, text)
    y -= font_size + 8
    return y


def _extract_common_context(tool_meta: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    각 도구의 result.json payload를 참고해 공통 컨텍스트(AWS Profile, Region 등)를 유추.
    """
    profiles = set()
    regions = set()
    for meta in tool_meta.values():
        payload = meta.get("payload") or {}
        profile = payload.get("profile")
        region = payload.get("region")
        if profile:
            profiles.add(str(profile))
        if region:
            regions.add(str(region))

    profile_str = ", ".join(sorted(profiles)) if profiles else "default (추정, 명시 옵션 없음)"
    region_str = ", ".join(sorted(regions)) if regions else "(실행 옵션에 region 미지정)"

    return {"profile": profile_str, "region": region_str}


def _detect_frameworks_from_files(files: List[Dict[str, Any]]) -> List[str]:
    """
    파일 경로/이름을 보고 어떤 컴플라이언스 프레임워크 산출물이 있는지 간단 탐지.
    (Prowler CSV 파일 네이밍 활용)
    """
    if not files:
        return []

    mapping = [
        ("isms_p", "ISMS-P"),
        ("kisa_isms_p", "ISMS-P"),
        ("iso27001", "ISO/IEC 27001"),
        ("gdpr", "GDPR"),
        ("hipaa", "HIPAA"),
        ("cis_", "CIS Benchmark"),
        ("fedramp", "FedRAMP"),
        ("soc2", "SOC 2"),
        ("gxp", "GxP / Annex 11"),
    ]

    found = set()
    for f in files:
        path = str(f.get("path", "")).lower()
        for key, label in mapping:
            if key in path:
                found.add(label)
    return sorted(found)


# ──────────────────────────────────────────────
# 세부 취약점 항목 설명 템플릿
# ──────────────────────────────────────────────
DETAILED_ITEMS: List[Dict[str, Any]] = [
    {
        "code": "CA-03",
        "title": "클라우드 계정 루트·관리자 권한 관리",
        "area": "계정보안",
        "overview": (
            "클라우드 계정의 루트 또는 관리자 권한이 최소 권한 원칙에 맞게 관리되지 않거나, "
            "불필요하게 활성화되어 있는 경우를 점검한다."
        ),
        "check": (
            "Prowler, Scout Suite 등의 도구를 활용해 루트 계정 사용 여부, MFA 적용 여부, "
            "관리자 권한을 가진 IAM 사용자/역할의 현황을 점검하였다."
        ),
        "purpose": (
            "과도한 권한을 가진 계정을 식별하고, 권한 축소·MFA 적용·비사용 계정 비활성화 등을 통해 "
            "계정 탈취 시 피해를 최소화하기 위함이다."
        ),
        "risk": (
            "루트/관리자 계정이 탈취되면 전체 클라우드 리소스에 대한 제어권이 공격자에게 넘어가 "
            "대규모 정보 유출 및 서비스 중단으로 이어질 수 있다."
        ),
        "tools": "Prowler, Cloud Custodian, Steampipe (mods), Scout Suite",
        "good": (
            "루트 계정은 비상용으로만 사용되고, 일상적 운영에는 별도 최소 권한 계정이 사용된다. "
            "루트 및 관리자 계정에는 MFA가 적용되어 있으며, 비사용 계정은 주기적으로 점검·비활성화된다."
        ),
        "bad": (
            "루트 계정이 일상적인 운영에 사용되거나, 관리자 권한 계정에 MFA가 미적용되어 있고, "
            "비사용 계정이 장기간 방치되어 있는 경우."
        ),
        "steps": [
            "Prowler로 AWS 계정 전반에 대한 계정·IAM 관련 체크를 수행하고 High/Medium 이상 결과를 추출한다.",
            "Scout Suite HTML 리포트에서 계정 보안(Identity & Access Management) 관련 대시보드를 확인하여 위험 계정을 목록화한다.",
            "Cloud Custodian 정책으로 비사용·과도 권한 계정에 대한 자동 알림 또는 차단 정책을 적용한다.",
        ],
    },
    {
        "code": "LG-01",
        "title": "클라우드 감사 로그(CloudTrail 등) 설정 미흡",
        "area": "로그·감사",
        "overview": (
            "클라우드 환경에서 API 호출 이력, 콘솔 로그인 이력 등 감사 로그가 적절히 수집·보존되지 않는 경우를 점검한다."
        ),
        "check": (
            "Prowler, Steampipe 모드(aws_compliance.benchmark.cis_v300 등)를 이용해 CloudTrail, Config, "
            "S3 서버 액세스 로그 등의 활성화 여부 및 보호 설정을 점검하였다."
        ),
        "purpose": (
            "보안 사고 발생 시 행위 추적 및 원인 분석이 가능하도록 감사 로그를 충분히 수집·보존하고, "
            "위·변조 방지 설정을 통해 로그 신뢰성을 확보하기 위함이다."
        ),
        "risk": (
            "감사 로그가 없거나 불충분하면 침해 사고 발생 시 공격 경로와 영향 범위를 파악하기 어렵고, "
            "법적·규제 준수 측면에서도 증적 부족으로 이어질 수 있다."
        ),
        "tools": "Prowler, Cloud Custodian, Steampipe (mods), Scout Suite",
        "good": (
            "CloudTrail, Config 등 핵심 감사 로그가 모든 리전에 대해 활성화되어 있고, "
            "로그는 별도의 보안 계정/S3 버킷 등에 장기 보존되며, 버전 관리·불변 스토리지 설정이 적용되어 있다."
        ),
        "bad": (
            "일부 리전/서비스에 대해서만 로그가 활성화되어 있거나, 로그 보존 기간이 짧고, "
            "버전 관리/불변 스토리지 등의 보호 설정이 되어 있지 않은 경우."
        ),
        "steps": [
            "Steampipe의 AWS Compliance 모드를 실행해 로그·감사 관련 규칙 결과를 CSV/JSON으로 수집한다.",
            "Prowler의 로그/모니터링 관련 체크 결과 중 실패한 항목을 정리해 우선순위에 따라 개선 계획을 수립한다.",
            "Cloud Custodian 또는 Terraform 등을 활용해 로그 활성화 및 보존 정책을 코드화한다.",
        ],
    },
]


# ──────────────────────────────────────────────
# 메인 함수
# ──────────────────────────────────────────────
def generate_evidence_pdf(
    codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    SAGE 보고서 구조에 맞춰 PDF 증적 보고서를 생성한다.

    반환:
    {
      "pdf_path": 절대경로,
      "run_dir_rel": "runs/evidence_pdf/20251113_153012",
      "file_rel": "SAGE_report.pdf"
    }
    """
    if not codes:
        codes = list(DEFAULT_TOOL_CODES)

    # 1) 각 도구별 latest result 메타 로딩
    tool_meta: Dict[str, Dict[str, Any]] = {}
    for code in codes:
        meta = find_latest_result_for_code(code) or {}
        tool_meta[code] = meta

    # 산출물 카운트 및 프레임워크 감지
    artifact_counts: Dict[str, int] = {}
    frameworks_all = set()
    for code, meta in tool_meta.items():
        files = meta.get("files") or []
        artifact_counts[code] = len(files)
        for fw in _detect_frameworks_from_files(files):
            frameworks_all.add(fw)

    context = _extract_common_context(tool_meta)
    aws_profile = context["profile"]
    aws_region = context["region"]
    frameworks_str = ", ".join(sorted(frameworks_all)) if frameworks_all else "-"

    # 2) PDF 준비
    out_dir = _safe_evidence_dir(EVIDENCE_ROOT)
    pdf_filename = "evidence_report.pdf"
    pdf_path = os.path.join(out_dir, pdf_filename)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    margin_x = 25 * mm
    y = _new_page_y()

    # ─────────────────────────────────────
    # 0. 표지
    # ─────────────────────────────────────
    c.setFont(KOREAN_FONT_NAME, TITLE_FONT)
    c.drawString(margin_x, y, "SAGE 클라우드 보안·컴플라이언스")
    y -= TITLE_FONT + 10
    c.drawString(margin_x, y, "취약점 분석·평가 증적 보고서")
    y -= TITLE_FONT + 20

    c.setFont(KOREAN_FONT_NAME, SUBTITLE_FONT)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(margin_x, y, f"작성일시: {now_str}")
    y -= SUBTITLE_FONT + 8
    c.drawString(margin_x, y, f"AWS Profile: {aws_profile}")
    y -= SUBTITLE_FONT + 8
    c.drawString(margin_x, y, f"대상 리전: {aws_region}")
    y -= SUBTITLE_FONT + 8

    tools_label = ", ".join(
        get_item_by_code(code).get("name", code)
        if get_item_by_code(code)
        else code
        for code in codes
    )
    c.drawString(margin_x, y, f"사용 도구: {tools_label}")
    y -= SUBTITLE_FONT + 14

    c.setFont(KOREAN_FONT_NAME, SMALL_FONT)
    c.drawString(
        margin_x,
        y,
        "※ 본 문서는 SAGE Dashboard에서 실행된 오픈소스 보안/컴플라이언스 도구의 최신 결과를 기반으로 생성되었습니다.",
    )

    c.showPage()
    y = _new_page_y()

    # ─────────────────────────────────────
    # 1. 종합 요약 (Executive Summary)
    # ─────────────────────────────────────
    y = _draw_heading(c, "1. 종합 요약 (Executive Summary)", margin_x, y, level=1)

    # 1-1 전체 점검 개요
    y = _draw_heading(c, "1-1. 전체 점검 개요", margin_x, y, level=2)
    total_artifacts = sum(artifact_counts.values())
    text = (
        f"이번 점검은 AWS Profile '{aws_profile}' 환경을 대상으로, "
        f"{tools_label} 4종 도구를 활용하여 클라우드 보안·컴플라이언스 구성을 분석·평가하였다. "
        f"각 도구의 최신 실행 결과 기준으로 총 {total_artifacts}개 이상의 산출물(리포트/로그/JSON 등)이 생성되었다."
    )
    y = _draw_paragraph(c, text, margin_x, y, max_chars=80, font_size=BODY_FONT)
    y -= 6

    # 1-2 규제·컴플라이언스 프레임워크 관점 요약
    y = _draw_heading(c, "1-2. 규제·컴플라이언스 관점 요약", margin_x, y, level=2)
    if frameworks_str != "-":
        text = (
            "도구 산출물 분석 결과, 다음 컴플라이언스 프레임워크 관점의 점검 결과가 생성되었다: "
            f"{frameworks_str}. "
            "각 프레임워크별 상세 위반 여부·항목은 개별 CSV/JSON 리포트에서 확인할 수 있다."
        )
    else:
        text = (
            "현재 수집된 산출물에서는 특정 규제·컴플라이언스 프레임워크명을 식별하지 못하였다. "
            "Prowler/Steampipe 등의 출력 포맷 및 파일명을 기반으로 후속 분석이 가능하다."
        )
    y = _draw_paragraph(c, text, margin_x, y, max_chars=80, font_size=BODY_FONT)
    y -= 6

    # 1-3 개선 우선순위 (템플릿)
    y = _draw_heading(c, "1-3. 개선 우선순위(템플릿)", margin_x, y, level=2)
    priority_lines = [
        "① CA-03 클라우드 계정 루트·관리자 권한 관리",
        "② LG-01 클라우드 감사 로그(CloudTrail 등) 설정 보강",
        "③ (선택) 스토리지·네트워크·암호화 등 추가 통제 항목",
    ]
    for line in priority_lines:
        y = _draw_paragraph(c, f"- {line}", margin_x, y, max_chars=80, font_size=BODY_FONT)
    y -= 4

    c.showPage()
    y = _new_page_y()

    # ─────────────────────────────────────
    # 2. 컴플라이언스 관점 요약
    # ─────────────────────────────────────
    y = _draw_heading(c, "2. 컴플라이언스 관점 요약", margin_x, y, level=1)

    for item in DETAILED_ITEMS:
        summary = (
            f"[{item['code']}] {item['area']} – {item['title']}\n"
            f"· 관련 규제: ISMS-P / ISO27001 / (환경에 따라 추가 매핑)\n"
            f"· 영향도: High (템플릿 기준)\n"
            f"· 근거 도구: {item['tools']}"
        )
        y = _draw_paragraph(c, summary, margin_x, y, max_chars=90, font_size=BODY_FONT)
        y -= 4

    c.showPage()
    y = _new_page_y()

    # ─────────────────────────────────────
    # 3. 세부 취약점 항목
    # ─────────────────────────────────────
    y = _draw_heading(c, "3. 세부 취약점 항목", margin_x, y, level=1)

    for item in DETAILED_ITEMS:
        title = f"3. 세부 취약점 항목 - {item['code']} {item['title']}"
        y = _draw_heading(c, title, margin_x, y, level=2)

        y = _draw_paragraph(c, f"취약점 개요: {item['overview']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"점검 내용: {item['check']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"점검 목적: {item['purpose']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"보안 위협: {item['risk']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"점검 대상 도구: {item['tools']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"판단 기준(양호): {item['good']}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"판단 기준(취약): {item['bad']}", margin_x, y, 90, BODY_FONT)

        y = _draw_paragraph(c, "점검 및 조치 사례:", margin_x, y, 90, BODY_FONT)
        for idx, step in enumerate(item["steps"], start=1):
            y = _draw_paragraph(c, f"Step {idx}: {step}", margin_x + 6 * mm, y, 88, BODY_FONT)

        y -= 8
        y = _ensure_page_space(c, y, 3, font_size=BODY_FONT)

    c.showPage()
    y = _new_page_y()

    # ─────────────────────────────────────
    # 4. 도구별 실행 상세
    # ─────────────────────────────────────
    y = _draw_heading(c, "4. 도구별 실행 상세", margin_x, y, level=1)

    for code in codes:
        meta = tool_meta.get(code) or {}
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        category = item.get("category", "-")
        homepage = item.get("homepage", "-")
        desc = item.get("desc", "")

        title = f"[{tool_name}] {code}"
        y = _draw_heading(c, title, margin_x, y, level=2)

        # 기본 정보
        y = _draw_paragraph(c, f"Category: {category}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Homepage: {homepage}", margin_x, y, 90, BODY_FONT)
        if desc:
            y = _draw_paragraph(c, f"Description: {desc}", margin_x, y, 90, BODY_FONT)

        run_dir = meta.get("run_dir", "-")
        output_dir = meta.get("output_dir", "-")
        rc = meta.get("rc")
        duration_ms = meta.get("duration_ms")
        note = meta.get("note") or ""
        files = meta.get("files") or []

        rc_str = "-" if rc is None else str(rc)
        dur_str = "-" if duration_ms is None else f"{duration_ms} ms"

        y = _draw_paragraph(c, f"Run dir: {run_dir}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Output dir: {output_dir}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Exit code: {rc_str}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Duration: {dur_str}", margin_x, y, 90, BODY_FONT)
        if note:
            y = _draw_paragraph(c, f"Note: {note}", margin_x, y, 90, BODY_FONT)

        # 산출물 요약
        y = _draw_paragraph(
            c,
            "Generated Artifacts (Top N):",
            margin_x,
            y,
            max_chars=90,
            font_size=BODY_FONT,
        )
        top_files = sorted(
            files, key=lambda f: f.get("mtime", 0), reverse=True
        )[:8]

        if not top_files:
            y = _draw_paragraph(
                c,
                "- No files recorded in latest run.",
                margin_x + 6 * mm,
                y,
                90,
                BODY_FONT,
            )
        else:
            for f in top_files:
                path = str(f.get("path", ""))
                size = f.get("size")
                mtime = f.get("mtime")
                size_kb = "-" if size is None else f"{round(size/1024, 1)} KB"
                mtime_str = (
                    "-"
                    if not mtime
                    else datetime.fromtimestamp(mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                y = _draw_paragraph(
                    c,
                    f"- {path}",
                    margin_x + 6 * mm,
                    y,
                    95,
                    BODY_FONT,
                )
                y = _draw_paragraph(
                    c,
                    f"  (size={size_kb}, mtime={mtime_str})",
                    margin_x + 8 * mm,
                    y,
                    95,
                    SMALL_FONT,
                )

        y -= 10
        y = _ensure_page_space(c, y, 4, font_size=BODY_FONT)

    c.showPage()
    y = _new_page_y()

    # ─────────────────────────────────────
    # 5. 부록: 산출물 개요
    # ─────────────────────────────────────
    y = _draw_heading(c, "5. 부록 – 도구별 산출물 개요", margin_x, y, level=1)

    for code in codes:
        meta = tool_meta.get(code) or {}
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        files = meta.get("files") or []
        out_dir = meta.get("output_dir", "-")

        summary = (
            f"[{tool_name}] {code}\n"
            f"· Output dir: {out_dir}\n"
            f"· 기록된 산출물 개수: {len(files)}개\n"
            "· 상세 내용은 SAGE Dashboard 또는 개별 리포트 파일(CSV/JSON/HTML/로그)에서 확인 가능"
        )
        y = _draw_paragraph(c, summary, margin_x, y, 90, BODY_FONT)
        y -= 4

    c.save()

    run_dir_rel = os.path.relpath(out_dir, os.getcwd())
    file_rel = os.path.relpath(pdf_path, out_dir)  # "evidence_report.pdf"

    # 간단 메타 정보
    meta_path = os.path.join(out_dir, "meta.json")
    meta_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "pdf_file": file_rel,
        "codes": codes,
        "aws_profile": aws_profile,
        "aws_region": aws_region,
        "frameworks": sorted(frameworks_all),
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

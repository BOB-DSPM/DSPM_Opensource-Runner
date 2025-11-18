# ============================================
# file: app/services/evidence_report_service.py
# (SAGE 보고서 전용 - Platypus 기반 가독성 강화 버전)
# ============================================
from __future__ import annotations

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

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

# 레이아웃 상수
TOP_MARGIN_MM = 30
BOTTOM_MARGIN_MM = 25
TITLE_FONT = 22
SECTION_TITLE_FONT = 16
SUBTITLE_FONT = 13
BODY_FONT = 11
SMALL_FONT = 9


# ──────────────────────────────────────────────
# 스타일 정의
# ──────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "TITLE",
        parent=base["Heading1"],
        fontName=KOREAN_FONT_NAME,
        fontSize=TITLE_FONT,
        leading=TITLE_FONT + 4,
        spaceAfter=8,
    )

    subtitle = ParagraphStyle(
        "SUBTITLE",
        parent=base["Heading2"],
        fontName=KOREAN_FONT_NAME,
        fontSize=TITLE_FONT,
        leading=TITLE_FONT + 4,
        textColor=colors.HexColor("#333333"),
        spaceAfter=16,
    )

    section = ParagraphStyle(
        "SECTION",
        parent=base["Heading2"],
        fontName=KOREAN_FONT_NAME,
        fontSize=SECTION_TITLE_FONT,
        leading=SECTION_TITLE_FONT + 4,
        textColor=colors.HexColor("#1f4287"),
        spaceBefore=8,
        spaceAfter=12,
    )

    subsection = ParagraphStyle(
        "SUBSECTION",
        parent=base["Heading3"],
        fontName=KOREAN_FONT_NAME,
        fontSize=SUBTITLE_FONT,
        leading=SUBTITLE_FONT + 4,
        textColor=colors.HexColor("#1f4287"),
        spaceBefore=6,
        spaceAfter=6,
    )

    body = ParagraphStyle(
        "BODY",
        parent=base["BodyText"],
        fontName=KOREAN_FONT_NAME,
        fontSize=BODY_FONT,
        leading=BODY_FONT + 6,  # 줄간 넉넉
        spaceAfter=2,
    )

    small = ParagraphStyle(
        "SMALL",
        parent=base["BodyText"],
        fontName=KOREAN_FONT_NAME,
        fontSize=SMALL_FONT,
        leading=SMALL_FONT + 4,
        textColor=colors.HexColor("#555555"),
        spaceAfter=1,
    )

    bullet = ParagraphStyle(
        "BULLET",
        parent=body,
        leftIndent=10 * mm,
        bulletIndent=5 * mm,
        bulletFontName=KOREAN_FONT_NAME,
        bulletFontSize=BODY_FONT,
    )

    return {
        "TITLE": title,
        "SUBTITLE": subtitle,
        "SECTION": section,
        "SUBSECTION": subsection,
        "BODY": body,
        "SMALL": small,
        "BULLET": bullet,
    }


# ──────────────────────────────────────────────
# 유틸 함수
# ──────────────────────────────────────────────
def _safe_evidence_dir(base_dir: str = EVIDENCE_ROOT) -> str:
    """PDF 보고서를 저장할 디렉터리 생성 (예: runs/evidence_pdf/20251113_153012)."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(base_dir, ts))
    os.makedirs(path, exist_ok=True)
    return path


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


def _extract_severity_stats(tool_meta: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    각 도구 payload에서 severity 통계를 읽어옴.
    payload.severity_stats 가 있다면 사용, 없으면 0으로 세팅.
    구조 예:
      payload: {
        "severity_stats": {
          "HIGH": 10,
          "MEDIUM": 20,
          "LOW": 5,
          "TOTAL": 35
        }
      }
    """
    result: Dict[str, Dict[str, int]] = {}
    for code, meta in tool_meta.items():
        payload = meta.get("payload") or {}
        stats = payload.get("severity_stats") or {}
        high = int(stats.get("HIGH", 0) or 0)
        medium = int(stats.get("MEDIUM", 0) or 0)
        low = int(stats.get("LOW", 0) or 0)
        total = int(stats.get("TOTAL", high + medium + low) or (high + medium + low))
        result[code] = {
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
            "TOTAL": total,
        }
    return result


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
    (Platypus 기반: 자동 줄바꿈 + 표 레이아웃 + 통계 테이블)

    반환:
    {
      "pdf_path": 절대경로,
      "run_dir_rel": "runs/evidence_pdf/20251113_153012",
      "file_rel": "evidence_report.pdf"
    }
    """
    if not codes:
        codes = list(DEFAULT_TOOL_CODES)

    styles = _build_styles()

    # 1) 각 도구별 latest result 메타 로딩
    tool_meta: Dict[str, Dict[str, Any]] = {}
    for code in codes:
        meta = find_latest_result_for_code(code) or {}
        tool_meta[code] = meta

    # 산출물 카운트 및 프레임워크 감지
    artifact_counts: Dict[str, int] = {}
    frameworks_all = set()
    all_files_for_fw: List[Dict[str, Any]] = []

    for code, meta in tool_meta.items():
        files = meta.get("files") or []
        artifact_counts[code] = len(files)
        all_files_for_fw.extend(files)

    for fw in _detect_frameworks_from_files(all_files_for_fw):
        frameworks_all.add(fw)

    context = _extract_common_context(tool_meta)
    aws_profile = context["profile"]
    aws_region = context["region"]

    frameworks_list = sorted(frameworks_all)
    frameworks_str = ", ".join(frameworks_list) if frameworks_list else "-"

    # severity 요약 (payload에 있으면 사용)
    severity_stats = _extract_severity_stats(tool_meta)

    # 도구 라벨
    tool_labels: Dict[str, str] = {}
    for code in codes:
        item = get_item_by_code(code) or {}
        tool_labels[code] = item.get("name", code)

    total_artifacts = sum(artifact_counts.values())
    tools_label_str = ", ".join(tool_labels[c] for c in codes)

    # 2) PDF 준비
    out_dir = _safe_evidence_dir(EVIDENCE_ROOT)
    pdf_filename = "evidence_report.pdf"
    pdf_path = os.path.join(out_dir, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=25 * mm,
        rightMargin=25 * mm,
        topMargin=TOP_MARGIN_MM * mm,
        bottomMargin=BOTTOM_MARGIN_MM * mm,
    )

    story: List[Any] = []

    # ─────────────────────────────────────
    # 0. 표지
    # ─────────────────────────────────────
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("SAGE 클라우드 보안·컴플라이언스", styles["TITLE"]))
    story.append(Paragraph("취약점 분석·평가 증적 보고서", styles["SUBTITLE"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph(f"작성일시: {now_str}", styles["BODY"]))
    story.append(Paragraph(f"AWS Profile: {aws_profile}", styles["BODY"]))
    story.append(Paragraph(f"대상 리전: {aws_region}", styles["BODY"]))
    story.append(Paragraph(f"사용 도구: {tools_label_str}", styles["BODY"]))
    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "※ 본 문서는 SAGE Dashboard에서 실행된 오픈소스 보안/컴플라이언스 도구의 최신 결과를 기반으로 생성되었습니다.",
            styles["SMALL"],
        )
    )

    story.append(PageBreak())

    # ─────────────────────────────────────
    # 1. 종합 요약 (Executive Summary)
    # ─────────────────────────────────────
    story.append(Paragraph("1. 종합 요약 (Executive Summary)", styles["SECTION"]))

    # 1-1 전체 점검 개요
    story.append(Paragraph("1-1. 전체 점검 개요", styles["SUBSECTION"]))
    story.append(
        Paragraph(
            (
                f"이번 점검은 AWS Profile '<b>{aws_profile}</b>' 환경을 대상으로, "
                f"<b>{tools_label_str}</b> {len(codes)}종 도구를 활용하여 클라우드 보안·컴플라이언스 구성을 분석·평가하였다. "
                f"각 도구의 최신 실행 결과 기준으로 총 <b>{total_artifacts}</b>개 이상의 산출물(리포트/로그/JSON 등)이 생성되었다."
            ),
            styles["BODY"],
        )
    )
    story.append(Spacer(1, 6))

    # 요약 표 (환경/기본정보)
    summary_table_data = [
        ["항목", "값"],
        ["AWS Profile", aws_profile],
        ["Region", aws_region],
        ["총 산출물 개수", str(total_artifacts)],
        ["사용 도구", tools_label_str],
    ]
    summary_table = Table(summary_table_data, colWidths=[40 * mm, 110 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0e7ff")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT_NAME),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # 1-2 규제·컴플라이언스 관점 요약
    story.append(Paragraph("1-2. 규제·컴플라이언스 관점 요약", styles["SUBSECTION"]))
    if frameworks_str != "-":
        story.append(
            Paragraph(
                (
                    "도구 산출물 분석 결과, 다음 컴플라이언스 프레임워크 관점의 점검 결과가 생성되었다: "
                    f"<b>{frameworks_str}</b>. "
                    "각 프레임워크별 상세 위반 여부·항목은 개별 CSV/JSON 리포트에서 확인할 수 있다."
                ),
                styles["BODY"],
            )
        )
    else:
        story.append(
            Paragraph(
                (
                    "현재 수집된 산출물에서는 특정 규제·컴플라이언스 프레임워크명을 식별하지 못하였다. "
                    "Prowler/Steampipe 등의 출력 포맷 및 파일명을 기반으로 후속 분석이 가능하다."
                ),
                styles["BODY"],
            )
        )
    story.append(Spacer(1, 8))

    # 1-3 위험도/심각도 요약 테이블
    story.append(Paragraph("1-3. 위험도(Severity) 요약", styles["SUBSECTION"]))

    sev_table_data = [["도구", "HIGH", "MEDIUM", "LOW", "TOTAL"]]
    for code in codes:
        label = tool_labels.get(code, code)
        sev = severity_stats.get(code, {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0})
        sev_table_data.append(
            [
                label,
                str(sev["HIGH"]),
                str(sev["MEDIUM"]),
                str(sev["LOW"]),
                str(sev["TOTAL"]),
            ]
        )

    sev_table = Table(sev_table_data, colWidths=[45 * mm, 22 * mm, 22 * mm, 22 * mm, 22 * mm])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fee2e2")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#fecaca")),
                ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT_NAME),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef2f2")]),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 12))

    # 1-4 개선 우선순위 (템플릿)
    story.append(Paragraph("1-4. 개선 우선순위(템플릿)", styles["SUBSECTION"]))
    priority_lines = [
        "CA-03: 클라우드 계정 루트·관리자 권한 관리 강화",
        "LG-01: CloudTrail·Config 등 감사 로그 활성화 및 장기 보존 설정",
        "기타: 스토리지·네트워크·암호화 등 추가 통제 항목 검토",
    ]
    for line in priority_lines:
        story.append(Paragraph(f"• {line}", styles["BODY"]))

    story.append(PageBreak())

    # ─────────────────────────────────────
    # 2. 컴플라이언스 관점 요약
    # ─────────────────────────────────────
    story.append(Paragraph("2. 컴플라이언스 관점 요약", styles["SECTION"]))

    for item in DETAILED_ITEMS:
        story.append(
            Paragraph(
                f"[{item['code']}] {item['area']} – {item['title']}",
                styles["SUBSECTION"],
            )
        )
        story.append(
            Paragraph(
                "· 관련 규제: ISMS-P / ISO27001 / (환경에 따라 추가 매핑)",
                styles["BODY"],
            )
        )
        story.append(Paragraph("· 영향도: High (템플릿 기준)", styles["BODY"]))
        story.append(
            Paragraph(f"· 근거 도구: {item['tools']}", styles["BODY"])
        )
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # ─────────────────────────────────────
    # 3. 세부 취약점 항목
    # ─────────────────────────────────────
    story.append(Paragraph("3. 세부 취약점 항목", styles["SECTION"]))

    for item in DETAILED_ITEMS:
        story.append(
            Paragraph(
                f"{item['code']} {item['title']}",
                styles["SUBSECTION"],
            )
        )
        story.append(Paragraph(f"<b>취약점 개요</b>: {item['overview']}", styles["BODY"]))
        story.append(Paragraph(f"<b>점검 내용</b>: {item['check']}", styles["BODY"]))
        story.append(Paragraph(f"<b>점검 목적</b>: {item['purpose']}", styles["BODY"]))
        story.append(Paragraph(f"<b>보안 위협</b>: {item['risk']}", styles["BODY"]))
        story.append(Paragraph(f"<b>점검 대상 도구</b>: {item['tools']}", styles["BODY"]))
        story.append(Paragraph(f"<b>판단 기준(양호)</b>: {item['good']}", styles["BODY"]))
        story.append(Paragraph(f"<b>판단 기준(취약)</b>: {item['bad']}", styles["BODY"]))
        story.append(Spacer(1, 4))

        story.append(Paragraph("<b>점검 및 조치 사례</b>", styles["BODY"]))
        for idx, step in enumerate(item["steps"], start=1):
            story.append(Paragraph(f"{idx}. {step}", styles["BODY"]))

        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ─────────────────────────────────────
    # 4. 도구별 실행 상세
    # ─────────────────────────────────────
    story.append(Paragraph("4. 도구별 실행 상세", styles["SECTION"]))

    for code in codes:
        meta = tool_meta.get(code) or {}
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        category = item.get("category", "-")
        homepage = item.get("homepage", "-")
        desc = item.get("desc", "")

        story.append(
            Paragraph(
                f"[{tool_name}] ({code})",
                styles["SUBSECTION"],
            )
        )

        info_table_data = [
            ["항목", "값"],
            ["Category", category],
            ["Homepage", homepage],
            ["Description", desc or "-"],
        ]
        info_table = Table(info_table_data, colWidths=[30 * mm, 120 * mm])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d4d4d8")),
                    ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT_NAME),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(info_table)
        story.append(Spacer(1, 4))

        run_dir = meta.get("run_dir", "-")
        output_dir = meta.get("output_dir", "-")
        rc = meta.get("rc")
        duration_ms = meta.get("duration_ms")
        note = meta.get("note") or ""
        files = meta.get("files") or []

        rc_str = "-" if rc is None else str(rc)
        dur_str = "-" if duration_ms is None else f"{duration_ms} ms"

        exec_table_data = [
            ["실행 항목", "값"],
            ["Run dir", run_dir],
            ["Output dir", output_dir],
            ["Exit code", rc_str],
            ["Duration", dur_str],
        ]
        if note:
            exec_table_data.append(["Note", note])

        exec_table = Table(exec_table_data, colWidths=[30 * mm, 120 * mm])
        exec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c7d2fe")),
                    ("FONTNAME", (0, 0), (-1, -1), KOREAN_FONT_NAME),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(exec_table)
        story.append(Spacer(1, 6))

        # 산출물 요약 (Top N)
        story.append(Paragraph("<b>Generated Artifacts (Top N)</b>", styles["BODY"]))
        top_files = sorted(files, key=lambda f: f.get("mtime", 0) or 0, reverse=True)[:8]

        if not top_files:
            story.append(Paragraph("- No files recorded in latest run.", styles["BODY"]))
        else:
            for f in top_files:
                path = str(f.get("path", ""))
                size = f.get("size")
                mtime = f.get("mtime")
                size_kb = "-" if size is None else f"{round(size / 1024, 1)} KB"
                mtime_str = (
                    "-"
                    if not mtime
                    else datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                )

                story.append(
                    Paragraph(f"• {path}", styles["BODY"])
                )
                story.append(
                    Paragraph(
                        f"&nbsp;&nbsp;(size={size_kb}, mtime={mtime_str})",
                        styles["SMALL"],
                    )
                )

        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ─────────────────────────────────────
    # 5. 부록: 산출물 개요
    # ─────────────────────────────────────
    story.append(Paragraph("5. 부록 – 도구별 산출물 개요", styles["SECTION"]))

    for code in codes:
        meta = tool_meta.get(code) or {}
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        files = meta.get("files") or []
        out_dir_tool = meta.get("output_dir", "-")

        story.append(
            Paragraph(
                f"[{tool_name}] ({code})",
                styles["SUBSECTION"],
            )
        )
        story.append(
            Paragraph(
                f"· Output dir: {out_dir_tool}<br/>"
                f"· 기록된 산출물 개수: <b>{len(files)}</b>개<br/>"
                "· 상세 내용은 SAGE Dashboard 또는 개별 리포트 파일(CSV/JSON/HTML/로그)에서 확인 가능",
                styles["BODY"],
            )
        )
        story.append(Spacer(1, 6))

    # 실제 PDF 생성
    doc.build(story)

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
        "frameworks": frameworks_list,
        "severity_stats": severity_stats,
        "artifact_counts": artifact_counts,
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

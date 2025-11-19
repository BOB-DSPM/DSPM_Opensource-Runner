# ============================================
# file: app/services/evidence_report_service.py
# (SAGE 보고서 전용 - 통계/목록 + Prowler/Scout/Steampipe 표 상위10)
# ============================================
from __future__ import annotations

import os
import json
import time
import csv
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
from reportlab.lib.utils import ImageReader


# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
EVIDENCE_ROOT = "./runs/evidence_pdf"
DEFAULT_TOOL_CODES = ["prowler", "custodian", "steampipe", "scout"]

# 폰트 경로 (app/services 기준 ../fonts/GowunDodum-Regular.ttf)
BASE_DIR = Path(__file__).resolve().parent
FONT_PATH = BASE_DIR.parent / "fonts" / "GowunDodum-Regular.ttf"
KOREAN_FONT_NAME = "GowunDodum"

WATERMARK_PATH = BASE_DIR.parent / "assets" / "MADEIT.png"
WATERMARK_COLOR_PATH = BASE_DIR.parent / "assets" / "MADEIT-color.png"
try:
    WATERMARK_IMAGE = ImageReader(str(WATERMARK_PATH))
except Exception as e:
    print(f"[WARN] Failed to load watermark image: {e}")
    WATERMARK_IMAGE = None
try:
    WATERMARK_COLOR_IMAGE = ImageReader(str(WATERMARK_COLOR_PATH))
except Exception as e:
    print(f"[WARN] Failed to load color watermark image: {e}")
    WATERMARK_COLOR_IMAGE = None

try:
    pdfmetrics.registerFont(TTFont(KOREAN_FONT_NAME, str(FONT_PATH)))
except Exception as e:
    # 실패해도 기본 폰트로라도 생성되도록만 함
    print(f"[WARN] Failed to register Korean font '{KOREAN_FONT_NAME}': {e}")

KOREAN_FONT_NAME = "GowunDodum"

# Bold 폰트 있으면 사용, 없으면 기본 폰트 재사용
BOLD_FONT_NAME = KOREAN_FONT_NAME
try:
    FONT_PATH_BOLD = BASE_DIR.parent / "fonts" / "GowunDodum-Bold.ttf"
    if FONT_PATH_BOLD.exists():
        pdfmetrics.registerFont(TTFont("GowunDodum-Bold", str(FONT_PATH_BOLD)))
        BOLD_FONT_NAME = "GowunDodum-Bold"
except Exception as e:
    print(f"[WARN] Failed to register bold font: {e}")


# 레이아웃 상수 (줄 간격 넉넉하게)
TOP_MARGIN_MM = 30
BOTTOM_MARGIN_MM = 25
TITLE_FONT = 30  # 표지 큰 제목 더 크게
SECTION_TITLE_FONT = 16
SUBTITLE_FONT = 13
BODY_FONT = 11
SMALL_FONT = 9
CARD_BODY_FONT = BODY_FONT + 3  # 박스(Card) 내부 글자 조금 키움
CARD_SMALL_FONT = SMALL_FONT + 2

# 제목 간 간격 보정
HEADING_LEVEL1_EXTRA = 10   # 섹션 제목 뒤 여유
HEADING_LEVEL2_EXTRA = 8  # 소제목 뒤 여유


# ──────────────────────────────────────────────
# 유틸 함수
# ──────────────────────────────────────────────
def _safe_evidence_dir(base_dir: str = EVIDENCE_ROOT) -> str:
    """PDF 보고서를 저장할 디렉터리 생성 (예: runs/evidence_pdf/20251113_153012)."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.abspath(os.path.join(base_dir, ts))
    os.makedirs(path, exist_ok=True)
    return path


def _wrap_text(
    text: str,
    max_width: float,
    font_name: str = KOREAN_FONT_NAME,
    font_size: int = BODY_FONT,
) -> List[str]:
    """
    문자열을 주어진 픽셀 폭(max_width) 안에서 자동 줄바꿈한다.
    - ReportLab의 stringWidth로 실제 폭을 계산해서 오른쪽 박스를 넘지 않게 함.
    """
    lines: List[str] = []

    for raw_line in (text or "").split("\n"):
        line = raw_line.rstrip()
        if not line:
            lines.append("")
            continue

        words = line.split(" ")
        current = ""

        for word in words:
            # 현재 줄에 word를 붙였을 때 폭 계산
            candidate = word if not current else current + " " + word
            width = pdfmetrics.stringWidth(candidate, font_name, font_size)

            if width <= max_width:
                # 아직 폭 안에 들어오면 현재 줄에 계속 붙임
                current = candidate
            else:
                # 이미 꽉 찼으면 이전 줄을 확정하고 새 줄 시작
                if current:
                    lines.append(current)
                current = word

                # 단일 word 자체가 너무 길어서 max_width를 초과하는 경우(긴 URL 등)
                # 글자 단위로 강제 분할
                while pdfmetrics.stringWidth(current, font_name, font_size) > max_width:
                    tmp = ""
                    for ch in current:
                        cand2 = tmp + ch
                        if pdfmetrics.stringWidth(cand2, font_name, font_size) <= max_width:
                            tmp = cand2
                        else:
                            break
                    if not tmp:   # 안전장치
                        break
                    lines.append(tmp)
                    current = current[len(tmp):].lstrip()

        if current:
            lines.append(current)

    return lines

def _draw_watermark(c: canvas.Canvas, alpha: Optional[float] = None, use_color: bool = False) -> None:
    """
    현재 페이지 가운데에 MADEIT 로고 워터마크를 옅게 깐다.
    """
    image = WATERMARK_COLOR_IMAGE if use_color else WATERMARK_IMAGE
    if image is None:
        return

    page_w, page_h = A4
    iw, ih = image.getSize()

    # 페이지의 70% 폭, 40% 높이 안에 들어가도록 스케일
    max_w = page_w * 0.7
    max_h = page_h * 0.4
    scale = min(max_w / iw, max_h / ih)

    w = iw * scale
    h = ih * scale
    x = (page_w - w) / 2.0
    y = (page_h - h) / 2.0

    c.saveState()
    try:
        # 지원되면 투명도 낮게 설정
        if hasattr(c, "setFillAlpha"):
            c.setFillAlpha(alpha if alpha is not None else 0.15)  # 기본 워터마크는 더 연하게

        c.drawImage(
            image,
            x,
            y,
            width=w,
            height=h,
            preserveAspectRatio=True,
            mask="auto",
        )
    finally:
        c.restoreState()


def _new_page_y() -> float:
    return A4[1] - TOP_MARGIN_MM * mm

def _start_new_page(c: canvas.Canvas) -> float:
    """
    새 페이지로 넘어가고 워터마크를 다시 깐 다음, y 시작 위치를 반환.
    """
    c.showPage()
    # 일반 페이지는 기본 워터마크(흑백, 연하게)
    _draw_watermark(c)
    return _new_page_y()


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
        return _start_new_page(c)

    return y

def _draw_paragraph(
    c: canvas.Canvas,
    text: str,
    x: float,
    y: float,
    max_chars: int = 80,          # ← 기존 파라미터는 남겨두지만 실제로는 안 씀
    font_size: int = BODY_FONT,
) -> float:
    """
    여러 줄 문단 출력.
    반환값: 마지막 줄 다음 y 좌표
    - 페이지 폭과 오른쪽 여백을 고려해 자동 줄바꿈한다.
    """
    # A4 기준, 왼쪽 margin_x와 대칭이 되도록 오른쪽 여백도 25mm로 가정
    page_width = A4[0]
    right_margin = 25 * mm
    max_width = page_width - x - right_margin   # 남은 출력 폭

    lines = _wrap_text(text, max_width, font_name=KOREAN_FONT_NAME, font_size=font_size)
    if not lines:
        return y

    y = _ensure_page_space(c, y, len(lines), font_size=font_size)
    c.setFont(KOREAN_FONT_NAME, font_size)

    # 본문은 조금 더 넉넉하게 줄 간격
    if font_size >= BODY_FONT:
        leading = font_size + 6
    else:
        leading = font_size + 4

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
    wrap: bool = False,
) -> float:
    """
    level 1: 큰 섹션 제목
    level 2: subsection 제목
    - 제목 전후로 여백을 조금 더 줘서 줄 간격이 넉넉하게 보이게 함.
    """
    if level == 1:
        font_size = SECTION_TITLE_FONT
        extra = HEADING_LEVEL1_EXTRA
    else:
        font_size = SUBTITLE_FONT
        extra = HEADING_LEVEL2_EXTRA

    right_margin = 25 * mm
    max_width = A4[0] - x - right_margin

    if wrap:
        lines = _wrap_text(text, max_width, font_name=KOREAN_FONT_NAME, font_size=font_size)
        lines = lines or [text]
        y = _ensure_page_space(c, y, len(lines) + 1, font_size=font_size)
        c.setFont(KOREAN_FONT_NAME, font_size)
        leading = font_size + 4
        for line in lines:
            c.drawString(x, y, line)
            y -= leading
        y -= extra
    else:
        y = _ensure_page_space(c, y, 2, font_size=font_size)
        c.setFont(KOREAN_FONT_NAME, font_size)
        c.drawString(x, y, text)
        y -= font_size + extra
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
# 통계/분석 유틸 (Prowler / Steampipe / Custodian)
# ──────────────────────────────────────────────
def _join_file_path(meta: Dict[str, Any], path: str) -> str:
    """
    result.json 메타의 run_dir 기반으로 파일 시스템 상 실제 경로를 만든다.
    path는 보통 'outputs/...' 형태라고 가정.
    """
    run_dir = meta.get("run_dir") or meta.get("base_dir") or ""
    return os.path.join(run_dir, path)


def _analyze_prowler_from_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Prowler 결과(메인 CSV)를 읽어 통계를 만든다.

    - total_fail, severity_counts: STATUS == FAIL 기준
    - findings: STATUS와 상관없이 모든 행을 담음 (표 출력용)

    반환:
    {
      "total_rows": int,
      "total_fail": int,
      "severity_counts": {"CRITICAL": n, "HIGH": m, ...},  # FAIL 기준
      "findings": [
          {
            "check_id": ...,
            "title": ...,
            "severity": ...,
            "status": ...,
            "service": ...,
            "region": ...,
            "resource": ...,
            "reason": ...,
          },
          ...
      ]
    }
    """
    result = {
        "total_rows": 0,
        "total_fail": 0,
        "severity_counts": {},
        "findings": [],
    }
    if not meta:
        return result

    files = meta.get("files") or []
    if not files:
        return result

    # 메인 CSV 후보: outputs/ 아래의 .csv (compliance/ 포함 가능)
    csv_candidates = [
        f for f in files if str(f.get("path", "")).lower().endswith(".csv")
    ]

    main_csv_entry = None
    # compliance/ 아닌 것 우선
    for f in csv_candidates:
        p = str(f.get("path", ""))
        if "/compliance/" not in p and "compliance" not in p:
            main_csv_entry = f
            break
    if not main_csv_entry and csv_candidates:
        main_csv_entry = csv_candidates[0]

    if not main_csv_entry:
        return result

    csv_path = _join_file_path(meta, main_csv_entry["path"])
    if not os.path.exists(csv_path):
        print(f"[WARN] Prowler CSV not found: {csv_path}")
        return result

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f, delimiter=";")
            header = next(reader, None)
            if not header:
                return result

            def idx(col_names: List[str]) -> Optional[int]:
                for name in col_names:
                    if name in header:
                        return header.index(name)
                return None

            idx_status = idx(["STATUS"])
            idx_sev = idx(["SEVERITY", "severity"])
            idx_check_id = idx(["CHECK_ID", "CHECKID", "check_id"])
            idx_check_title = idx(["CHECK_TITLE", "TITLE", "check_title"])
            idx_service = idx(["SERVICE", "SERVICE_NAME", "CLOUD_SERVICE"])
            idx_region = idx(["REGION", "REGION_NAME", "CLOUD_REGION", "AWS_REGION"])
            idx_resource = idx(["RESOURCE_ID", "RESOURCE_NAME", "CLOUD_RESOURCE_ID"])
            idx_reason = idx(
                ["RISK", "RISK_DESCRIPTION", "FAIL_REASON", "NOTES", "REMEDIATION"]
            )

            def safe_get(row: List[str], i: Optional[int]) -> str:
                if i is None or i >= len(row):
                    return ""
                return (row[i] or "").strip()

            for row in reader:
                result["total_rows"] += 1
                status = safe_get(row, idx_status).upper() if idx_status is not None else ""
                severity = (
                    safe_get(row, idx_sev).upper() if idx_sev is not None else ""
                ) or "UNKNOWN"

                # FAIL 통계 집계
                if status == "FAIL":
                    result["total_fail"] += 1
                    result["severity_counts"][severity] = (
                        result["severity_counts"].get(severity, 0) + 1
                    )

                # findings에는 STATUS 상관없이 다 넣음
                finding = {
                    "check_id": safe_get(row, idx_check_id),
                    "title": safe_get(row, idx_check_title),
                    "severity": severity,
                    "status": status or "UNKNOWN",
                    "service": safe_get(row, idx_service),
                    "region": safe_get(row, idx_region),
                    "resource": safe_get(row, idx_resource),
                    "reason": safe_get(row, idx_reason),
                }
                result["findings"].append(finding)

    except Exception as e:
        print(f"[WARN] Failed to analyze Prowler CSV: {e}")

    return result


def _analyze_steampipe_from_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Steampipe report JSON(steampipe_report.json)을 읽어 alarm/ok/info 통계와
    상위 컨트롤(alarm 많은 순) 정보를 만든다.
    반환:
    {
      "total_controls": int,
      "alarm": int,
      "ok": int,
      "info": int,
      "unknown": int,
      "severity_counts": {...},
      "controls": [
         {
           "id": "...",
           "title": "...",
           "severity": "...",
           "severity_order": int,
           "alarm": n,
           "ok": m,
           "info": k,
           "skip": s,
           "service": "...",
           "description": "...",
           "examples": [...]
         }
      ]
    }
    """
    stats = {
        "total_controls": 0,
        "alarm": 0,
        "ok": 0,
        "info": 0,
        "skip": 0,
        "unknown": 0,
        "severity_counts": {},
        "controls": [],
    }
    if not meta:
        return stats

    files = meta.get("files") or []
    target = None
    for f in files:
        p = str(f.get("path", ""))
        if p.endswith("steampipe_report.json"):
            target = f
            break
    if not target:
        return stats

    json_path = _join_file_path(meta, target["path"])
    if not os.path.exists(json_path):
        print(f"[WARN] Steampipe JSON not found: {json_path}")
        return stats

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load steampipe_report.json: {e}")
        return stats

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }

    def _extract_examples(results: Any) -> List[str]:
        examples: List[str] = []
        if isinstance(results, list):
            for row in results:
                if len(examples) >= 3:
                    break
                if isinstance(row, dict):
                    cand = (
                        row.get("resource") or row.get("resource_id") or row.get("title") or row.get("name")
                    )
                    if cand:
                        examples.append(str(cand))
                    elif "_resource" in row:
                        examples.append(str(row["_resource"]))
                    else:
                        examples.append(str(next(iter(row.values()))))
                else:
                    examples.append(str(row))
        elif isinstance(results, dict):
            for v in results.values():
                if len(examples) >= 3:
                    break
                if isinstance(v, list):
                    for vv in v:
                        examples.append(str(vv))
                        if len(examples) >= 3:
                            break
                else:
                    examples.append(str(v))
        return examples

    def walk_groups(groups: List[Dict[str, Any]]) -> None:
        if not groups:
            return
        for g in groups:
            controls = g.get("controls") or []
            for c in controls:
                stats["total_controls"] += 1
                summary = c.get("summary") or {}
                alarm = int(summary.get("alarm", 0) or 0)
                ok = int(summary.get("ok", 0) or 0)
                info = int(summary.get("info", 0) or 0)
                skip = int(summary.get("skip", 0) or 0)

                stats["alarm"] += alarm
                stats["ok"] += ok
                stats["info"] += info
                stats["skip"] += skip
                if alarm == ok == info == skip == 0:
                    stats["unknown"] += 1

                ctrl_id = str(c.get("name") or c.get("id") or c.get("title") or "")
                ctrl_title = str(c.get("title") or ctrl_id or "-")
                severity = str(c.get("severity") or "UNKNOWN").upper()
                sev_order = severity_order.get(severity, severity_order["UNKNOWN"])
                service = (
                    c.get("service")
                    or (c.get("tags") or {}).get("service")
                    or (c.get("category"))
                    or "-"
                )
                desc = c.get("description") or c.get("documentation") or ""
                examples = _extract_examples(c.get("results") or [])

                if alarm > 0:
                    stats["severity_counts"][severity] = stats["severity_counts"].get(severity, 0) + alarm

                    stats["controls"].append(
                        {
                            "id": ctrl_id or "-",
                            "title": ctrl_title,
                            "severity": severity,
                            "severity_order": sev_order,
                            "alarm": alarm,
                            "ok": ok,
                            "info": info,
                            "skip": skip,
                            "service": service,
                            "description": desc,
                            "examples": examples,
                        }
                    )

            sub = g.get("groups") or []
            if sub:
                walk_groups(sub)

    try:
        walk_groups(data.get("groups") or [])
    except Exception as e:
        print(f"[WARN] Failed to parse steampipe groups: {e}")

    stats["controls"].sort(
        key=lambda x: (
            x["severity_order"],
            -x["alarm"],
            x.get("id") or "",
        )
    )

    return stats


def _analyze_custodian_from_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Cloud Custodian outputs 디렉터리 내 resources.json 들을 읽어
    정책별 발견 리소스 개수를 집계한다.

    반환:
    {
      "policies": [
         {
           "policy": "iam-users-without-mfa-audit",
           "count": 3,
           "path": ".../outputs/iam-users-without-mfa-audit/resources.json",
           "examples": ["user1", "user2", ...]  # 대표 리소스 예시 (최대 3개)
         },
         ...
       ],
      "total_findings": int
    }
    """
    result = {"policies": [], "total_findings": 0}
    if not meta:
        return result

    files = meta.get("files") or []
    if not files:
        return result

    resources_entries = [
        f for f in files if str(f.get("path", "")).endswith("resources.json")
    ]

    # 대표 리소스 추출용 후보 키
    CANDIDATE_KEYS = [
        "id",
        "name",
        "Name",
        "UserName",
        "InstanceId",
        "DBInstanceIdentifier",
        "BucketName",
        "GroupId",
        "SecurityGroupId",
        "LoadBalancerArn",
        "LoadBalancerName",
        "Arn",
        "ResourceId",
        "KeyId",
    ]

    def _extract_example_id(res: Any) -> str:
        """리소스 객체에서 대표 식별자를 최대한 공통적으로 뽑아낸다."""
        if isinstance(res, dict):
            # 1) 대표 키 우선
            for k in CANDIDATE_KEYS:
                if k in res and isinstance(res[k], str) and res[k]:
                    return res[k]

            # 2) 태그/Tags 에서 Name 찾기
            tags = res.get("Tags") or res.get("tags")
            if isinstance(tags, list):
                for t in tags:
                    if not isinstance(t, dict):
                        continue
                    key = t.get("Key") or t.get("key")
                    if key in ("Name", "name"):
                        val = t.get("Value") or t.get("value")
                        if isinstance(val, str) and val:
                            return val

        # 3) 마지막 fallback: 문자열화해서 앞부분만 사용
        s = str(res)
        return s[:80]

    for f in resources_entries:
        path = str(f.get("path", ""))
        full_path = _join_file_path(meta, path)
        policy_dir = os.path.dirname(path).split("/")[-1]

        meta_path = path.replace("resources.json", "metadata.json")
        meta_full = _join_file_path(meta, meta_path)
        policy_name = policy_dir

        if os.path.exists(meta_full):
            try:
                with open(meta_full, "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                policy_obj = mdata.get("policy") or {}
                name_from_meta = policy_obj.get("name")
                if name_from_meta:
                    policy_name = name_from_meta
            except Exception:
                pass

        count = 0
        examples: List[str] = []

        try:
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8") as rf:
                    data = json.load(rf)
                if isinstance(data, list):
                    count = len(data)
                    # 예시 리소스 최대 3개까지 추출
                    for res in data:
                        if len(examples) >= 3:
                            break
                        examples.append(_extract_example_id(res))
        except Exception as e:
            print(f"[WARN] Failed to load Custodian resources: {full_path} - {e}")
            continue

        if count <= 0:
            continue

        result["policies"].append(
            {
                "policy": policy_name,
                "count": count,
                "path": full_path,
                "examples": examples,
            }
        )
        result["total_findings"] += count

    result["policies"].sort(key=lambda x: x["policy"])
    return result


def _analyze_scout_from_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Scout Suite 결과 JS(scoutsuite_results_*.js)를 읽어 상위 취약점 목록을 만든다.
    - level(danger/warning/info)과 flagged_items를 사용해 정렬
    """
    result = {
        "findings": [],
        "severity_counts": {},
        "total_flagged": 0,
        "summary": {},
    }
    if not meta:
        return result

    files = meta.get("files") or []
    target = None
    for f in files:
        p = str(f.get("path", ""))
        if p.endswith(".js") and "scoutsuite-results" in p and "results" in os.path.basename(p):
            target = f
            break
    if not target:
        return result

    js_path = _join_file_path(meta, target["path"])
    if not os.path.exists(js_path):
        print(f"[WARN] ScoutSuite results JS not found: {js_path}")
        return result

    try:
        raw = Path(js_path).read_text(encoding="utf-8", errors="replace")
        parts = raw.split("=", 1)
        if len(parts) < 2:
            return result
        json_text = parts[1].strip()
        if json_text.endswith(";"):
            json_text = json_text[:-1].strip()
        data = json.loads(json_text)
    except Exception as e:
        print(f"[WARN] Failed to parse ScoutSuite results: {e}")
        return result

    result["summary"] = data.get("last_run", {}).get("summary", {})

    severity_map = {
        "danger": ("CRITICAL", 0),
        "warning": ("MEDIUM", 1),
        "info": ("INFO", 2),
        "ok": ("INFO", 3),
    }

    findings: List[Dict[str, Any]] = []
    services = data.get("services") or {}
    for svc_name, svc in services.items():
        for fid, fobj in (svc.get("findings") or {}).items():
            flagged = int(fobj.get("flagged_items") or 0)
            if flagged <= 0:
                continue
            level = str(fobj.get("level") or "info").lower()
            severity, order = severity_map.get(level, ("UNKNOWN", 5))

            desc = fobj.get("description") or fobj.get("rationale") or fid
            rationale = fobj.get("rationale") or ""

            examples: List[str] = []
            items_field = fobj.get("items")
            if isinstance(items_field, list):
                examples = [str(x) for x in items_field[:3]]
            elif isinstance(items_field, dict):
                for val in items_field.values():
                    if len(examples) >= 3:
                        break
                    if isinstance(val, list):
                        for v in val:
                            examples.append(str(v))
                            if len(examples) >= 3:
                                break
                    else:
                        examples.append(str(val))

            findings.append(
                {
                    "id": fid,
                    "service": svc_name,
                    "severity": severity,
                    "severity_order": order,
                    "flagged_items": flagged,
                    "description": desc,
                    "rationale": rationale,
                    "examples": examples,
                }
            )
            result["severity_counts"][severity] = (
                result["severity_counts"].get(severity, 0) + flagged
            )
            result["total_flagged"] += flagged

    findings.sort(
        key=lambda x: (
            x["severity_order"],
            -x["flagged_items"],
            x.get("service") or "",
            x.get("id") or "",
        )
    )
    result["findings"] = findings
    return result


def _merge_severity_counts(*dicts: Dict[str, int]) -> Dict[str, int]:
    merged: Dict[str, int] = {}
    for d in dicts:
        for k, v in d.items():
            merged[k] = merged.get(k, 0) + v
    return merged


def _build_prowler_threat_items(
    prowler_stats: Dict[str, Any],
    max_items: int = 10,
) -> List[Dict[str, Any]]:
    """
    Prowler FAIL 결과를 체크 ID/제목 단위로 묶어서
    '세부 위협 항목' 목록을 만든다.

    반환 예:
    [
      {
        "check_id": "iam_user_no_mfa",
        "title": "Ensure IAM users have MFA enabled",
        "severity": "HIGH",
        "fail_count": 12,
        "service": "iam",
        "region": "ap-northeast-2",
        "resource": "user/demo",
        "reason": "MFA is not enabled for IAM user ..."
      },
      ...
    ]
    """
    findings = prowler_stats.get("findings") or []
    if not findings:
        return []

    # FAIL 결과만 사용
    fail_rows = [
        f for f in findings
        if (f.get("status") or "").upper() == "FAIL"
    ]
    if not fail_rows:
        return []

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }

    grouped: Dict[str, Dict[str, Any]] = {}

    for f in fail_rows:
        check_id = (f.get("check_id") or "").strip()
        title = (f.get("title") or "").strip()
        key = f"{check_id}||{title}"

        severity = (f.get("severity") or "UNKNOWN").upper()
        sev_ord = severity_order.get(severity, severity_order["UNKNOWN"])

        entry = grouped.get(key)
        if entry is None:
            grouped[key] = {
                "check_id": check_id or "-",
                "title": title or "-",
                "severity": severity,
                "severity_order": sev_ord,
                "fail_count": 1,
                "service": f.get("service") or "-",
                "region": f.get("region") or "-",
                "resource": f.get("resource") or "-",
                "reason": (f.get("reason") or "").strip(),
            }
        else:
            # FAIL 건수 누적
            entry["fail_count"] += 1

            # 더 높은(위험한) severity가 나오면 교체
            if sev_ord < entry["severity_order"]:
                entry["severity"] = severity
                entry["severity_order"] = sev_ord

            # reason이 비어있으면 새 row의 reason 사용
            if not entry["reason"] and f.get("reason"):
                entry["reason"] = (f.get("reason") or "").strip()

            # 서비스/리전/리소스도 비어있을 때만 채워주기
            if entry["service"] == "-" and f.get("service"):
                entry["service"] = f.get("service")
            if entry["region"] == "-" and f.get("region"):
                entry["region"] = f.get("region")
            if entry["resource"] == "-" and f.get("resource"):
                entry["resource"] = f.get("resource")

    items = list(grouped.values())

    # 심각도 → FAIL 건수 → 체크 ID 순으로 정렬 후 상위 N개
    items.sort(
        key=lambda x: (
            x["severity_order"],
            -x["fail_count"],
            x["check_id"],
        )
    )
    return items[:max_items]


# ──────────────────────────────────────────────
# Prowler 상위 10건 표 렌더링
# ──────────────────────────────────────────────
def _draw_prowler_table(
    c: canvas.Canvas,
    findings: List[Dict[str, Any]],
    margin_x: float,
    y: float,
) -> float:
    """
    Prowler findings 상위 10건을 '세로 표' 형태로 출력.
    - 각 취약점마다 작은 카드/표처럼:
      ┌──────────────────────────────┐
      │ No.1 [STATUS/SEV]           │
      │ 체크 ID: ...                │
      │ 서비스: ..., 리전: ...      │
      │ 리소스: ...                 │
      │ 사유/위험 설명: ...        │
      └──────────────────────────────┘
    """

    if not findings:
        return _draw_paragraph(
            c,
            "현재 Prowler 메인 CSV에서 진단 결과를 식별하지 못했습니다.",
            margin_x,
            y,
            70,
            BODY_FONT,
        )

    width, _ = A4
    box_left = margin_x
    box_right = width - margin_x
    box_width = box_right - box_left

    # 제목 설명 한 줄 정도 먼저
    y = _draw_paragraph(
        c,
        "※ 아래 표는 Prowler 진단 결과 중 우선 확인이 필요한 상위 10개 항목을 세로 표 형태로 정리한 것입니다.",
        margin_x,
        y,
        max_chars=80,   # 페이지 폭 기준으로도 조금 줄이기
        font_size=BODY_FONT,
    )
    # 설명과 No.1 사이 여백을 넉넉히
    y -= BODY_FONT + 15

    # 박스 내부에서 사용할 최대 글자 수(폭)
    # - 몸통 텍스트는 55자 정도, reason(작은 글씨)는 70자
    INNER_MAX = 55
    INNER_REASON_MAX = 70

    def _estimate_height(fitem: Dict[str, Any]) -> float:
        """카드 전체 높이 대략 계산(줄바꿈 반영)"""
        inner_x = margin_x + 4 * mm
        value_x = inner_x + 32 * mm
        right_margin = 25 * mm
        max_w_body = A4[0] - value_x - right_margin
        max_w_reason = A4[0] - value_x - right_margin

        def lines(text: str, font_size: int) -> int:
            lw = _wrap_text(text or "", max_w_body, font_name=KOREAN_FONT_NAME, font_size=font_size)
            return len(lw) or 1

        def lines_reason(text: str) -> int:
            lw = _wrap_text(text or "", max_w_reason, font_name=KOREAN_FONT_NAME, font_size=SMALL_FONT)
            return len(lw) or 1

        h = 0
        h += 5  # pre offset
        h += CARD_BODY_FONT + 10  # header line
        h += lines(fitem.get("check_id"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines(fitem.get("title"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        combo = f"{fitem.get('service') or '-'} / {fitem.get('region') or '-'}"
        h += lines(combo, CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines(fitem.get("resource"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines_reason(fitem.get("reason")) * (CARD_SMALL_FONT + 4) + 4
        # h += 6  # 카드 간 간격(박스 하단 + 여백)
        return h

    # 각 finding을 카드 형태로 반복
    for idx_f, fitem in enumerate(findings[:10], start=1):
        est_h = _estimate_height(fitem)
        if y - est_h < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

        status = (fitem.get("status") or "UNKNOWN").upper()
        sev = (fitem.get("severity") or "UNKNOWN").upper()
        check_id = fitem.get("check_id") or "-"
        title = fitem.get("title") or "-"
        service = fitem.get("service") or "-"
        region = fitem.get("region") or "-"
        resource = fitem.get("resource") or "-"
        reason = fitem.get("reason") or "-"

        # 카드(박스) 상단 y좌표 저장
        box_top_y = y

        # 박스 안 패딩
        inner_x = box_left + 4 * mm
        label_x = inner_x
        value_x = inner_x + 32 * mm  # 라벨 열 폭

        # 1) 첫 줄: No + 상태/심각도
        c.drawString(inner_x, y, "")
        y-=10
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        header_text = f"No.{idx_f}  [{status}/{sev}]"
        c.drawString(inner_x, y, header_text)
        y -= CARD_BODY_FONT + 10

        # 2) 체크 ID
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(label_x, y, "체크 ID:")
        y = _draw_paragraph(
            c,
            check_id,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        # 3) 점검 항목(타이틀)
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(label_x, y, "점검 항목:")
        y = _draw_paragraph(
            c,
            title,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        # 4) 서비스 / 리전
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(label_x, y, "서비스/리전:")
        combo = f"{service} / {region}"
        y = _draw_paragraph(
            c,
            combo,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        # 5) 리소스
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(label_x, y, "리소스:")
        y = _draw_paragraph(
            c,
            resource,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        # 6) 사유/위험 설명
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(label_x, y, "사유/위험 설명:")
        y = _draw_paragraph(
            c,
            reason,
            value_x,
            y,
            max_chars=INNER_REASON_MAX,
            font_size=CARD_SMALL_FONT,
        )
        y -= 4

        # 카드 하단 y 저장 (박스 테두리용)
        box_bottom_y = y + 4  # 마지막 줄 밑에 약간 여유

        # 박스 테두리 그리기
        c.setLineWidth(0.5)
        c.rect(
            box_left,
            box_bottom_y,
            box_width,
            box_top_y - box_bottom_y + 8,  # 위/아래 여유
        )

        # 카드 사이 간격
        y = box_bottom_y - 10

        # 다음 카드 시작 전에만 페이지 넘기기 (박스 일부 잘림 허용)
        if y < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

    return y


def _draw_scout_table(
    c: canvas.Canvas,
    findings: List[Dict[str, Any]],
    margin_x: float,
    y: float,
) -> float:
    """
    Scout Suite Flagged 항목 상위 10건을 카드 형태로 출력.
    """
    if not findings:
        return _draw_paragraph(
            c,
            "Scout Suite 리포트에서 Flagged 항목을 찾지 못했습니다.",
            margin_x,
            y,
            70,
            BODY_FONT,
        )

    width, _ = A4
    box_left = margin_x
    box_right = width - margin_x
    box_width = box_right - box_left

    y = _draw_paragraph(
        c,
        "※ 아래 표는 Scout Suite 리포트에서 위험도가 높은 순으로 Flagged 항목 상위 10개를 정리한 것입니다.",
        margin_x,
        y,
        max_chars=80,
        font_size=BODY_FONT,
    )
    y -= BODY_FONT + 15

    INNER_MAX = 55

    def _estimate_height(fitem: Dict[str, Any]) -> float:
        inner_x = margin_x + 4 * mm
        value_x = inner_x + 32 * mm
        right_margin = 25 * mm
        max_w = A4[0] - value_x - right_margin

        def lines(text: str, font_size: int) -> int:
            lw = _wrap_text(text or "", max_w, font_name=KOREAN_FONT_NAME, font_size=font_size)
            return len(lw) or 1

        h = 5  # pre offset
        h += CARD_BODY_FONT + 10  # header
        h += lines(f"{fitem.get('service') or '-'} / {fitem.get('id') or '-'}", CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines(fitem.get("description"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        if fitem.get("rationale"):
            h += lines(fitem.get("rationale"), CARD_SMALL_FONT) * (CARD_SMALL_FONT + 4) + 4
        if fitem.get("examples"):
            examples_txt = "; ".join(fitem.get("examples") or [])
            h += lines(examples_txt, CARD_SMALL_FONT) * (CARD_SMALL_FONT + 4) + 4
        h += 6
        return h

    for idx_f, fitem in enumerate(findings[:10], start=1):
        est_h = _estimate_height(fitem)
        if y - est_h < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

        sev = (fitem.get("severity") or "UNKNOWN").upper()
        flagged = int(fitem.get("flagged_items") or 0)
        fid = fitem.get("id") or "-"
        service = fitem.get("service") or "-"
        desc = fitem.get("description") or "-"
        rationale = fitem.get("rationale") or ""
        examples = fitem.get("examples") or []

        box_top_y = y
        inner_x = box_left + 4 * mm
        label_x = inner_x
        value_x = inner_x + 32 * mm
        y-=10
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(inner_x, y, f"No.{idx_f}  [{sev}] flagged={flagged}")
        y -= CARD_BODY_FONT + 10

        c.drawString(label_x, y, "서비스/체크:")
        y = _draw_paragraph(
            c,
            f"{service} / {fid}",
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        c.drawString(label_x, y, "설명:")
        y = _draw_paragraph(
            c,
            desc,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        if rationale:
            c.drawString(label_x, y, "근거:")
            y = _draw_paragraph(
                c,
                rationale,
                value_x,
                y,
                max_chars=INNER_MAX,
                font_size=CARD_SMALL_FONT,
            )
            y -= 4

        if examples:
            c.drawString(label_x, y, "예시:")
            y = _draw_paragraph(
                c,
                "; ".join(examples),
                value_x,
                y,
                max_chars=INNER_MAX,
                font_size=CARD_SMALL_FONT,
            )
            y -= 4

        box_bottom_y = y + 4
        c.setLineWidth(0.5)
        c.rect(
            box_left,
            box_bottom_y,
            box_width,
            box_top_y - box_bottom_y + 8,
        )

        y = box_bottom_y - 10
        if y < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

    return y


def _draw_steampipe_table(
    c: canvas.Canvas,
    controls: List[Dict[str, Any]],
    margin_x: float,
    y: float,
) -> float:
    """
    Steampipe Powerpipe benchmark 결과에서 alarm 많은 순 상위 10개 컨트롤을 카드 형태로 출력.
    """
    if not controls:
        return _draw_paragraph(
            c,
            "Steampipe 리포트에서 alarm 상태의 컨트롤을 찾지 못했습니다.",
            margin_x,
            y,
            70,
            BODY_FONT,
        )

    width, _ = A4
    box_left = margin_x
    box_right = width - margin_x
    box_width = box_right - box_left

    y = _draw_paragraph(
        c,
        "※ 아래 표는 Steampipe(Powerpipe benchmark) 결과에서 alarm 개수가 많은 순으로 상위 10개 컨트롤을 정리한 것입니다.",
        margin_x,
        y,
        max_chars=80,
        font_size=BODY_FONT,
    )
    y -= BODY_FONT + 15

    INNER_MAX = 55

    def _estimate_height(ctrl: Dict[str, Any]) -> float:
        inner_x = margin_x + 4 * mm
        value_x = inner_x + 32 * mm
        right_margin = 25 * mm
        max_w = A4[0] - value_x - right_margin

        def lines(text: str, font_size: int) -> int:
            lw = _wrap_text(text or "", max_w, font_name=KOREAN_FONT_NAME, font_size=font_size)
            return len(lw) or 1

        h = 5  # pre offset
        h += CARD_BODY_FONT + 10  # header
        h += lines(f"{ctrl.get('id') or '-'} – {ctrl.get('title') or '-'}", CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines(ctrl.get("service"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        h += lines(ctrl.get("description"), CARD_BODY_FONT) * (CARD_BODY_FONT + 6) + 4
        if ctrl.get("examples"):
            examples_txt = "; ".join(ctrl.get("examples") or [])
            h += lines(examples_txt, CARD_SMALL_FONT) * (CARD_SMALL_FONT + 4) + 4
        h += 6
        return h

    for idx_c, ctrl in enumerate(controls[:10], start=1):
        est_h = _estimate_height(ctrl)
        if y - est_h < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

        sev = (ctrl.get("severity") or "UNKNOWN").upper()
        alarm = int(ctrl.get("alarm") or 0)
        ok = int(ctrl.get("ok") or 0)
        info = int(ctrl.get("info") or 0)
        skip = int(ctrl.get("skip") or 0)
        cid = ctrl.get("id") or "-"
        title = ctrl.get("title") or "-"
        service = ctrl.get("service") or "-"
        desc = ctrl.get("description") or "-"
        examples = ctrl.get("examples") or []

        box_top_y = y
        inner_x = box_left + 4 * mm
        label_x = inner_x
        value_x = inner_x + 32 * mm
        y-=10
        c.setFont(KOREAN_FONT_NAME, CARD_BODY_FONT)
        c.drawString(inner_x, y, f"No.{idx_c}  [{sev}] alarm={alarm} ok={ok}")
        y -= CARD_BODY_FONT + 10

        c.drawString(label_x, y, "컨트롤:")
        y = _draw_paragraph(
            c,
            f"{cid} – {title}",
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        c.drawString(label_x, y, "서비스:")
        y = _draw_paragraph(
            c,
            service,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        c.drawString(label_x, y, "설명:")
        y = _draw_paragraph(
            c,
            desc,
            value_x,
            y,
            max_chars=INNER_MAX,
            font_size=CARD_BODY_FONT,
        )
        y -= 4

        if examples:
            c.drawString(label_x, y, "예시:")
            y = _draw_paragraph(
                c,
                "; ".join(examples),
                value_x,
                y,
                max_chars=INNER_MAX,
                font_size=CARD_SMALL_FONT,
            )
            y -= 4

        box_bottom_y = y + 4
        c.setLineWidth(0.5)
        c.rect(
            box_left,
            box_bottom_y,
            box_width,
            box_top_y - box_bottom_y + 8,
        )

        y = box_bottom_y - 10
        if y < BOTTOM_MARGIN_MM * mm:
            y = _start_new_page(c)

    return y





# ──────────────────────────────────────────────
# 메인 함수
# ──────────────────────────────────────────────
def generate_evidence_pdf(
    codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    SAGE 보고서 구조에 맞춰 PDF 증적 보고서를 생성한다.

    섹션 구성:
      1. 종합 요약
      2. 세부 취약점 항목(템플릿 설명)
      3. 주요 진단 결과 (Prowler/Scout/Steampipe 상위 10건 표)
      4. 도구별 실행 상세
      5. 부록 – 도구별 산출물 개요
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
    # 1-a) 통계 분석 (Prowler / Steampipe / Custodian)
    prowler_stats = _analyze_prowler_from_meta(tool_meta.get("prowler"))
    steampipe_stats = _analyze_steampipe_from_meta(tool_meta.get("steampipe"))
    custodian_stats = _analyze_custodian_from_meta(tool_meta.get("custodian"))
    scout_stats = _analyze_scout_from_meta(tool_meta.get("scout"))

    total_severity = _merge_severity_counts(prowler_stats.get("severity_counts", {}))

    # 2) PDF 준비
    out_dir = _safe_evidence_dir(EVIDENCE_ROOT)
    pdf_filename = "evidence_report.pdf"
    pdf_path = os.path.join(out_dir, pdf_filename)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    margin_x = 25 * mm
    _draw_watermark(c, alpha=0.25, use_color=True)
    y = _new_page_y()

    # ─────────────────────────────────────
    # 0. 표지
    # ─────────────────────────────────────
    # 표지 상단 제목(볼드, 크게)
    c.setFont(BOLD_FONT_NAME, TITLE_FONT)
    c.drawString(margin_x, y, "SAGE 클라우드 보안·컴플라이언스")
    y -= TITLE_FONT + 10
    c.drawString(margin_x, y, "취약점 분석·평가 증적 보고서")
    y -= TITLE_FONT + 20

    # 메타 정보는 표지 하단 쪽에 배치
    y = BOTTOM_MARGIN_MM * mm + 40 * mm
    meta_font = SUBTITLE_FONT + 3  # 작성일시/메타 정보 더 크게
    c.setFont(KOREAN_FONT_NAME, meta_font)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(margin_x, y, f"작성일시: {now_str}")
    y -= meta_font + 8
    c.drawString(margin_x, y, f"AWS Profile: {aws_profile}")
    y -= meta_font + 8
    c.drawString(margin_x, y, f"대상 리전: {aws_region}")
    y -= meta_font + 8

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

    y = _start_new_page(c)

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
    y -= 4

    # 1-1-b 위험도 통계 요약 (Prowler FAIL 기준)
    if prowler_stats.get("total_fail", 0) > 0:
        sev_summary_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
            cnt = prowler_stats["severity_counts"].get(sev, 0)
            if cnt:
                sev_summary_parts.append(f"{sev}: {cnt}건")
        sev_summary = ", ".join(sev_summary_parts) if sev_summary_parts else "통계 없음"

        text = (
            f"Prowler FAIL 결과 기준으로 총 {prowler_stats['total_fail']}건의 취약점이 식별되었으며, "
            f"Severity 분포는 {sev_summary} 수준이다."
        )
        y = _draw_paragraph(c, text, margin_x, y, max_chars=80, font_size=BODY_FONT)
        y -= 8

    # 1-2 개선 우선순위 (템플릿)
    y = _draw_heading(c, "1-2. 개선 우선순위(템플릿)", margin_x, y, level=2)
    priority_lines = [
        "① CA-03 클라우드 계정 루트·관리자 권한 관리",
        "② LG-01 클라우드 감사 로그(CloudTrail 등) 설정 보강",
        "③ (선택) 스토리지·네트워크·암호화 등 추가 통제 항목",
    ]
    for line in priority_lines:
        y = _draw_paragraph(c, f"- {line}", margin_x, y, max_chars=80, font_size=BODY_FONT)
    y -= 4

    y = _start_new_page(c)

    # ─────────────────────────────────────
    # ─────────────────────────────────────
    # 2. 세부 취약점 항목 (개념 설명)
    # ─────────────────────────────────────
    # ─────────────────────────────────────
    # 2. 세부 취약점 항목 (개념 설명)
    # ─────────────────────────────────────
    # ─────────────────────────────────────
    y = _draw_heading(c, "2. 세부 취약점 항목 (Prowler 기반 위협 설명)", margin_x, y, level=1)

    threat_items = _build_prowler_threat_items(prowler_stats, max_items=10)

    if not threat_items:
        y = _draw_paragraph(
            c,
            "현재 Prowler FAIL 결과에서 세부 위협 항목을 추출할 수 있는 데이터가 없습니다.",
            margin_x,
            y,
            80,
            BODY_FONT,
        )
    else:
        intro = (
            "본 장에서는 Prowler FAIL 결과를 기반으로, 실제 점검에서 발견된 주요 취약점 항목과 "
            "각 항목에 대한 위협(위험 설명)을 정리하였다. 체크 ID/제목 단위로 FAIL 건수를 집계하고, "
            "Prowler 리포트 상의 '위험 설명/사유(RISK/FAIL_REASON/NOTES 등)' 필드를 그대로 활용한다."
        )
        y = _draw_paragraph(c, intro, margin_x, y, 80, BODY_FONT)
        y -= 10

        for idx, t in enumerate(threat_items, start=1):
            title = (
                f"2-{idx}. [{t['severity']}] {t['check_id']} – {t['title']}"
                if t.get("check_id")
                else f"2-{idx}. [{t['severity']}] {t['title']}"
            )
            y = _draw_heading(c, title, margin_x, y, level=2, wrap=True)

            # FAIL 건수
            y = _draw_paragraph(
                c,
                f"· FAIL 발생 건수: {t['fail_count']}건",
                margin_x,
                y,
                90,
                BODY_FONT,
            )

            # 서비스/리전
            service = t.get("service") or "-"
            region = t.get("region") or "-"
            y = _draw_paragraph(
                c,
                f"· 주요 서비스/리전: {service} / {region}",
                margin_x,
                y,
                90,
                BODY_FONT,
            )

            # 대표 리소스
            resource = (t.get("resource") or "").strip()
            if resource:
                y = _draw_paragraph(
                    c,
                    f"· 대표 리소스 예시: {resource}",
                    margin_x,
                    y,
                    90,
                    BODY_FONT,
                )

            # ★ 여기서 “위협만 뽑아서” 사용
            reason = (t.get("reason") or "").strip()
            if reason:
                y = _draw_paragraph(
                    c,
                    f"· Prowler 위협/위험 설명: {reason}",
                    margin_x,
                    y,
                    90,
                    BODY_FONT,
                )
            else:
                y = _draw_paragraph(
                    c,
                    "· Prowler 위협/위험 설명: (리포트에 별도 설명 텍스트 없음)",
                    margin_x,
                    y,
                    90,
                    BODY_FONT,
                )

            # 항목 간 간격을 더 넓게 확보
            y -= 20
            y = _ensure_page_space(c, y, 6, font_size=BODY_FONT)

    y = _start_new_page(c)

    # ─────────────────────────────────────
    # 3. 주요 진단 결과 (상위 10건)
    # ─────────────────────────────────────
    y -= 10
    y = _draw_heading(c, "3. 주요 진단 결과 (상위 10건)", margin_x, y, level=1)

    # 3-1. Prowler
    y = _draw_heading(c, "3-1. Prowler (상위 10건)", margin_x, y, level=2)
    findings = prowler_stats.get("findings") or []
    y = _draw_prowler_table(c, findings, margin_x, y)

    # 섹션 종료 후 페이지 분리
    y = _start_new_page(c)

    # 3-2. Scout Suite
    y -= 6
    y = _draw_heading(c, "3-2. Scout Suite (상위 10건)", margin_x, y, level=2)
    y = _draw_scout_table(c, scout_stats.get("findings") or [], margin_x, y)

    # 섹션 종료 후 페이지 분리
    y = _start_new_page(c)

    # 3-3. Steampipe
    y -= 6
    y = _draw_heading(c, "3-3. Steampipe (상위 10건)", margin_x, y, level=2)
    y = _draw_steampipe_table(c, steampipe_stats.get("controls") or [], margin_x, y)

    y = _start_new_page(c)

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

        run_dir_val = meta.get("run_dir", "-")
        output_dir_val = meta.get("output_dir", "-")
        rc = meta.get("rc")
        duration_ms = meta.get("duration_ms")
        note = meta.get("note") or ""
        files = meta.get("files") or []

        rc_str = "-" if rc is None else str(rc)
        dur_str = "-" if duration_ms is None else f"{duration_ms} ms"

        y = _draw_paragraph(c, f"Run dir: {run_dir_val}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Output dir: {output_dir_val}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Exit code: {rc_str}", margin_x, y, 90, BODY_FONT)
        y = _draw_paragraph(c, f"Duration: {dur_str}", margin_x, y, 90, BODY_FONT)
        if note:
            y = _draw_paragraph(c, f"Note: {note}", margin_x, y, 90, BODY_FONT)

        # 도구별 통계 요약
        if code == "prowler" and prowler_stats.get("total_rows", 0) > 0:
            y = _draw_paragraph(
                c,
                "Prowler 통계 (요약):",
                margin_x,
                y,
                max_chars=90,
                font_size=BODY_FONT,
            )
            y = _draw_paragraph(
                c,
                f"- 총 진단 행 수: {prowler_stats['total_rows']}행",
                margin_x + 6 * mm,
                y,
                90,
                BODY_FONT,
            )
            y = _draw_paragraph(
                c,
                f"- FAIL 건수: {prowler_stats['total_fail']}건",
                margin_x + 6 * mm,
                y,
                90,
                BODY_FONT,
            )
            if prowler_stats["total_fail"] > 0:
                for sev, cnt in prowler_stats["severity_counts"].items():
                    y = _draw_paragraph(
                        c,
                        f"- {sev}: {cnt}건 (FAIL)",
                        margin_x + 6 * mm,
                        y,
                        90,
                        BODY_FONT,
                    )

        if code == "steampipe" and steampipe_stats.get("total_controls", 0) > 0:
            y = _draw_paragraph(
                c,
                "Steampipe 통계 (control 요약):",
                margin_x,
                y,
                90,
                BODY_FONT,
            )
            y = _draw_paragraph(
                c,
                f"- 총 Control: {steampipe_stats['total_controls']}개",
                margin_x + 6 * mm,
                y,
                90,
                BODY_FONT,
            )
            y = _draw_paragraph(
                c,
                f"- alarm: {steampipe_stats['alarm']} / ok: {steampipe_stats['ok']} / info: {steampipe_stats['info']} / skip: {steampipe_stats['skip']} / unknown: {steampipe_stats['unknown']}",
                margin_x + 6 * mm,
                y,
                90,
                BODY_FONT,
            )

            if code == "custodian" and custodian_stats.get("total_findings", 0) > 0:
                y = _draw_paragraph(
                    c,
                    "Cloud Custodian 통계 (policy별 발견 리소스 수):",
                    margin_x,
                    y,
                    90,
                    BODY_FONT,
                )
                y = _draw_paragraph(
                    c,
                    f"- 총 발견 리소스: {custodian_stats['total_findings']}개",
                    margin_x + 6 * mm,
                    y,
                    90,
                    BODY_FONT,
                )
                for p in custodian_stats["policies"]:
                    y = _draw_paragraph(
                        c,
                        f"- {p['policy']}: {p['count']}개",
                        margin_x + 6 * mm,
                        y,
                        90,
                        BODY_FONT,
                    )

                    examples = p.get("examples") or []
                    if examples:
                        # 예시 리소스는 한 줄에 콤마로 나열
                        ex_str = ", ".join(examples)
                        y = _draw_paragraph(
                            c,
                            f"  · 예시 리소스: {ex_str}",
                            margin_x + 8 * mm,
                            y,
                            95,
                            SMALL_FONT,
                        )


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
                if mtime:
                    try:
                        mtime_str = datetime.fromtimestamp(mtime).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    except Exception:
                        mtime_str = "-"
                else:
                    mtime_str = "-"

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

    y = _start_new_page(c)

    # ─────────────────────────────────────
    # 5. 부록: 산출물 개요
    # ─────────────────────────────────────
    y = _draw_heading(c, "5. 부록 – 도구별 산출물 개요", margin_x, y, level=1)

    for code in codes:
        meta = tool_meta.get(code) or {}
        item = get_item_by_code(code) or {}
        tool_name = item.get("name", code)
        files = meta.get("files") or []
        out_dir_val = meta.get("output_dir", "-")

        summary = (
            f"[{tool_name}] {code}\n"
            f"· Output dir: {out_dir_val}\n"
            f"· 기록된 산출물 개수: {len(files)}개\n"
            "· 상세 내용은 SAGE Dashboard 또는 개별 리포트 파일(CSV/JSON/HTML/로그)에서 확인 가능"
        )
        y = _draw_paragraph(c, summary, margin_x, y, 90, BODY_FONT)
        y -= 6

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
        "prowler": {
            "total_rows": prowler_stats.get("total_rows", 0),
            "total_fail": prowler_stats.get("total_fail", 0),
            "severity_counts": prowler_stats.get("severity_counts", {}),
        },
        "steampipe": steampipe_stats,
        "custodian": {
            "total_findings": custodian_stats.get("total_findings", 0),
            "policies": custodian_stats.get("policies", []),
        },
        "scout": {
            "total_flagged": scout_stats.get("total_flagged", 0),
            "severity_counts": scout_stats.get("severity_counts", {}),
            "summary": scout_stats.get("summary", {}),
        },
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

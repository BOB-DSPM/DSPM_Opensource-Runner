# app/services/oss_service.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
from ..utils.loader import list_items, get_item_by_code, merge

# ---------- 내부 헬퍼 ----------

def _prowler_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    """prowler 세부 정보 템플릿(정적). 실행은 하지 않고 옵션/예시만 제공."""
    defaults = {
        "code": "prowler",
        "name": "Prowler",
        "category": "cloud-security",
        "tags": ["aws", "security", "audit", "cli"],
        "homepage": "https://github.com/prowler-cloud/prowler",
        "desc": "AWS 등 클라우드 보안 점검 CLI",
        "license": "Apache-2.0",
    }
    meta = merge(defaults, base or {})

    options: List[Dict[str, Any]] = [
        {
            "key": "provider",
            "label": "Provider",
            "type": "enum",
            "values": ["aws", "azure", "gcp", "kubernetes", "github", "m365", "oci", "nhn"],
            "required": True,
            "default": "aws",
            "help": "기본 진단 대상 클라우드/플랫폼",
        },
        {
            "key": "profile",
            "label": "AWS CLI Profile",
            "type": "string",
            "required": False,
            "placeholder": "default",
            "help": "AWS 접근 시 사용할 프로파일 (예: default)",
            "visible_if": {"provider": "aws"},
        },
        {
            "key": "region",
            "label": "AWS Region",
            "type": "string",
            "required": False,
            "placeholder": "ap-northeast-2",
            "help": "AWS 리전 제한이 필요할 때 지정",
            "visible_if": {"provider": "aws"},
        },
        {
            "key": "list",
            "label": "List Mode",
            "type": "enum",
            "values": ["checks", "services", "compliance", "categories"],
            "required": False,
            "help": "목록 출력 모드(--list-<mode>)",
        },
        {
            "key": "services",
            "label": "Services",
            "type": "array[string]",
            "required": False,
            "help": "특정 서비스만 점검 (예: s3, rds)",
        },
        {
            "key": "checks",
            "label": "Checks",
            "type": "array[string]",
            "required": False,
            "help": "특정 체크 ID만 실행",
        },
        {
            "key": "compliance",
            "label": "Compliance Frameworks",
            "type": "array[string]",
            "required": False,
            "help": "특정 규정 프레임워크만 실행 (예: cis_1.4, nist_csf 등)",
        },
        {
            "key": "severity",
            "label": "Severity",
            "type": "enum",
            "values": ["informational", "low", "medium", "high", "critical"],
            "required": False,
            "help": "심각도 필터",
        },
        {
            "key": "format",
            "label": "Output Format",
            "type": "enum",
            "values": ["json", "csv", "html", "json-asff"],
            "required": False,
            "default": "json",
        },
        {
            "key": "output",
            "label": "Output Path",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
            "help": "결과 저장 디렉토리/파일 경로",
        },
    ]

    cli_examples: List[str] = [
        "prowler -v",
        "prowler aws",
        "prowler aws --profile default --regions ap-northeast-2",
        "prowler aws --services s3,rds",
        "prowler aws --list-checks",
        "prowler aws --list-services",
        "prowler aws --list-compliance",
        "prowler aws --list-categories",
        "prowler aws --output json --output-directory ./outputs",
        "prowler aws --compliance cis_1.4",
    ]

    return {
        **meta,
        "detail": {
            "about": "Prowler는 멀티클라우드 보안 점검 CLI입니다. 여기서는 실행하지 않고 옵션/예시만 반환합니다.",
            "options": options,
            "cli_examples": cli_examples,
            "use_endpoint": "/api/oss/prowler/use",
            "disclaimer": "※ 본 API는 커맨드를 실제로 실행하지 않으며, 생성된 명령 문자열만 반환합니다.",
        },
    }

def _build_prowler_command(payload: Dict[str, Any]) -> str:
    """프론트의 '사용하기' 시뮬레이션 옵션으로 커맨드 문자열 생성(실행 없음)."""
    provider = payload.get("provider", "aws")
    parts: List[str] = ["prowler", provider]

    profile = payload.get("profile")
    if profile:
        parts += ["--profile", str(profile)]

    region = payload.get("region")
    if region and provider == "aws":
        parts += ["--regions", str(region)]

    list_mode = payload.get("list")
    if list_mode in {"checks", "services", "compliance", "categories"}:
        parts.append(f"--list-{list_mode}")

    def _join_csv(v):
        if isinstance(v, list):
            return ",".join(map(str, v))
        return str(v)

    services = payload.get("services")
    if services:
        parts += ["--services", _join_csv(services)]

    checks = payload.get("checks")
    if checks:
        parts += ["--checks", _join_csv(checks)]

    compliance = payload.get("compliance")
    if compliance:
        parts += ["--compliance", _join_csv(compliance)]

    severity = payload.get("severity")
    if severity:
        parts += ["--severity", str(severity)]

    out_fmt = payload.get("format")
    if out_fmt:
        parts += ["--output", str(out_fmt)]

    out_path = payload.get("output")
    if out_path:
        parts += ["--output-directory", str(out_path)]

    return " ".join(parts)

# ---------- 서비스 API ----------

def get_catalog(q: Optional[str] = None) -> Dict[str, Any]:
    items = list_items()
    if q:
        ql = q.lower()
        items = [
            it for it in items
            if any((str(it.get(k, "")).lower().find(ql) >= 0) for k in ("name", "code", "category", "desc"))
        ]
    return {"items": items}

def get_detail(code: str) -> Dict[str, Any]:
    item = get_item_by_code(code)
    if not item:
        return {"error": 404, "message": f"'{code}' 항목을 찾을 수 없습니다."}

    if code == "prowler":
        return _prowler_detail(item)

    return {
        **item,
        "detail": {
            "about": "이 항목은 아직 상세 템플릿이 없습니다.",
            "use_endpoint": None,
        },
    }

def simulate_use(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    item = get_item_by_code(code)
    if not item:
        return {"error": 404, "message": f"'{code}' 항목을 찾을 수 없습니다."}

    if code != "prowler":
        return {"error": 400, "message": "현재는 prowler만 시뮬레이션을 지원합니다."}

    command = _build_prowler_command(payload or {})
    return {
        "code": code,
        "name": item.get("name"),
        "simulate": True,
        "command": command,
        "note": "이 API는 커맨드 문자열만 반환하며 실제 실행은 하지 않습니다.",
    }

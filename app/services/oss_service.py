# app/services/oss_service.py
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from ..utils.loader import list_items, get_item_by_code, merge

# ---------- 내부 헬퍼 ----------

def _prowler_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    """prowler 세부 정보 템플릿(정적)."""
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
            "label": "Output Path (dir)",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
            "help": "결과 저장 디렉토리. 서버 내부에서 안전 경로로 보정됨.",
        },
        # ----- ⬇ pip-install 관련 옵션(신규) -----
        {
            "key": "pip_install",
            "label": "Auto pip install prowler",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
            "help": "실행 전 prowler가 없으면 pip로 자동 설치",
        },
        {
            "key": "pip_index_url",
            "label": "Pip Index URL",
            "type": "string",
            "required": False,
            "placeholder": "https://pypi.org/simple",
            "help": "사설/미러 인덱스 URL이 있을 경우",
        },
        {
            "key": "pip_extra_args",
            "label": "Pip Extra Args",
            "type": "string",
            "required": False,
            "placeholder": "--no-cache-dir -U",
            "help": "추가 pip 인자(예: 업그레이드/캐시 끄기 등)",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "600",
            "help": "최대 실행 시간(초). 기본 600.",
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
            "about": "Prowler는 멀티클라우드 보안 점검 CLI입니다.",
            "options": options,
            "cli_examples": cli_examples,
            "use_endpoint": "/api/oss/prowler/use",
            "run_endpoint": "/api/oss/prowler/run",
            "disclaimer": "※ 커맨드 실행은 서버에서 수행됩니다. 신뢰된 옵션만 허용됩니다.",
        },
    }

def _join_csv(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, list):
        return ",".join(str(x) for x in v if str(x).strip())
    return str(v)

def _build_prowler_args(payload: Dict[str, Any]) -> List[str]:
    """실행용 인자 리스트(쉘이 아닌 직접 인자) 구성."""
    provider = str(payload.get("provider", "aws")).strip()
    if provider not in {"aws", "azure", "gcp", "kubernetes", "github", "m365", "oci", "nhn"}:
        raise ValueError(f"Unsupported provider: {provider}")

    args: List[str] = ["prowler", provider]

    list_mode = payload.get("list")
    if list_mode in {"checks", "services", "compliance", "categories"}:
        args.append(f"--list-{list_mode}")

    region = payload.get("region")
    if region and provider == "aws":
        args += ["--regions", str(region)]

    services = _join_csv(payload.get("services"))
    if services:
        args += ["--services", services]

    checks = _join_csv(payload.get("checks"))
    if checks:
        args += ["--checks", checks]

    compliance = _join_csv(payload.get("compliance"))
    if compliance:
        args += ["--compliance", compliance]

    severity = payload.get("severity")
    if severity:
        args += ["--severity", str(severity)]

    out_fmt = payload.get("format")
    if out_fmt:
        args += ["--output", str(out_fmt)]

    out_path = payload.get("output")
    if out_path:
        args += ["--output-directory", str(out_path)]

    return args

def _safe_run_dir(base_dir: str = "./runs") -> str:
    ts = time.strftime("%Y%m")
    path = os.path.abspath(os.path.join(base_dir, ts, str(uuid.uuid4())))
    os.makedirs(path, exist_ok=True)
    return path

def _sanitize_subdir(root: str, subdir: Optional[str]) -> str:
    if not subdir:
        return root
    cand = os.path.abspath(os.path.join(root, subdir))
    if not cand.startswith(os.path.abspath(root) + os.sep):
        return root
    os.makedirs(cand, exist_ok=True)
    return cand

def _list_files_under(path: str, max_items: int = 200) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        for dirpath, _, filenames in os.walk(path):
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    stat = os.stat(full)
                    rel = os.path.relpath(full, path)
                    items.append({
                        "path": rel,
                        "size": stat.st_size,
                        "mtime": int(stat.st_mtime),
                    })
                    if len(items) >= max_items:
                        return items
                except OSError:
                    continue
    except Exception:
        pass
    return items

def _build_prowler_command(payload: Dict[str, Any]) -> str:
    return " ".join(shlex.quote(x) for x in _build_prowler_args(payload))

# ---------- pip 설치/검증 헬퍼 ----------

def _pip_install_prowler(index_url: Optional[str] = None, extra_args: Optional[str] = None, timeout: int = 600) -> Dict[str, Any]:
    """
    sys.executable -m pip install prowler [--index-url ...] [extra_args...]
    """
    args = [sys.executable, "-m", "pip", "install", "prowler"]
    if index_url:
        args += ["--index-url", str(index_url)]
    if extra_args:
        # 사용자가 공백으로 나눈 추가 인자 제공 가능
        args += shlex.split(extra_args)

    started = time.time()
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        rc = res.returncode
        stdout = res.stdout or ""
        stderr = res.stderr or ""
    except subprocess.TimeoutExpired as te:
        rc = -1
        stdout = te.stdout or ""
        stderr = (te.stderr or "") + f"\n[ERROR] pip install timeout after {timeout} sec"
    except Exception as e:
        rc = 1
        stdout = ""
        stderr = f"[ERROR] pip install failed: {e}"
    duration_ms = int((time.time() - started) * 1000)

    return {
        "cmd": " ".join(shlex.quote(x) for x in args),
        "rc": rc,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
    }

def _check_prowler_exists() -> Dict[str, Any]:
    """prowler -v 로 존재 확인"""
    try:
        res = subprocess.run(["prowler", "-v"], capture_output=True, text=True, timeout=30)
        return {"exists": res.returncode == 0, "rc": res.returncode, "stdout": res.stdout, "stderr": res.stderr}
    except FileNotFoundError:
        return {"exists": False, "rc": 127, "stdout": "", "stderr": "FileNotFoundError"}
    except Exception as e:
        return {"exists": False, "rc": 1, "stdout": "", "stderr": str(e)}

def ensure_prowler(pip_install: bool, index_url: Optional[str], extra_args: Optional[str]) -> Dict[str, Any]:
    """
    prowler 바이너리 확인 후, 없으면 pip install (선택).
    반환: {checked_before, installed(여부), check_after, pip_log(선택)}
    """
    pre = _check_prowler_exists()
    installed = False
    pip_log = None

    if not pre.get("exists", False) and pip_install:
        pip_log = _pip_install_prowler(index_url=index_url, extra_args=extra_args, timeout=900)
        post = _check_prowler_exists()
        installed = bool(post.get("exists", False))
        return {"checked_before": pre, "installed": installed, "check_after": post, "pip_log": pip_log}

    # 이미 있음 혹은 pip_install=False
    return {"checked_before": pre, "installed": False, "check_after": pre, "pip_log": pip_log}

# ---------- 서비스 API(시뮬레이트) ----------

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

# ---------- 서비스 API(실행) ----------

def run_tool(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    실제 커맨드 실행. stdout/stderr/rc/실행시간/생성파일 목록 + (선행 pip 설치 로그) 반환.
    """
    item = get_item_by_code(code)
    if not item:
        return {"error": 404, "message": f"'{code}' 항목을 찾을 수 없습니다."}
    if code != "prowler":
        return {"error": 400, "message": "현재는 prowler만 실행을 지원합니다."}

    # -------------------- ⬇ pip install (옵션) --------------------
    pip_install_flag = str(payload.get("pip_install", "true")).lower() == "true"
    pip_index_url = payload.get("pip_index_url") or None
    pip_extra_args = payload.get("pip_extra_args") or None
    preinstall_info = ensure_prowler(
        pip_install=pip_install_flag,
        index_url=pip_index_url,
        extra_args=pip_extra_args,
    )
    # 설치 실패해도 일단 계속 진행(사용자가 일부 기능만 쓸 수도 있음)

    # -------------------- 실행 디렉토리/출력 경로 --------------------
    base_run_dir = _safe_run_dir("./runs")
    user_out = payload.get("output")
    out_dir = _sanitize_subdir(base_run_dir, user_out)

    # prowler 인자 생성 (출력 디렉토리 강제)
    payload = dict(payload or {})
    payload["output"] = out_dir
    try:
        args = _build_prowler_args(payload)
    except Exception as e:
        return {"error": 400, "message": f"Invalid options: {e}", "preinstall": preinstall_info}

    # 환경변수 (AWS_PROFILE 등)
    env = os.environ.copy()
    profile = payload.get("profile")
    if profile and payload.get("provider", "aws") == "aws":
        env["AWS_PROFILE"] = str(profile)

    # 타임아웃
    try:
        timeout_sec = int(str(payload.get("timeout_sec", "600")))
    except ValueError:
        timeout_sec = 600

    # 실행
    started = time.time()
    try:
        result = subprocess.run(
            args,
            cwd=base_run_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        rc = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
    except subprocess.TimeoutExpired as te:
        rc = -1
        stdout = te.stdout or ""
        stderr = (te.stderr or "") + f"\n[ERROR] Timeout after {timeout_sec} sec"
    except FileNotFoundError:
        rc = 127
        stdout = ""
        stderr = "[ERROR] prowler 바이너리를 찾을 수 없습니다. PATH 또는 설치 상태를 확인하세요."
    except Exception as e:
        rc = 1
        stdout = ""
        stderr = f"[ERROR] Unexpected: {e}"
    duration_ms = int((time.time() - started) * 1000)

    def _clip(s: str, limit: int = 200_000) -> str:
        if len(s) > limit:
            return s[:limit] + f"\n...[truncated {len(s)-limit} bytes]"
        return s

    files = _list_files_under(out_dir)

    return {
        "code": code,
        "command": " ".join(shlex.quote(x) for x in args),
        "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
        "output_dir": os.path.relpath(out_dir, os.getcwd()),
        "rc": rc,
        "duration_ms": duration_ms,
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
        "files": files,
        "note": "stdout/stderr는 길이 제한으로 잘릴 수 있습니다.",
        "preinstall": preinstall_info,  # ⬅ 설치 전/후 확인 및 pip 로그 포함
    }

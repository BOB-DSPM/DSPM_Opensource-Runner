# ==============================
# file: app/services/oss_service.py
# ==============================
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Callable, Iterable, Tuple
import asyncio
import json
import platform
import shutil
from glob import glob

from ..utils.loader import list_items, get_item_by_code, merge
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────────────────────
# 상수/공통
# ──────────────────────────────────────────────────────────────
LATEST_DIR = "./runs/_latest"
RUNS_ROOT = "./runs"


def _split_vals(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    parts = []
    for p in s.replace(",", " ").split():
        p = p.strip()
        if p:
            parts.append(p)
    return parts


def _log_write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(text)


def _log_write_bytes(path: str, b: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "ab") as f:
        f.write(b)


def _run_with_live_logging(
    args: List[str],
    cwd: Optional[str],
    env: Dict[str, str],
    timeout_sec: int,
    log_path: str,
) -> tuple[int, str, str, int]:
    started = time.time()
    started_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = []
    header.append(f"[START] {started_dt}\n")
    header.append(f"[CWD]   {os.path.abspath(cwd or os.getcwd())}\n")
    header.append(f"[CMD]   {' '.join(shlex.quote(x) for x in args)}\n")
    header.append("-" * 80 + "\n")
    _log_write_text(log_path, "".join(header))

    proc = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    collected_stdout: List[str] = []
    try:
        assert proc.stdout is not None
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            _log_write_text(log_path, line)
            collected_stdout.append(line)

            if timeout_sec and (time.time() - started) > timeout_sec:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                _log_write_text(log_path, f"\n[ERROR] Timeout after {timeout_sec} sec\n")
                break

        rc = proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        rc = -1
        _log_write_text(log_path, f"\n[ERROR] Timeout after {timeout_sec} sec (wait)\n")
    except Exception as e:
        rc = 1
        _log_write_text(log_path, f"\n[ERROR] Unexpected: {e}\n")

    duration_ms = int((time.time() - started) * 1000)
    _log_write_text(
        log_path, "-" * 80 + f"\n[RC] {rc}  [DURATION_MS] {duration_ms}\n"
    )
    stdout_text = "".join(collected_stdout)
    return rc, stdout_text, "", duration_ms


def _join_csv(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, list):
        return ",".join(str(x) for x in v if str(x).strip())
    return str(v)


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
                    items.append(
                        {
                            "path": rel
                            if rel.startswith("outputs/")
                            else f"outputs/{rel}"
                            if path.endswith("outputs")
                            else rel,
                            "size": stat.st_size,
                            "mtime": int(stat.st_mtime),
                        }
                    )
                    if len(items) >= max_items:
                        return items
                except OSError:
                    continue
    except Exception:
        pass
    return items


def _clip(s: str, limit: int = 200_000) -> str:
    if s is None:
        return ""
    if len(s) > limit:
        return s[:limit] + f"\n...[truncated {len(s)-limit} bytes]"
    return s


# ──────────────────────────────────────────────────────────────
# 최근 실행 포인터/결과 관리
# ──────────────────────────────────────────────────────────────
def _record_last_run(code: str, run_dir: str, output_dir: str) -> None:
    """./runs/_latest/<code>.json 에 최근 실행 포인터 저장"""
    try:
        os.makedirs(LATEST_DIR, exist_ok=True)
        data = {
            "code": code,
            "ts": int(time.time()),
            "run_dir": os.path.relpath(run_dir, os.getcwd()),
            "output_dir": os.path.relpath(output_dir, os.getcwd()),
        }
        with open(
            os.path.join(LATEST_DIR, f"{code}.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _load_last_run(code: str) -> Optional[Dict[str, Any]]:
    """최근 실행 포인터를 읽어 output_dir 및 파일 목록을 리턴"""
    try:
        path = os.path.join(LATEST_DIR, f"{code}.json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        out_dir = meta.get("output_dir")
        if not out_dir:
            return None
        out_abs = os.path.abspath(out_dir)
        if not os.path.isdir(out_abs):
            return None
        files = _list_files_under(out_abs)
        meta["files"] = files
        meta["output_dir"] = out_dir  # 상대경로 유지
        return meta
    except Exception:
        return None


def _iter_result_jsons() -> List[Tuple[str, float]]:
    """
    runs/**/result.json 파일들을 (경로, mtime) 리스트로 반환 (최신순).
    """
    results: List[Tuple[str, float]] = []
    for path in glob(os.path.join(RUNS_ROOT, "*", "*", "result.json")):
        try:
            mt = os.path.getmtime(path)
            results.append((path, mt))
        except OSError:
            continue
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def find_latest_result_for_code(code: str) -> Optional[Dict[str, Any]]:
    """
    요구사항 1:
    - result.json에서 최근 실행을 확인하여 저장된 위치(run_dir/output_dir 포함)와 메타를 가져온다.
    우선순위: runs/_latest 포인터 → runs/**/result.json 스캔
    """
    # 1) 포인터 파일 우선
    pointer = _load_last_run(code)
    if pointer:
        # 포인터 기반으로 같은 run_dir의 result.json을 시도
        rd = pointer.get("run_dir")
        if rd:
            res_path = os.path.join(rd, "result.json")
            if os.path.isfile(res_path):
                try:
                    data = json.loads(open(res_path, "r", encoding="utf-8").read())
                    return data
                except Exception:
                    pass
        # 포인터만이라도 기초 메타 구성
        return {
            "code": code,
            "run_dir": pointer.get("run_dir"),
            "output_dir": pointer.get("output_dir"),
            "files": pointer.get("files", []),
            "note": "latest pointer를 기반으로 반환(결과 파일 파싱 실패 시)",
        }

    # 2) 전체 runs/**/result.json 스캔 (최신부터)
    for res_path, _mt in _iter_result_jsons():
        try:
            with open(res_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("code") == code:
                return data
        except Exception:
            continue
    return None


def collect_executed_contents(
    run_dir: Optional[str], output_dir: Optional[str], code: Optional[str]
) -> Dict[str, Any]:
    """
    요구사항 2:
    - '해당 파일에서 실행했던 내용들'을 모두 가져온다.
    해석:
      * 공통: outputs/log.txt 전체(클립) 및 실행 커맨드(result.json 내 command는 상위에서 제공됨)
      * custodian: outputs/policies.yml(있으면) 원문도 포함
      * outputs 하위 소형 텍스트 산출물도 일부 수집
    """
    out: Dict[str, Any] = {}
    try:
        if not run_dir or not output_dir:
            return out
        # 경로 보정
        rd_abs = os.path.abspath(run_dir)
        if os.path.isabs(output_dir):
            out_abs = output_dir
        elif output_dir.startswith("runs/"):
            out_abs = os.path.abspath(output_dir)
        else:
            out_abs = os.path.abspath(os.path.join(run_dir, output_dir))

        # 로그
        log_path = os.path.join(out_abs, "log.txt")
        if os.path.isfile(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                out["log_txt"] = _clip(f.read())

        # custodian 정책 원문
        if str(code).lower() == "custodian":
            pol1 = os.path.join(out_abs, "policies.yml")
            pol2 = os.path.join(out_abs, "policy.yml")
            for p in (pol1, pol2):
                if os.path.isfile(p):
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        out["policy_yaml"] = _clip(f.read(), 500_000)
                    break

        # outputs 하위 텍스트 산출물들(소형)도 일부 수집 (최대 N개, 각 100KB)
        collected_texts: Dict[str, str] = {}
        MAX_FILES, MAX_BYTES = 10, 100_000
        for dirpath, _, filenames in os.walk(out_abs):
            for name in filenames:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, rd_abs)
                if os.path.splitext(name)[1].lower() in {
                    ".txt",
                    ".log",
                    ".json",
                    ".csv",
                    ".yml",
                    ".yaml",
                }:
                    try:
                        sz = os.path.getsize(path)
                        if sz <= MAX_BYTES:
                            with open(
                                path, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                collected_texts[rel] = f.read()
                            if len(collected_texts) >= MAX_FILES:
                                break
                    except Exception:
                        continue
            if len(collected_texts) >= MAX_FILES:
                break
        if collected_texts:
            out["small_text_artifacts"] = collected_texts

    except Exception:
        pass
    return out


# ──────────────────────────────────────────────────────────────
# 설치/체크 유틸
# ──────────────────────────────────────────────────────────────
def _check_bin_exists(bin_name: str) -> Dict[str, Any]:
    try:
        res = subprocess.run(
            [bin_name, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        exists = (res.returncode == 0) or bool(res.stdout or res.stderr)
        return {
            "exists": exists,
            "rc": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except FileNotFoundError:
        return {
            "exists": False,
            "rc": 127,
            "stdout": "",
            "stderr": "FileNotFoundError",
        }
    except Exception as e:
        return {"exists": False, "rc": 1, "stdout": "", "stderr": str(e)}


def _pip_install(
    pkg: str,
    index_url: Optional[str],
    extra_args: Optional[str],
    timeout: int = 900,
) -> Dict[str, Any]:
    args = [sys.executable, "-m", "pip", "install", pkg]
    if index_url:
        args += ["--index-url", str(index_url)]
    if extra_args:
        args += shlex.split(extra_args)
    started = time.time()
    try:
        res = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        rc = res.returncode
        stdout, stderr = res.stdout or "", res.stderr or ""
    except subprocess.TimeoutExpired as te:
        rc = -1
        stdout = te.stdout or ""
        stderr = (te.stderr or "") + (
            f"\n[ERROR] pip install timeout after {timeout} sec"
        )
    except Exception as e:
        rc, stdout, stderr = 1, "", f"[ERROR] pip install failed: {e}"
    duration_ms = int((time.time() - started) * 1000)
    return {
        "cmd": " ".join(shlex.quote(x) for x in args),
        "rc": rc,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
    }


def _run_install_cmds(
    cmds: Iterable[List[str]],
    cwd: str | None = None,
    env: dict | None = None,
    timeout: int = 600,
):
    logs = []
    for cmd in cmds:
        try:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            logs.append(
                {
                    "cmd": " ".join(shlex.quote(x) for x in cmd),
                    "rc": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                }
            )
            if res.returncode == 0:
                return True, logs
        except Exception as e:
            logs.append(
                {
                    "cmd": " ".join(shlex.quote(x) for x in cmd),
                    "rc": -1,
                    "stdout": "",
                    "stderr": str(e),
                }
            )
    return False, logs


def ensure_tool_extended(
    bin_name: str,
    pip_pkg: Optional[str],
    pip_install: bool,
    index_url: Optional[str],
    extra_args: Optional[str],
    install_cmds: Optional[Iterable[Iterable[str]]] = None,
) -> Dict[str, Any]:
    pre = _check_bin_exists(bin_name)
    installed, pip_log, bin_install_log = False, None, None

    if not pre.get("exists", False):
        if pip_install and pip_pkg:
            pip_log = _pip_install(
                pip_pkg, index_url, extra_args, timeout=900
            )
            post = _check_bin_exists(bin_name)
            installed = bool(post.get("exists", False))
            if installed:
                return {
                    "checked_before": pre,
                    "installed": True,
                    "check_after": post,
                    "pip_log": pip_log,
                    "bin_install_log": None,
                }

        if install_cmds:
            ok, bin_install_log = _run_install_cmds(
                install_cmds, timeout=900
            )
            post = _check_bin_exists(bin_name)
            installed = bool(post.get("exists", False))
            return {
                "checked_before": pre,
                "installed": installed,
                "check_after": post,
                "pip_log": pip_log,
                "bin_install_log": bin_install_log,
            }

    return {
        "checked_before": pre,
        "installed": False,
        "check_after": pre,
        "pip_log": pip_log,
        "bin_install_log": bin_install_log,
    }


# ──────────────────────────────────────────────────────────────
# detail 템플릿
# ──────────────────────────────────────────────────────────────
def _detail_template(
    defaults: Dict[str, Any],
    options: List[Dict[str, Any]],
    cli_examples: List[str],
    run_endpoint_code: str,
) -> Dict[str, Any]:
    meta = defaults
    return {
        **meta,
        "detail": {
            "about": meta.get("desc") or "",
            "options": options,
            "cli_examples": cli_examples,
            "use_endpoint": f"/api/oss/{run_endpoint_code}/use",
            "run_endpoint": f"/api/oss/{run_endpoint_code}/run",
            "disclaimer": "※ 커맨드 실행은 서버에서 수행됩니다. 신뢰된 옵션만 허용됩니다.",
        },
    }


# ──────────────────────────────────────────────────────────────
# Prowler
# ──────────────────────────────────────────────────────────────
def _prowler_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "prowler",
            "name": "Prowler",
            "category": "cloud-security",
            "tags": ["aws", "security", "audit", "cli"],
            "homepage": "https://github.com/prowler-cloud/prowler",
            "desc": "AWS 등 클라우드 보안 점검 CLI",
            "license": "Apache-2.0",
        },
        base or {},
    )
    options = [
        {
            "key": "provider",
            "label": "Provider",
            "type": "enum",
            "values": [
                "aws",
                "azure",
                "gcp",
                "kubernetes",
                "github",
                "m365",
                "oci",
                "nhn",
            ],
            "required": True,
            "default": "aws",
        },
        {
            "key": "profile",
            "label": "AWS CLI Profile",
            "type": "string",
            "required": False,
            "placeholder": "default",
            "visible_if": {"provider": "aws"},
        },
        {
            "key": "region",
            "label": "AWS Region",
            "type": "string",
            "required": False,
            "placeholder": "ap-northeast-2",
            "visible_if": {"provider": "aws"},
        },
        {
            "key": "list",
            "label": "List Mode",
            "type": "enum",
            "values": ["checks", "services", "compliance", "categories"],
            "required": False,
        },
        {
            "key": "services",
            "label": "Services",
            "type": "array[string]",
            "required": False,
        },
        {
            "key": "checks",
            "label": "Checks",
            "type": "array[string]",
            "required": False,
        },
        {
            "key": "compliance",
            "label": "Compliance Frameworks",
            "type": "array[string]",
            "required": False,
        },
        {
            "key": "severity",
            "label": "Severity",
            "type": "enum",
            "values": [
                "informational",
                "low",
                "medium",
                "high",
                "critical",
            ],
            "required": False,
        },
        {
            "key": "output_formats",
            "label": "Output Formats",
            "type": "array[string]",
            "required": False,
            "placeholder": "csv,json-ocsf,html",
        },
        {
            "key": "format",
            "label": "(Legacy) Single Format",
            "type": "enum",
            "values": ["json", "csv", "html", "json-asff", "json-ocsf"],
            "required": False,
        },
        {
            "key": "output",
            "label": "Output Path (dir)",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {
            "key": "pip_index_url",
            "label": "Pip Index URL",
            "type": "string",
            "required": False,
        },
        {
            "key": "pip_extra_args",
            "label": "Pip Extra Args",
            "type": "string",
            "required": False,
            "placeholder": "--no-cache-dir -U",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "600",
        },
    ]
    cli_examples = [
        "prowler -v",
        "prowler aws --regions ap-northeast-2",
        "prowler aws --list-checks",
        "prowler aws --output json --output-directory ./outputs",
    ]
    return _detail_template(defaults, options, cli_examples, "prowler")


def _build_prowler_args(payload: Dict[str, Any]) -> List[str]:
    provider = str(payload.get("provider", "aws")).strip()
    if provider not in {
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "github",
        "m365",
        "oci",
        "nhn",
    }:
        raise ValueError(f"Unsupported provider: {provider}")
    args: List[str] = ["prowler", provider]

    if (m := payload.get("list")) in {
        "checks",
        "services",
        "compliance",
        "categories",
    }:
        args += [f"--list-{m}"]

    if provider == "aws" and (r := payload.get("region")):
        args += ["--region", str(r)]

    services = _split_vals(payload.get("services"))
    if services:
        args += ["--service"] + services

    checks = _split_vals(payload.get("checks"))
    if checks:
        args += ["--check"] + checks

    compliances = _split_vals(payload.get("compliance"))
    if compliances:
        args += ["--compliance"] + compliances

    if (sev := payload.get("severity")):
        sevs = _split_vals(sev)
        if sevs:
            args += ["--severity"] + sevs

    ofmts = payload.get("output_formats")
    if ofmts:
        vals = _split_vals(ofmts)
        if vals:
            args += ["--output-formats"] + vals
    elif (fmt := payload.get("format")):
        args += ["--output-formats", str(fmt)]

    if (out := payload.get("output")):
        args += ["--output-directory", str(out)]
    return args


# ──────────────────────────────────────────────────────────────
# Checkov
# ──────────────────────────────────────────────────────────────
def _checkov_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "checkov",
            "name": "Checkov",
            "category": "iac-security",
            "tags": [
                "terraform",
                "cloudformation",
                "kubernetes",
                "helm",
                "iac",
                "sast",
            ],
            "homepage": "https://github.com/bridgecrewio/checkov",
            "desc": "IaC 정적 분석(SAST)으로 보안/컴플라이언스 위반을 탐지",
            "license": "Apache-2.0",
        },
        base or {},
    )
    options = [
        {
            "key": "directory",
            "label": "Target Directory",
            "type": "string",
            "required": True,
            "placeholder": "./iac",
        },
        {
            "key": "framework",
            "label": "Framework",
            "type": "enum",
            "values": [
                "terraform",
                "cloudformation",
                "kubernetes",
                "helm",
                "arm",
                "bicep",
                "serverless",
            ],
            "required": False,
        },
        {
            "key": "quiet",
            "label": "Quiet",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {
            "key": "skip_download",
            "label": "Skip Download",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {
            "key": "output",
            "label": "Output Format",
            "type": "enum",
            "values": ["json", "junitxml", "sarif", "cli"],
            "required": False,
            "default": "json",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "300",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {"key": "pip_index_url", "type": "string", "required": False},
        {"key": "pip_extra_args", "type": "string", "required": False},
    ]
    cli = ["checkov -d ./iac -o json --quiet"]
    return _detail_template(defaults, options, cli, "checkov")


def _build_checkov_args(payload: Dict[str, Any]) -> List[str]:
    if not payload.get("directory"):
        raise ValueError("directory is required")
    args = ["checkov", "-d", str(payload["directory"])]
    if (fw := payload.get("framework")):
        args += ["--framework", str(fw)]
    if str(payload.get("quiet", "true")).lower() == "true":
        args += ["--quiet"]
    if str(payload.get("skip_download", "true")).lower() == "true":
        args += ["--skip-download"]
    args += ["-o", str(payload.get("output", "json"))]
    return args


# ──────────────────────────────────────────────────────────────
# Trivy
# ──────────────────────────────────────────────────────────────
def _trivy_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "trivy",
            "name": "Trivy",
            "category": "container-security",
            "tags": [
                "container",
                "kubernetes",
                "sbom",
                "iac",
                "vulnerability",
            ],
            "homepage": "https://github.com/aquasecurity/trivy",
            "desc": "컨테이너/FS/K8s/IaC 취약점/오탑재 스캐너",
            "license": "Apache-2.0",
        },
        base or {},
    )
    options = [
        {
            "key": "mode",
            "label": "Scan Mode",
            "type": "enum",
            "values": ["image", "fs", "repo", "k8s"],
            "required": True,
            "default": "image",
        },
        {
            "key": "target",
            "label": "Target (image path/dir/repo)",
            "type": "string",
            "required": True,
            "placeholder": "nginx:latest or ./",
        },
        {
            "key": "format",
            "label": "Output Format",
            "type": "enum",
            "values": ["table", "json", "sarif", "cyclonedx"],
            "required": False,
            "default": "json",
        },
        {
            "key": "severity",
            "label": "Severity filter",
            "type": "string",
            "required": False,
            "placeholder": "CRITICAL,HIGH",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "600",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install (via pipx)",
            "type": "enum",
            "values": ["false"],
            "required": False,
            "default": "false",
        },
    ]
    cli = ["trivy image nginx:latest --format json"]
    return _detail_template(defaults, options, cli, "trivy")


def _build_trivy_args(payload: Dict[str, Any]) -> List[str]:
    mode = str(payload.get("mode", "image"))
    target = payload.get("target")
    if not target:
        raise ValueError("target is required")
    args = ["trivy", mode, str(target)]
    if (fmt := payload.get("format")):
        args += ["--format", str(fmt)]
    if (sev := payload.get("severity")):
        args += ["--severity", str(sev)]
    return args


# ──────────────────────────────────────────────────────────────
# Gitleaks
# ──────────────────────────────────────────────────────────────
def _gitleaks_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "gitleaks",
            "name": "Gitleaks",
            "category": "secrets-detection",
            "tags": ["secrets", "git", "ci", "detection"],
            "homepage": "https://github.com/gitleaks/gitleaks",
            "desc": "Git 리포/디렉터리에서 비밀키/자격증명 유출 탐지",
            "license": "MIT",
        },
        base or {},
    )
    options = [
        {
            "key": "source",
            "label": "Scan Source (path or git url)",
            "type": "string",
            "required": True,
            "placeholder": "./ or file://./repo",
        },
        {
            "key": "report",
            "label": "Report Path",
            "type": "string",
            "required": False,
            "placeholder": "./outputs/gitleaks.json",
        },
        {
            "key": "format",
            "label": "Format",
            "type": "enum",
            "values": ["json", "sarif", "csv", "junit"],
            "required": False,
            "default": "json",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "300",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["false"],
            "required": False,
            "default": "false",
        },
    ]
    cli = ["gitleaks detect -s . -f json -r ./outputs/gitleaks.json"]
    return _detail_template(defaults, options, cli, "gitleaks")


def _build_gitleaks_args(payload: Dict[str, Any]) -> List[str]:
    src = payload.get("source")
    if not src:
        raise ValueError("source is required")
    args = ["gitleaks", "detect", "-s", str(src)]
    fmt = str(payload.get("format", "json"))
    args += ["-f", fmt]
    if (rp := payload.get("report")):
        args += ["-r", str(rp)]
    return args


# ──────────────────────────────────────────────────────────────
# Cloud Custodian
# ──────────────────────────────────────────────────────────────
def _custodian_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "custodian",
            "name": "Cloud Custodian",
            "category": "cloud-governance",
            "tags": ["aws", "azure", "gcp", "policy-as-code", "remediation"],
            "homepage": "https://github.com/cloud-custodian/cloud-custodian",
            "desc": "정책-as-코드 기반 감지/자동 시정 및 증적",
            "license": "Apache-2.0",
        },
        base or {},
    )
    options = [
        {
            "key": "policy",
            "label": "Policy YAML Path (optional)",
            "type": "string",
            "required": False,
            "placeholder": "./policies.yml",
        },
        {
            "key": "policy_inline",
            "label": "Policy YAML (inline)",
            "type": "string",
            "required": False,
            "placeholder": "(텍스트로 붙여넣기)",
        },
        {
            "key": "output",
            "label": "Output Dir",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
            "default": "./outputs",
        },
        {
            "key": "region",
            "label": "Region (aws)",
            "type": "string",
            "required": False,
            "placeholder": "ap-northeast-2",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "1200",
            "default": "900",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {"key": "pip_index_url", "type": "string", "required": False},
        {"key": "pip_extra_args", "type": "string", "required": False},
    ]
    cli = ["custodian run -s ./outputs policies.yml"]
    return _detail_template(defaults, options, cli, "custodian")


def _build_custodian_args(payload: Dict[str, Any]) -> List[str]:
    if not payload.get("policy"):
        raise ValueError("policy is required")
    args = [
        "custodian",
        "run",
        "-s",
        str(payload.get("output", "./outputs")),
        str(payload["policy"]),
    ]
    if (r := payload.get("region")):
        args += ["-r", str(r)]
    return args


def _ensure_inline_policy_to_outdir(
    payload: Dict[str, Any], out_dir: str
) -> Dict[str, Any]:
    inline = (
        payload.get("policy_inline")
        or payload.get("policy_text")
        or payload.get("policy_yaml")
    )
    if inline:
        policy_abs = os.path.abspath(os.path.join(out_dir, "policies.yml"))
        os.makedirs(os.path.dirname(policy_abs), exist_ok=True)
        with open(
            policy_abs, "w", encoding="utf-8", errors="ignore"
        ) as f:
            f.write(str(inline))
        payload["policy"] = policy_abs
        return payload
    if (p := payload.get("policy")) and not os.path.isabs(p):
        payload["policy"] = os.path.abspath(os.path.join(out_dir, p))
    return payload


# ──────────────────────────────────────────────────────────────
# Steampipe
# ──────────────────────────────────────────────────────────────
def _steampipe_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "steampipe",
            "name": "Steampipe (mods)",
            "category": "cloud-compliance",
            "tags": ["sql", "aws", "compliance", "report"],
            "homepage": "https://steampipe.io",
            "desc": "클라우드를 SQL로 질의, 모드로 컴플라이언스 리포트 생성",
            "license": "AGPL-3.0",
        },
        base or {},
    )
    options = [
        {
            "key": "mod",
            "label": "Mod (e.g., turbot/steampipe-mod-aws-compliance)",
            "type": "string",
            "required": True,
            "default": "turbot/steampipe-mod-aws-compliance",
            "help": "GitHub org/repo 형태 권장. 예) turbot/steampipe-mod-aws-compliance",
        },
        {
            "key": "benchmark",
            "label": "Benchmark (optional)",
            "type": "string",
            "required": False,
            "placeholder": "benchmark.cis_v200",
        },
        {
            "key": "output",
            "label": "Output Dir (reports)",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
            "default": "./outputs",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "1200",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["false"],
            "required": False,
            "default": "false",
        },
    ]
    cli = ["steampipe check all --export"]
    return _detail_template(defaults, options, cli, "steampipe")


def _build_steampipe_args(payload: Dict[str, Any]) -> List[str]:
    mod = payload.get("mod")
    if not mod:
        raise ValueError("mod is required")

    # turbot/steampipe-mod-aws-compliance → github.com/turbot/steampipe-mod-aws-compliance 형태로 보정
    mod_str = str(mod).strip()
    if not mod_str.startswith("github.com/"):
        mod_str = f"github.com/{mod_str}"

    args = ["steampipe", "check"]

    # benchmark 지정 시: steampipe check benchmark.cis_v200
    # 없으면: steampipe check all
    if (bm := payload.get("benchmark")):
        args += [str(bm)]
    else:
        args += ["all"]

    # export 디렉터리 지정 (없으면 ./outputs)
    out = payload.get("output") or "./outputs"
    args += ["--export", str(out)]

    # mod 지정
    args += ["--mod", mod_str]

    return args


# ──────────────────────────────────────────────────────────────
# Scout Suite
# ──────────────────────────────────────────────────────────────
def _scout_detail(base: Dict[str, Any]) -> Dict[str, Any]:
    defaults = merge(
        {
            "code": "scout",
            "name": "Scout Suite",
            "category": "cloud-security",
            "tags": ["aws", "azure", "gcp", "assessment", "report"],
            "homepage": "https://github.com/nccgroup/ScoutSuite",
            "desc": "멀티클라우드 구성 점검 후 HTML 리포트 생성",
            "license": "GPL-2.0",
        },
        base or {},
    )
    options = [
        {
            "key": "provider",
            "label": "Provider",
            "type": "enum",
            "values": ["aws", "azure", "gcp"],
            "required": True,
            "default": "aws",
        },
        {
            "key": "profile",
            "label": "AWS CLI Profile",
            "type": "string",
            "required": False,
            "placeholder": "default",
            "visible_if": {"provider": "aws"},
        },
        {
            "key": "output",
            "label": "Output Dir",
            "type": "string",
            "required": False,
            "placeholder": "./outputs",
        },
        {
            "key": "timeout_sec",
            "label": "Timeout (sec)",
            "type": "string",
            "required": False,
            "placeholder": "1800",
        },
        {
            "key": "pip_install",
            "label": "Auto pip install",
            "type": "enum",
            "values": ["true", "false"],
            "required": False,
            "default": "true",
        },
        {"key": "pip_index_url", "type": "string", "required": False},
        {"key": "pip_extra_args", "type": "string", "required": False},
    ]
    cli = ["scout aws --report-dir ./outputs"]
    return _detail_template(defaults, options, cli, "scout")


def _build_scout_args(payload: Dict[str, Any]) -> List[str]:
    provider = str(payload.get("provider", "aws"))
    if provider not in {"aws", "azure", "gcp"}:
        raise ValueError("Unsupported provider")
    args = ["scout", provider]
    if (out := payload.get("output")):
        args += ["--report-dir", str(out)]
    return args


# ──────────────────────────────────────────────────────────────
# 카탈로그/디테일/시뮬
# ──────────────────────────────────────────────────────────────
def get_catalog(q: Optional[str] = None) -> Dict[str, Any]:
    items = list_items()
    if q:
        ql = q.lower()
        items = [
            it
            for it in items
            if any(
                (
                    str(it.get(k, "")).lower().find(ql) >= 0
                    for k in ("name", "code", "category", "desc")
                )
            )
        ]
    return {"items": items}


def get_detail(code: str) -> Dict[str, Any]:
    item = get_item_by_code(code)
    if not item:
        return {
            "error": 404,
            "message": f"'{code}' 항목을 찾을 수 없습니다.",
        }
    DETAIL = {
        "prowler": _prowler_detail,
        "checkov": _checkov_detail,
        "trivy": _trivy_detail,
        "gitleaks": _gitleaks_detail,
        "custodian": _custodian_detail,
        "steampipe": _steampipe_detail,
        "scout": _scout_detail,
    }
    base = (
        DETAIL[code](item)
        if code in DETAIL
        else {
            **item,
            "detail": {
                "about": "이 항목은 아직 상세 템플릿이 없습니다.",
                "use_endpoint": None,
            },
        }
    )
    # ▼ 최근 실행 정보 주입 (포인터 기반 요약)
    recent = _load_last_run(code)
    if recent:
        base["recent"] = recent
    return base


def _build_command_for(code: str, payload: Dict[str, Any]) -> List[str]:
    BUILDERS: Dict[str, Callable[[Dict[str, Any]], List[str]]] = {
        "prowler": _build_prowler_args,
        "checkov": _build_checkov_args,
        "trivy": _build_trivy_args,
        "gitleaks": _build_gitleaks_args,
        "custodian": _build_custodian_args,
        "steampipe": _build_steampipe_args,
        "scout": _build_scout_args,
    }
    if code not in BUILDERS:
        raise ValueError(f"Unsupported tool: {code}")
    return BUILDERS[code](payload)


# ──────────────────────────────────────────────────────────────
# TOOLS 레지스트리
# ──────────────────────────────────────────────────────────────
TOOLS: Dict[str, Dict[str, Any]] = {
    "prowler": {"bin": "prowler", "pip": "prowler", "install_cmds": None},
    "checkov": {"bin": "checkov", "pip": "checkov", "install_cmds": None},
    "trivy": {
        "bin": "trivy",
        "pip": None,
        "install_cmds": [
            ["sudo", "apt", "update"],
            ["sudo", "apt", "install", "-y", "trivy"],
        ],
    },
    "gitleaks": {
        "bin": "gitleaks",
        "pip": None,
        "install_cmds": [
            ["sudo", "apt", "update"],
            ["sudo", "apt", "install", "-y", "gitleaks"],
        ],
    },
    "custodian": {"bin": "custodian", "pip": "c7n", "install_cmds": None},
    "steampipe": {"bin": "steampipe", "pip": None, "install_cmds": []},
    "scout": {"bin": "scout", "pip": "ScoutSuite", "install_cmds": None},
}


# ──────────────────────────────────────────────────────────────
# 시뮬레이트
# ──────────────────────────────────────────────────────────────
def simulate_use(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    item = get_item_by_code(code)
    if not item:
        return {
            "error": 404,
            "message": f"'{code}' 항목을 찾을 수 없습니다.",
        }
    try:
        cmd_list = _build_command_for(code, payload or {})
    except Exception as e:
        return {"error": 400, "message": f"Invalid options: {e}"}
    command = " ".join(shlex.quote(x) for x in cmd_list)
    return {
        "code": code,
        "name": item.get("name"),
        "simulate": True,
        "command": command,
        "note": "명령만 생성, 실행은 하지 않음",
    }


# ──────────────────────────────────────────────────────────────
# 동기 실행 (공통)
# ──────────────────────────────────────────────────────────────
def run_tool(code: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    # custodian은 별도 루틴
    if code == "custodian":
        return _run_custodian_with_payload(payload)

    item = get_item_by_code(code)
    if not item:
        return {
            "error": 404,
            "message": f"'{code}' 항목을 찾을 수 없습니다.",
        }

    base_run_dir = _safe_run_dir("./runs")
    out_dir = _sanitize_subdir(base_run_dir, payload.get("output"))
    payload = dict(payload or {})
    if "output" in payload and payload["output"]:
        payload["output"] = out_dir

    pip_install_flag = (
        str(payload.get("pip_install", "true")).lower() == "true"
    )
    pip_index_url = payload.get("pip_index_url") or None
    pip_extra_args = payload.get("pip_extra_args") or None

    if code not in TOOLS:
        return {"error": 400, "message": f"Unsupported tool: {code}"}
    tool_meta = TOOLS[code]
    bin_name, pip_pkg, install_cmds = (
        tool_meta["bin"],
        tool_meta.get("pip"),
        tool_meta.get("install_cmds"),
    )

    preinstall_info = ensure_tool_extended(
        bin_name,
        pip_pkg,
        pip_install_flag,
        pip_index_url,
        pip_extra_args,
        install_cmds=install_cmds,
    )

    env = os.environ.copy()
    if payload.get("profile"):
        env["AWS_PROFILE"] = str(payload["profile"])

    try:
        timeout_sec = int(str(payload.get("timeout_sec", "600")))
    except ValueError:
        timeout_sec = 600

    try:
        args = _build_command_for(code, payload)
    except Exception as e:
        return {
            "error": 400,
            "message": f"Invalid options: {e}",
            "preinstall": preinstall_info,
        }

    log_path = os.path.join(out_dir, "log.txt")
    rc, stdout_text, stderr_text, duration_ms = _run_with_live_logging(
        args=args,
        cwd=base_run_dir,
        env=env,
        timeout_sec=timeout_sec,
        log_path=log_path,
    )

    files = _list_files_under(out_dir)

    # ▼ 최근 실행 포인터 저장
    _record_last_run(code, base_run_dir, out_dir)

    # result.json 저장 (최신 탐색 편의를 위해)
    try:
        result_path = os.path.join(base_run_dir, "result.json")
        payload_redacted = {
            k: v
            for k, v in (payload or {}).items()
            if k not in {"policy_inline", "policy_text", "policy_yaml"}
        }
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "code": code,
                    "command": " ".join(shlex.quote(x) for x in args),
                    "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
                    "output_dir": os.path.relpath(out_dir, os.getcwd()),
                    "rc": rc,
                    "duration_ms": duration_ms,
                    "stdout": _clip(stdout_text),
                    "stderr": _clip(stderr_text),
                    "files": files,
                    "note": "stdout/stderr는 길이 제한으로 잘릴 수 있습니다.",
                    "preinstall": preinstall_info,
                    "payload": payload_redacted,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        pass

    return {
        "code": code,
        "command": " ".join(shlex.quote(x) for x in args),
        "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
        "output_dir": os.path.relpath(out_dir, os.getcwd()),
        "rc": rc,
        "duration_ms": duration_ms,
        "stdout": _clip(stdout_text),
        "stderr": _clip(stderr_text),
        "files": files,
        "note": "stdout/stderr는 길이 제한으로 잘릴 수 있습니다.",
        "preinstall": preinstall_info,
    }


# ──────────────────────────────────────────────────────────────
# 스트리밍 실행
# ──────────────────────────────────────────────────────────────
async def _aiter_stream_popen(
    cmd: list[str],
    cwd: str | None = None,
    env: dict | None = None,
    timeout: int | None = None,
):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        start = time.time()
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield line
            if timeout and (time.time() - start) > timeout:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                yield f"\n[ERROR] Timeout after {timeout} sec\n".encode()
                break
        rc = await proc.wait()
        yield f"\n[RC] {rc}\n".encode()
    except Exception as e:
        yield f"\n[ERROR] {e}\n".encode()


async def iter_run_stream(code: str, payload: Dict[str, Any]):
    item = get_item_by_code(code)
    if not item:
        yield b'{"error":404,"message":"item not found"}\n'
        return

    base_run_dir = _safe_run_dir("./runs")
    out_dir = _sanitize_subdir(base_run_dir, payload.get("output"))
    payload = dict(payload or {})
    if payload.get("output"):
        payload["output"] = out_dir

    try:
        timeout_sec = int(str(payload.get("timeout_sec", "600")))
    except ValueError:
        timeout_sec = 600
    env = os.environ.copy()
    if payload.get("profile"):
        env["AWS_PROFILE"] = str(payload["profile"])

    if code not in TOOLS:
        yield b'{"error":400,"message":"unsupported tool"}\n'
        return
    tool_meta = TOOLS[code]
    bin_name, pip_pkg, install_cmds = (
        tool_meta["bin"],
        tool_meta.get("pip"),
        tool_meta.get("install_cmds"),
    )

    pip_install_flag = (
        str(payload.get("pip_install", "true")).lower() == "true"
    )
    pip_index_url = payload.get("pip_index_url") or None
    pip_extra_args = payload.get("pip_extra_args") or None

    # 0) OS 패키지 설치 경로(trivy/gitleaks 등)
    if install_cmds:
        yield b"\n===== [STEP] ensure tool (apt/etc) =====\n"
        for cmd in install_cmds:
            async for chunk in _aiter_stream_popen(
                list(cmd), env=env, timeout=900
            ):
                yield chunk
        chk = _check_bin_exists(bin_name)
        yield (
            f"\n[check_after] exists={chk.get('exists')} rc={chk.get('rc')}\n"
        ).encode()

    # 1) pip 기반 설치 경로(checkov/custodian/scout 등)도 스트리밍에서 보장
    if (not install_cmds) and pip_pkg:
        yield b"\n===== [STEP] ensure tool (pip) =====\n"
        info = ensure_tool_extended(
            bin_name=bin_name,
            pip_pkg=pip_pkg,
            pip_install=pip_install_flag,
            index_url=pip_index_url,
            extra_args=pip_extra_args,
            install_cmds=None,
        )
        yield (
            json.dumps({"preinstall": info}, ensure_ascii=False) + "\n"
        ).encode()

    # 2) 최종 실행 파일 확인(shutil.which) 및 해석된 경로 사용
    resolved = shutil.which(bin_name)
    if not resolved:
        msg = (
            f"'{bin_name}' executable not found in PATH after ensure. "
            f"Please check installation."
        )
        yield (
            f'\n{{"error":127,"message":"{msg}"}}\n'.encode()
        )
        return

    yield b"\n===== [STEP] check tool =====\n"
    ver_cmd = (
        [resolved, "version"] if bin_name == "custodian" else [resolved, "--version"]
    )
    async for chunk in _aiter_stream_popen(ver_cmd, env=env, timeout=60):
        yield chunk

    # 인라인 YAML → policies.yml 저장
    if code == "custodian":
        payload = _ensure_inline_policy_to_outdir(payload, out_dir)

    try:
        args = _build_command_for(code, payload)
    except Exception as e:
        yield (
            f'\n{{"error":400,"message":"Invalid options: {e}"}}\n'.encode()
        )
        return

    yield b"\n===== [STEP] run =====\n"
    # 실행 시에도 해석된 경로 사용
    args[0] = resolved
    yield (f"$ {' '.join(shlex.quote(x) for x in args)}\n").encode()
    start_ts = time.time()
    async for chunk in _aiter_stream_popen(
        args, cwd=base_run_dir, env=env, timeout=timeout_sec
    ):
        yield chunk
    duration_ms = int((time.time() - start_ts) * 1000)

    files = _list_files_under(out_dir)

    # ▼ 최근 실행 포인터 저장
    _record_last_run(code, base_run_dir, out_dir)

    # result.json 저장 (스트리밍 모드도 동일하게)
    try:
        result_path = os.path.join(base_run_dir, "result.json")
        payload_redacted = {
            k: v
            for k, v in (payload or {}).items()
            if k not in {"policy_inline", "policy_text", "policy_yaml"}
        }
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "code": code,
                    "command": " ".join(shlex.quote(x) for x in args),
                    "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
                    "output_dir": os.path.relpath(out_dir, os.getcwd()),
                    "rc": None,  # 스트림에선 RC를 tail에서 제공하므로 생략/None
                    "duration_ms": duration_ms,
                    "stdout": "",
                    "stderr": "",
                    "files": files,
                    "note": "stream run summary",
                    "preinstall": None,
                    "payload": payload_redacted,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        pass

    tail = {
        "summary": {
            "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
            "output_dir": os.path.relpath(out_dir, os.getcwd()),
            "duration_ms": duration_ms,
            "files": files,
        }
    }
    yield b"\n===== [STEP] summary =====\n"
    yield (json.dumps(tail, ensure_ascii=False) + "\n").encode()


# ──────────────────────────────────────────────────────────────
# Custodian 전용 동기 실행
# ──────────────────────────────────────────────────────────────
def _run_custodian_with_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    base_run_dir = _safe_run_dir("./runs")
    out_dir = _sanitize_subdir(base_run_dir, payload.get("output"))
    payload = dict(payload or {})

    payload = _ensure_inline_policy_to_outdir(payload, out_dir)

    policy_path = payload.get("policy")
    if not policy_path:
        return {"error": 400, "message": "policy is required"}

    args = ["custodian", "run", "-s", out_dir, policy_path]
    if (r := payload.get("region")):
        args += ["-r", str(r)]

    env = os.environ.copy()
    if payload.get("profile"):
        env["AWS_PROFILE"] = str(payload["profile"])

    try:
        timeout_sec = int(str(payload.get("timeout_sec", "1200")))
    except ValueError:
        timeout_sec = 1200

    log_path = os.path.join(out_dir, "log.txt")

    preinstall = ensure_tool_extended("custodian", "c7n", True, None, None)

    rc, stdout_text, stderr_text, duration_ms = _run_with_live_logging(
        args=args,
        cwd=base_run_dir,
        env=env,
        timeout_sec=timeout_sec,
        log_path=log_path,
    )

    files = _list_files_under(out_dir)

    # ▼ 최근 실행 포인터 저장
    _record_last_run("custodian", base_run_dir, out_dir)

    # result.json 저장
    try:
        result_path = os.path.join(base_run_dir, "result.json")
        payload_redacted = {
            k: v
            for k, v in (payload or {}).items()
            if k not in {"policy_inline", "policy_text", "policy_yaml"}
        }
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "code": "custodian",
                    "command": " ".join(shlex.quote(x) for x in args),
                    "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
                    "output_dir": os.path.relpath(out_dir, os.getcwd()),
                    "rc": rc,
                    "duration_ms": duration_ms,
                    "stdout": _clip(stdout_text),
                    "stderr": _clip(stderr_text),
                    "files": files,
                    "note": "stdout/stderr는 길이 제한으로 잘릴 수 있습니다.",
                    "preinstall": preinstall,
                    "payload": payload_redacted,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        pass

    return {
        "code": "custodian",
        "command": " ".join(shlex.quote(x) for x in args),
        "run_dir": os.path.relpath(base_run_dir, os.getcwd()),
        "output_dir": os.path.relpath(out_dir, os.getcwd()),
        "rc": rc,
        "duration_ms": duration_ms,
        "stdout": _clip(stdout_text),
        "stderr": _clip(stderr_text),
        "files": files,
        "note": "stdout/stderr는 길이 제한으로 잘릴 수 있습니다.",
        "preinstall": preinstall,
    }

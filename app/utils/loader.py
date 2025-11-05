# =========================
# file: app/utils/loader.py
# =========================
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
import yaml

_CATALOG_CACHE: Optional[Dict[str, Any]] = None

def _catalog_path() -> str:
    here = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(here, "data", "oss_catalog.yaml")

def load_catalog() -> Dict[str, Any]:
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE
    path = _catalog_path()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    items = data.get("items") or []
    by_code = {str(i.get("code")).strip(): i for i in items if i.get("code")}
    _CATALOG_CACHE = {"items": items, "by_code": by_code}
    return _CATALOG_CACHE

def list_items() -> List[Dict[str, Any]]:
    return load_catalog().get("items", [])

def get_item_by_code(code: str) -> Optional[Dict[str, Any]]:
    return load_catalog().get("by_code", {}).get(code)

def merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    o = dict(a or {})
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(o.get(k), dict):
            o[k] = merge(o[k], v)
        else:
            o[k] = v
    return o
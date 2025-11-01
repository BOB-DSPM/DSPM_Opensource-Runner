from fastapi import APIRouter, Query, HTTPException
from typing import List, Optional
from app.utils.loader import load_catalog

router = APIRouter()

@router.get("", summary="오픈소스 목록 조회")
def list_oss(tag: Optional[str] = Query(None), q: Optional[str] = Query(None)):
    data = load_catalog()
    items = data["items"]
    if tag:
        items = [x for x in items if tag in x.get("tags", [])]
    if q:
        ql = q.lower()
        items = [x for x in items if ql in x["name"].lower() or ql in x.get("desc","").lower()]
    return {"count": len(items), "items": items}

@router.get("/{code}", summary="오픈소스 단건 조회")
def get_oss(code: str):
    data = load_catalog()
    for x in data["items"]:
        if x["code"] == code:
            return x
    raise HTTPException(status_code=404, detail="not found")
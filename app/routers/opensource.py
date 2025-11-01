# app/routers/opensource.py
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Path
from app.models.run_models import OpenSourceItem, RunOut
from app.services.runner import runner_service

router = APIRouter()

@router.get("/opensource-list")
def opensource_list():
    items = []
    for name, cmd in runner_service.list_opensource().items():
        items.append(OpenSourceItem(name=name, description=f"{name} runnable command", cmd=cmd).model_dump())
    return {"items": items}

@router.post("/set/{name}")
async def set_and_run(
    name: str = Path(..., description="오픈소스 이름 (opensource-list 참고)")
):
    try:
        rec = await runner_service.start(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"run": RunOut.from_record(rec).model_dump()}

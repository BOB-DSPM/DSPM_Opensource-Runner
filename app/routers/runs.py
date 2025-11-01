# app/routers/runs.py
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from app.models.run_models import RunOut
from app.services.runner import runner_service
from app.utils.sse import sse_format

router = APIRouter()

@router.get("/runs")
def list_runs():
    return {"runs": [RunOut.from_record(r).model_dump() for r in runner_service.list()]}

@router.get("/runs/{run_id}")
def get_run(run_id: str = Path(...)):
    r = runner_service.get(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": RunOut.from_record(r).model_dump()}

@router.get("/runs/{run_id}/logs")
async def stream_logs(
    run_id: str = Path(...),
    follow: bool = Query(True, description="추적 여부"),
    from_bytes: int = Query(0, ge=0, description="해당 바이트 offset부터 tail")
):
    r = runner_service.get(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="run not found")

    async def gen():
        async for line in runner_service.tail_sse(run_id, follow=follow, from_bytes=from_bytes):
            yield line

    return StreamingResponse(
        sse_format(gen()),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx 버퍼링 비활성화(필요 시)
        },
    )

@router.post("/runs/{run_id}/stop")
async def stop_run(run_id: str = Path(...)):
    ok = await runner_service.stop(run_id)
    if not ok:
        raise HTTPException(status_code=400, detail="unable to stop (not running or not found)")
    return {"ok": True}

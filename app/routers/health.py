from fastapi import APIRouter
router = APIRouter()

@router.get("", summary="헬스체크")
def health():
    return {"status": "ok"}

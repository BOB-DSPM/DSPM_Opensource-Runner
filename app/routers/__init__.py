# app/routers/__init__.py
from fastapi import APIRouter
from .health import router as health_router
from .opensource import router as opensource_router
from .runs import router as runs_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(opensource_router, tags=["opensource"])
api_router.include_router(runs_router, tags=["runs"])

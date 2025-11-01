from fastapi import FastAPI
from app.routers import health, oss

app = FastAPI(title="SAGE OSS API", version="0.1.0")
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(oss.router, prefix="/oss", tags=["oss"])
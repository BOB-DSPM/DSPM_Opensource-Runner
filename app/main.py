# =========================
# file: app/main.py
# =========================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, oss

app = FastAPI(title="SAGE OSS API", version="0.1.0")

ALLOWED_ORIGINS = [
    "http://211.44.183.248",
    "http://211.44.183.248:80",
    "http://211.44.183.248:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(oss.router, prefix="/oss", tags=["oss"])

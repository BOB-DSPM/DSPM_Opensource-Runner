# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, oss

app = FastAPI(title="SAGE OSS API", version="0.1.0")

# CORS 설정
ALLOWED_ORIGINS = [
    "http://211.44.183.248",        # 프론트가 80에서 뜨는 경우
    "http://211.44.183.248:80",
    "http://211.44.183.248:3000",   # CRA(dev) 포트
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    # 필요 시 HTTPS/도메인 추가
    # "https://your-frontend-domain",
    # "http://your-frontend-domain",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],   # ["GET","POST","OPTIONS"] 등으로 제한 가능
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# 라우터
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(oss.router, prefix="/oss", tags=["oss"])

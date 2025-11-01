# app/core/config.py
from __future__ import annotations
import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    APP_NAME: str = os.getenv("APP_NAME", "OSS Runner API")
    APP_VERSION: str = os.getenv("APP_VERSION", "0.1.0")
    ALLOW_ORIGINS: str = os.getenv("ALLOW_ORIGINS", "*")
    LOG_DIR: str = os.getenv("LOG_DIR", "./logs")
    RUN_TMP_DIR: str = os.getenv("RUN_TMP_DIR", "./.runs")
    # 실행 가능한 오픈소스 커맨드 매핑을 ENV로 주입하고 싶다면 JSON으로도 가능(여기선 하드코딩 + 확장 포인트만 제공)

settings = Settings()
os.makedirs(settings.LOG_DIR, exist_ok=True)
os.makedirs(settings.RUN_TMP_DIR, exist_ok=True)

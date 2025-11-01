# app/utils/sse.py
from __future__ import annotations
from typing import AsyncGenerator

async def sse_format(gen: AsyncGenerator[str, None]):
    """
    제네레이터에서 나온 문자열을 SSE 프레임으로 포맷팅.
    """
    async for line in gen:
        # 줄바꿈 포함 문자열을 각각 data: 라인으로 분해
        for chunk in line.rstrip("\n").split("\n"):
            yield f"data: {chunk}\n\n"

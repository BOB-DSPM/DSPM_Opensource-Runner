# app/services/runner.py
from __future__ import annotations
import asyncio
import os
import signal
import uuid
from typing import Dict, List, AsyncGenerator

from app.core.config import settings
from app.models.run_models import RunRecord, RunStatus

# 기본 제공(하드코딩) 오픈소스 → 커맨드 매핑
DEFAULT_OPEN_SOURCE_CMDS: Dict[str, List[str]] = {
    # 실제 배포 전 안전성 검증 필수
    "hello": ["bash", "-lc", "echo 'Hello OSS Runner'; for i in {1..5}; do echo step:$i; sleep 1; done"],
    "list-root": ["bash", "-lc", "ls -la /"],
    # 예시) prowler 라이트: "prowler-list": ["prowler", "aws", "--list-checks"],
}

class RunnerService:
    def __init__(self):
        self.opensource_cmds: Dict[str, List[str]] = dict(DEFAULT_OPEN_SOURCE_CMDS)
        self._runs: Dict[str, RunRecord] = {}
        self._proc_map: Dict[str, asyncio.subprocess.Process] = {}
        self._log_writers: Dict[str, asyncio.Task] = {}

    def list_opensource(self) -> Dict[str, List[str]]:
        return self.opensource_cmds

    def _new_log_path(self, run_id: str) -> str:
        return os.path.join(settings.LOG_DIR, f"{run_id}.log")

    async def _pump_streams(self, run_id: str, proc: asyncio.subprocess.Process, log_path: str):
        """
        stdout/stderr 를 log 파일로 지속 기록.
        """
        with open(log_path, "a", buffering=1) as f:
            async def _copy_stream(stream, prefix: str):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode(errors="replace")
                    f.write(text)
            await asyncio.gather(_copy_stream(proc.stdout, "OUT"), _copy_stream(proc.stderr, "ERR"))

    async def start(self, name: str) -> RunRecord:
        if name not in self.opensource_cmds:
            raise ValueError(f"unknown opensource: {name}")

        run_id = str(uuid.uuid4())
        cmd = self.opensource_cmds[name][:]
        record = RunRecord(run_id=run_id, name=name, cmd=cmd, log_path=self._new_log_path(run_id))
        self._runs[run_id] = record

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        record.status = RunStatus.RUNNING
        record.started_at = asyncio.get_event_loop().time()
        record.pid = proc.pid
        self._proc_map[run_id] = proc

        # 로그 펌프 태스크
        self._log_writers[run_id] = asyncio.create_task(self._pump_streams(run_id, proc, record.log_path))

        # 종료 감시
        asyncio.create_task(self._watch(run_id, proc))
        return record

    async def _watch(self, run_id: str, proc: asyncio.subprocess.Process):
        rc = await proc.wait()
        rec = self._runs.get(run_id)
        if not rec:
            return
        rec.returncode = rc
        rec.ended_at = asyncio.get_event_loop().time()
        if rec.status != RunStatus.STOPPED:
            rec.status = RunStatus.SUCCEEDED if rc == 0 else RunStatus.FAILED

        # 로그 태스크 종료 대기
        t = self._log_writers.pop(run_id, None)
        if t:
            with contextlib.suppress(Exception):
                await t

        # 파이프 닫기
        if proc.stdout: proc.stdout.feed_eof()
        if proc.stderr: proc.stderr.feed_eof()

    def get(self, run_id: str) -> RunRecord | None:
        return self._runs.get(run_id)

    def list(self) -> List[RunRecord]:
        # 최신순 정렬
        return sorted(self._runs.values(), key=lambda r: r.created_at, reverse=True)

    async def stop(self, run_id: str) -> bool:
        proc = self._proc_map.get(run_id)
        rec = self._runs.get(run_id)
        if not proc or not rec:
            return False
        if proc.returncode is not None:
            return False
        try:
            proc.send_signal(signal.SIGTERM)
            rec.status = RunStatus.STOPPED
            return True
        except ProcessLookupError:
            return False

    async def tail_sse(self, run_id: str, follow: bool = True, from_bytes: int = 0) -> AsyncGenerator[str, None]:
        """
        SSE로 사용할 로그 제네레이터.
        follow=True 면 파일 append 를 추적.
        """
        path = self._runs.get(run_id).log_path if self._runs.get(run_id) else None
        if not path or not os.path.exists(path):
            yield "[no log yet]\n"
            return

        # 기존 바이트부터 tail
        with open(path, "r") as f:
            f.seek(from_bytes)
            # 최초 남은 내용 출력
            for line in f:
                yield line

        if not follow:
            return

        # 파일 증가분 폴링
        last_size = os.path.getsize(path)
        while True:
            await asyncio.sleep(0.5)
            if not os.path.exists(path):
                break
            size = os.path.getsize(path)
            if size > last_size:
                with open(path, "r") as f:
                    f.seek(last_size)
                    for line in f:
                        yield line
                last_size = size

# 모듈 전역 서비스 싱글톤
import contextlib
runner_service = RunnerService()

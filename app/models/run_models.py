# app/models/run_models.py
from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pydantic import BaseModel

class RunStatus(str):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"

@dataclass
class RunRecord:
    run_id: str
    name: str
    cmd: List[str]
    status: RunStatus = RunStatus.PENDING
    returncode: Optional[int] = None
    pid: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    log_path: str = ""
    meta: Dict[str, str] = field(default_factory=dict)

class OpenSourceItem(BaseModel):
    name: str
    description: str
    cmd: List[str]

class RunOut(BaseModel):
    run_id: str
    name: str
    cmd: List[str]
    status: str
    returncode: int | None
    pid: int | None
    created_at: float
    started_at: float | None
    ended_at: float | None

    @staticmethod
    def from_record(r: RunRecord) -> "RunOut":
        return RunOut(
            run_id=r.run_id, name=r.name, cmd=r.cmd, status=r.status,
            returncode=r.returncode, pid=r.pid, created_at=r.created_at,
            started_at=r.started_at, ended_at=r.ended_at
        )

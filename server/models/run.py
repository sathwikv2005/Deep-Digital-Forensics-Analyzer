from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RunState:
    run_id: str
    status: str = "starting"
    current_stage: str | None = None
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    logs: list[dict] = field(default_factory=list)
import asyncio
from server.models.run import RunState


class RunManager:

    def __init__(self):
        self.current_run: RunState | None = None
        self.lock = asyncio.Lock()
        self.subscribers: dict[str, list[asyncio.Queue]] = {}

    async def create_run(self, run_id: str):
        async with self.lock:
            if self.current_run and self.current_run.status == "running":
                raise RuntimeError("A forensic analysis is already running.")

            self.current_run = RunState(
                run_id=run_id,
                status="running"
            )

            self.subscribers[run_id] = []

            return self.current_run

    def get_run(self, run_id: str):
        if not self.current_run:
            return None

        if self.current_run.run_id != run_id:
            return None

        return self.current_run

    async def publish(self, run_id: str, message: dict):
        run = self.get_run(run_id)

        if not run:
            return

        run.logs.append(message)

        for queue in self.subscribers.get(run_id, []):
            await queue.put(message)

    def subscribe(self, run_id: str):
        queue = asyncio.Queue()

        if run_id not in self.subscribers:
            self.subscribers[run_id] = []

        self.subscribers[run_id].append(queue)

        return queue

    def unsubscribe(self, run_id: str, queue):
        if run_id in self.subscribers:
            if queue in self.subscribers[run_id]:
                self.subscribers[run_id].remove(queue)


run_manager = RunManager()
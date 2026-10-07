import asyncio
from datetime import datetime

from server.pipeline.config import TOOLS
from server.core.state import run_manager


class PipelineRunner:

    def __init__(self, run_id: str):
        self.run_id = run_id

    async def log(self, stage: str, message: str):
        await run_manager.publish(
            self.run_id,
            {
                "type": "log",
                "stage": stage,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
        )

    async def run_tool(self, name, executable):

        await run_manager.publish(
            self.run_id,
            {
                "type": "stage",
                "stage": name,
                "status": "running"
            }
        )

        if not executable.exists():
            await self.log(
                name,
                f"Executable not found: {executable}"
            )
            return False

        process = await asyncio.create_subprocess_exec(
            str(executable),
            cwd=str(executable.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        while True:
            line = await process.stdout.readline()

            if not line:
                break

            message = line.decode(
                errors="replace"
            ).rstrip()

            if message:
                await self.log(name, message)

        return_code = await process.wait()

        if return_code != 0:
            await self.log(
                name,
                f"Process exited with code {return_code}"
            )

            await run_manager.publish(
                self.run_id,
                {
                    "type": "stage",
                    "stage": name,
                    "status": "failed"
                }
            )

            return False

        await run_manager.publish(
            self.run_id,
            {
                "type": "stage",
                "stage": name,
                "status": "completed"
            }
        )

        return True

    async def run(self):

        for name, executable in TOOLS:

            success = await self.run_tool(
                name,
                executable
            )

            if not success:
                return False

            await asyncio.sleep(1)

        return True
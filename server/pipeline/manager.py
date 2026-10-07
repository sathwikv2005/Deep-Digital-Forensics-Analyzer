import asyncio
from datetime import datetime

from server.pipeline.runner import PipelineRunner
from server.core.state import run_manager


async def execute_pipeline(run_id: str):

    runner = PipelineRunner(run_id)

    try:
        success = await runner.run()

        run = run_manager.get_run(run_id)

        if run:
            run.status = "completed" if success else "failed"
            run.finished_at = datetime.now()

        await run_manager.publish(
            run_id,
            {
                "type": "complete",
                "status": "success" if success else "failed"
            }
        )

    except Exception as exc:

        run = run_manager.get_run(run_id)

        if run:
            run.status = "failed"
            run.finished_at = datetime.now()

        await run_manager.publish(
            run_id,
            {
                "type": "error",
                "message": str(exc)
            }
        )
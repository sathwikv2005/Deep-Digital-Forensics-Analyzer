import asyncio
from datetime import datetime

from fastapi import APIRouter, HTTPException

from server.core.state import run_manager
from server.pipeline.manager import execute_pipeline
from server.pipeline.config import OUTPUTS


router = APIRouter(prefix="/api")


@router.post("/runs")
async def start_run():

    run_id = datetime.now().strftime(
        "run-%Y%m%d-%H%M%S"
    )

    try:
        run = await run_manager.create_run(run_id)

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc)
        )

    asyncio.create_task(
        execute_pipeline(run_id)
    )

    return {
        "runId": run_id,
        "status": run.status,
        "websocket": f"/ws/runs/{run_id}"
    }


@router.get("/runs/{run_id}")
async def get_run(run_id: str):

    run = run_manager.get_run(run_id)

    if not run:
        raise HTTPException(
            status_code=404,
            detail="Run not found"
        )

    return {
        "runId": run.run_id,
        "status": run.status,
        "currentStage": run.current_stage,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at
    }


@router.get("/outputs")
async def get_outputs():

    return {
        name: f"/outputs/{path.relative_to(path.parents[2]).as_posix()}"
        for name, path in OUTPUTS.items()
    }
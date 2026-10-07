from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.core.state import run_manager


router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def pipeline_websocket(
    websocket: WebSocket,
    run_id: str
):

    await websocket.accept()

    run = run_manager.get_run(run_id)

    if not run:
        await websocket.send_json({
            "type": "error",
            "message": "Run not found"
        })

        await websocket.close()
        return

    queue = run_manager.subscribe(run_id)

    try:

        for message in run.logs:
            await websocket.send_json(message)

        while True:

            message = await queue.get()

            await websocket.send_json(message)

            if message["type"] in {
                "complete",
                "error"
            }:
                break

    except WebSocketDisconnect:
        pass

    finally:
        run_manager.unsubscribe(
            run_id,
            queue
        )
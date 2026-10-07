from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server.api.routes import router as api_router
from server.api.websocket import router as websocket_router
from server.pipeline.config import ROOT


app = FastAPI(
    title="Deep AI Digital Forensics Analysis API",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(api_router)
app.include_router(websocket_router)


app.mount(
    "/outputs",
    StaticFiles(
        directory=str(ROOT / "output")
    ),
    name="outputs"
)


@app.get("/api/health")
async def health():
    return {
        "status": "ok"
    }
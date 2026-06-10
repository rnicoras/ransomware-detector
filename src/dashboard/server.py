from __future__ import annotations
import asyncio
import logging
import time
import json
from collections import deque
from typing import TYPE_CHECKING, Set
import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from src.events import ResponseAction, ThreatAssessment
from pathlib import Path

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)
_DASHBOARD_DIR = Path(__file__).parent


class Dashboard:
    def __init__(self, cfg: "AppConfig", bus: "EventBus"):
        self._cfg = cfg
        self._bus = bus
        self._stats = {
            "alerts": 0,
            "quarantines": 0,
            "suspensions": 0,
            "start_time": time.time(),
        }
        self._client: Set[WebSocket] = set()
        self._app = FastAPI()
        self._recent_events: deque = deque(maxlen=100)
        self._setup_routes()

    def _setup_routes(self):
        self._app.mount(
            "/static",
            StaticFiles(directory=str(_DASHBOARD_DIR)),
            name="static",
        )

        @self._app.get("/", response_class=HTMLResponse)
        async def index():
            return HTMLResponse(
                content=(_DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
            )

        @self._app.get("/status")
        async def status():
            return self._current_stats()

        @self._app.websocket("/ws")
        async def websocket_endpoint(ws: WebSocket):
            await ws.accept()
            self._client.add(ws)
            log.info("Dashboard client connected (%d total)", len(self._client))
            try:
                await ws.send_text(json.dumps({
                    "type": "stats",
                    "data": self._current_stats(),
                }))
                for event in self._recent_events:
                    await ws.send_text(json.dumps(event))
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                self._client.discard(ws)
                log.info(
                    "Dashboard client disconnected (%d total)", len(self._client)
                )

    def _current_stats(self) -> dict:
        return {
            "alerts": self._stats["alerts"],
            "quarantines": self._stats["quarantines"],
            "suspensions": self._stats["suspensions"],
            "uptime": int(time.time() - self._stats["start_time"]),
            "connected_clients": len(self._client),
        }

    async def _broadcast(self, message: dict):
        self._recent_events.append(message)
        if not self._client:
            return
        text = json.dumps(message)
        dead = set()
        for client in self._client:
            try:
                await client.send_text(text)
            except Exception:
                dead.add(client)
        self._client -= dead

    async def _event_loop(self):
        async for event in self._bus.subscribe(ThreatAssessment, ResponseAction):
            try:
                if isinstance(event, ThreatAssessment):
                    await self._broadcast({
                        "type": "threat_assessment",
                        "timestamp": event.timestamp,
                        "data": {
                            "score": event.score,
                            "path": str(event.path) if event.path else None,
                            "pid": event.pid,
                            "signals": [s.kind.name for s in event.signals],
                        },
                    })

                elif isinstance(event, ResponseAction):
                    kind = event.kind.name
                    if kind == "ALERT":
                        self._stats["alerts"] += 1
                    elif kind == "SUSPEND":
                        self._stats["suspensions"] += 1
                    elif kind == "QUARANTINE":
                        self._stats["quarantines"] += 1

                    await self._broadcast({
                        "type": "response_action",
                        "timestamp": event.timestamp,
                        "data": {
                            "kind": kind,
                            "score": event.score,
                            "path": str(event.path) if event.path else None,
                            "pid": event.pid,
                            "detail": event.detail,
                        },
                    })
                    await self._broadcast({
                        "type": "stats",
                        "data": self._current_stats(),
                    })

            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Dashboard event loop error")

    async def run(self) -> None:
        if not self._cfg.dashboard.enabled:
            log.info("Dashboard disabled")
            return

        log.info(
            "Dashboard running at http://%s:%d",
            self._cfg.dashboard.host,
            self._cfg.dashboard.port,
        )

        event_task = asyncio.create_task(
            self._event_loop(), name="dashboard_events"
        )

        config = uvicorn.Config(
            self._app,
            host=self._cfg.dashboard.host,
            port=self._cfg.dashboard.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)

        try:
            await server.serve()
        except asyncio.CancelledError:
            log.info(
                "Dashboard shutting down"
            )
        finally:
            event_task.cancel()
            await asyncio.gather(event_task, return_exceptions=True)
            log.info(
                "Dashboard stopped"
            )
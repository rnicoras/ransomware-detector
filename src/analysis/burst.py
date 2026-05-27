from __future__ import annotations
import asyncio
import logging
from collections import deque
from typing import TYPE_CHECKING
from src.events import FileEvent, HoneyfileEvent, SignalKind, ThreatSignal

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class BurstDetector:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._threshold = cfg.analysis.burst.threshold_ops_per_sec
        self._window = cfg.analysis.burst.window_seconds
        self._weight = cfg.threat_scoring.weights.burst_activity
        # Sliding window of event timestamps
        self._timestamps: deque[float] = deque()

    def _record(self, timestamp: float) -> float:
        self._timestamps.append(timestamp)
        cutoff = timestamp - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps) / self._window

    async def run(self) -> None:
        log.info(
            "BurstDetector started (threshold=%d ops/s, window=%ds)",
            self._threshold,
            self._window,
        )
        async for event in self._bus.subscribe(FileEvent, HoneyfileEvent):
            try:
                ops_per_sec = self._record(event.timestamp)

                if ops_per_sec >= self._threshold:
                    log.warning(
                        "Burst detected: %.1f ops/s (threshold=%d)",
                        ops_per_sec,
                        self._threshold,
                    )
                    await self._bus.publish(ThreatSignal(
                        kind=SignalKind.BURST_DETECTED,
                        score_contribution=self._weight,
                        path=event.path,
                        pid=getattr(event, "pid", None),
                        detail=f"{ops_per_sec:.1f} ops/s over {self._window}s window",
                    ))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("BurstDetector error processing event")
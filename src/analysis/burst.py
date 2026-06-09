from __future__ import annotations
import asyncio
import logging
from collections import defaultdict, deque
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
        # track which pids already fired burst to avoid spam
        self._alerted_pids: set[str] = set()
        # per pid windows
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)

    def _get_pid_key(self, event) -> str:
        pid = getattr(event, "pid", None)
        if pid is not None:
            return str(pid)
        else:
            return "unknown"

    def _record(self, pid_key: str, timestamp: float) -> float:
        window = self._timestamps[pid_key]
        window.append(timestamp)
        cutoff = timestamp - self._window
        while window and window[0] < cutoff:
            window.popleft()
        return len(window) / self._window
    
    def _clean_inactive_pids(self, current_time: float):
        # remove the pids that weren't active since 2x the window period
        inactive = [pid for pid, window in self._timestamps.items() if window and (current_time - window[-1]) > self._window * 2]
        for pid in inactive:
            del self._timestamps[pid]
            self._alerted_pids.discard(pid)


    async def run(self) -> None:
        log.info(
            "Burst Detector started"
        )
        event_count = 0
        async for event in self._bus.subscribe(FileEvent, HoneyfileEvent):
            try:
                pid_key = self._get_pid_key(event)
                ops_per_sec = self._record(pid_key, event.timestamp)
                if ops_per_sec >= self._threshold:
                    if pid_key not in self._alerted_pids:
                        self._alerted_pids.add(pid_key)
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
                else:
                    self._alerted_pids.discard(pid_key)
                event_count += 1
                # cleanup inactive pids every 100 events
                if event_count % 100 == 0:
                    self._clean_inactive_pids(event.timestamp)
            
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Burst Detector error processing event")
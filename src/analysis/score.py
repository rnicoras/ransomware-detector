from __future__ import annotations
import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from src.events import (
    ProcessEvent,
    SignalKind,
    ThreatAssessment,
    ThreatSignal,
)

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

# correlation window in seconds, signals arriving within this window individually from each analyser that we have so far
# for the same (path, pid) are merged into one assessment
# a ransomware file operation triggers multiple signals (high entropy, burst spike, etc) at the same time almost
# so without a window we'd emit 3 separate assessments with low score instead of one single big high score
_CORRELATION_WINDOW = 5.0


@dataclass
class _Bucket:
    # accumulate signals for one pair of (path, pid)
    path: Optional[Path]
    pid: Optional[int]
    signals: list[ThreatSignal] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def score(self) -> int:
        return min(100, sum(s.score_contribution for s in self.signals))


class ThreatScoringEngine:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus
        self._buckets: dict[tuple, _Bucket] = defaultdict(
            lambda: _Bucket(path=None, pid=None)
        )
        # pid = latest ProcessEvent (for correlation)
        self._process_events: dict[int, ProcessEvent] = {}

    def _bucket_key(self, signal: ThreatSignal) -> tuple:
        return (str(signal.path), signal.pid)

    def _get_or_create(self, signal: ThreatSignal) -> _Bucket:
        key = self._bucket_key(signal)
        if key not in self._buckets:
            self._buckets[key] = _Bucket(path=signal.path, pid=signal.pid)
        return self._buckets[key]

    async def _flush_bucket(self, key: tuple) -> None:
        bucket = self._buckets.pop(key, None)
        if bucket is None or not bucket.signals:
            return

        assessment = ThreatAssessment(
            score=bucket.score,
            signals=bucket.signals,
            path=bucket.path,
            pid=bucket.pid,
        )

        log.info("ThreatAssessment: %s", assessment.summary)
        await self._bus.publish(assessment)

    async def _flush_expired(self) -> None:
        while True:
            await asyncio.sleep(_CORRELATION_WINDOW / 2)
            now = time.time()
            expired = [
                key for key, bucket in self._buckets.items()
                if now - bucket.created_at >= _CORRELATION_WINDOW
            ]
            for key in expired:
                await self._flush_bucket(key)

    async def _handle_signal(self, signal: ThreatSignal) -> None:
        bucket = self._get_or_create(signal)
        bucket.signals.append(signal)

        log.debug(
            "Signal %s +%d → running score %d (path=%s pid=%s)",
            signal.kind.name,
            signal.score_contribution,
            bucket.score,
            signal.path,
            signal.pid,
        )

        # honeyfile touched = immediate flush
        if signal.kind == SignalKind.HONEYFILE_TOUCHED:
            await self._flush_bucket(self._bucket_key(signal))
            return

        # if score already exceeds the quarantine threshold, flush immediately
        # so the response layer can act without waiting for the window
        quarantine_threshold = self._cfg.threat_scoring.thresholds.quarantine
        if bucket.score >= quarantine_threshold:
            log.warning(
                "Score %d reached quarantine threshold %d — flushing immediately",
                bucket.score,
                quarantine_threshold,
            )
            await self._flush_bucket(self._bucket_key(signal))

    async def _handle_process_event(self, event: ProcessEvent) -> None:
        self._process_events[event.pid] = event
        for bucket in self._buckets.values():
            if bucket.pid == event.pid and bucket.path is None:
                log.debug("Enriched bucket for pid=%d with process info", event.pid)


    async def run(self) -> None:
        log.info("ThreatScoringEngine started")

        flush_task = asyncio.create_task(self._flush_expired(), name="score_flush")

        try:
            async for event in self._bus.subscribe(ThreatSignal, ProcessEvent):
                try:
                    if isinstance(event, ThreatSignal):
                        await self._handle_signal(event)
                    elif isinstance(event, ProcessEvent):
                        await self._handle_process_event(event)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("ThreatScoringEngine error processing event")
        except asyncio.CancelledError:
            log.info("ThreatScoringEngine shutting down")
        finally:
            flush_task.cancel()
            await asyncio.gather(flush_task, return_exceptions=True)
            # flush any remaining buckets on shutdown
            for key in list(self._buckets.keys()):
                await self._flush_bucket(key)
            log.info("ThreatScoringEngine stopped")
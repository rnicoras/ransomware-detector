from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING
from src.events import HoneyfileEvent, SignalKind, ThreatSignal
from src.analysis.burst import BurstDetector
from src.analysis.entropy import EntropyAnalyser
from src.analysis.typemutation import TypeMutationDetector
from src.analysis.extension_rename import ExtensionRenameDetector

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class AnalysisEngine:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus

    async def _honeyfile_relay(self) -> None:
        weight = self._cfg.threat_scoring.weights.honeyfile_touch
        async for event in self._bus.subscribe(HoneyfileEvent):
            try:
                log.warning(
                    "Honeyfile touched: %s",
                    event.path.name,
                )
                await self._bus.publish(ThreatSignal(
                    kind=SignalKind.HONEYFILE_TOUCHED,
                    score_contribution=weight,
                    path=event.path,
                    pid=event.pid,
                    detail=f"honeyfile {event.op.name}: {event.path.name}",
                ))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Honeyfile relay error")

    async def run(self) -> None:
        log.info("AnalysisEngine starting")

        tasks = [
            asyncio.create_task(BurstDetector(self._cfg, self._bus).run(), name="burst"),
            asyncio.create_task(EntropyAnalyser(self._cfg, self._bus).run(), name="entropy"),
            asyncio.create_task(TypeMutationDetector(self._cfg, self._bus).run(), name="typemutation"),
            asyncio.create_task(ExtensionRenameDetector(self._cfg, self._bus).run(), name="extension_rename"),
            asyncio.create_task(self._honeyfile_relay(), name="honeyfile_relay"),
        ]

        log.info("AnalysisEngine started (%d analyser tasks)", len(tasks))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            log.info("AnalysisEngine shutting down")
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            log.info("AnalysisEngine stopped")
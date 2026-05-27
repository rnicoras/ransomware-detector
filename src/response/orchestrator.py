from __future__ import annotations
import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING
from src.events import ResponseAction, ResponseKind, ThreatAssessment

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class ResponseOrchestrator:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus
        self._thresholds = cfg.threat_scoring.thresholds
        self._response = cfg.response
        # track suspended PIDs so we don't suspend the same process twice
        self._suspended_pids: set[int] = set()
        # track quarantined paths so we don't process them twice
        self._quarantined_paths: set[Path] = set()


    async def _alert(self, assessment: ThreatAssessment) -> None:
        log.warning(
            "ALERT score=%d path=%s pid=%s signals=%s",
            assessment.score,
            assessment.path,
            assessment.pid,
            [s.kind.name for s in assessment.signals],
        )
        await self._bus.publish(ResponseAction(
            kind=ResponseKind.ALERT,
            score=assessment.score,
            path=assessment.path,
            pid=assessment.pid,
            detail=assessment.summary,
        ))

    async def _suspend(self, assessment: ThreatAssessment) -> None:
        pid = assessment.pid
        if pid is None:
            log.debug("Suspend requested but no PID available")
            return
        if pid in self._suspended_pids:
            log.debug("PID %d already suspended", pid)
            return
        if not self._response.auto_suspend:
            log.info("auto_suspend disabled — skipping suspend for pid=%d", pid)
            return

        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()
            self._suspended_pids.add(pid)
            log.warning("SUSPENDED pid=%d name=%s", pid, proc.name())
            await self._bus.publish(ResponseAction(
                kind=ResponseKind.SUSPEND,
                score=assessment.score,
                path=assessment.path,
                pid=pid,
                detail=f"suspended process {proc.name()} (pid={pid})",
            ))
        except Exception as exc:
            log.error("Failed to suspend pid=%d: %s", pid, exc)

    async def _quarantine(self, assessment: ThreatAssessment) -> None:
        path = assessment.path
        if path is None:
            log.debug("Quarantine requested but no path available")
            return
        if path in self._quarantined_paths:
            log.debug("Path already quarantined: %s", path)
            return
        if not self._response.auto_quarantine:
            log.info("auto_quarantine disabled — skipping for %s", path)
            return

        q_dir = self._response.quarantine_dir
        q_dir.mkdir(parents=True, exist_ok=True)

        dest = q_dir / path.name
        # avoid name collisions in the quarantine dir
        if dest.exists():
            dest = q_dir / f"{path.stem}_{int(assessment.timestamp)}{path.suffix}"

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, shutil.move, str(path), str(dest))
            self._quarantined_paths.add(path)
            log.warning("QUARANTINED %s → %s", path.name, dest)
            await self._bus.publish(ResponseAction(
                kind=ResponseKind.QUARANTINE,
                score=assessment.score,
                path=path,
                pid=assessment.pid,
                detail=f"moved to quarantine: {dest}",
            ))
        except Exception as exc:
            log.error("Failed to quarantine %s: %s", path, exc)

    async def _kill(self, assessment: ThreatAssessment) -> None:
        pid = assessment.pid
        if pid is None:
            return
        if not self._response.auto_kill:
            return

        try:
            import psutil
            proc = psutil.Process(pid)
            proc.kill()
            log.warning("KILLED pid=%d", pid)
            await self._bus.publish(ResponseAction(
                kind=ResponseKind.KILL,
                score=assessment.score,
                path=assessment.path,
                pid=pid,
                detail=f"killed process pid={pid}",
            ))
        except Exception as exc:
            log.error("Failed to kill pid=%d: %s", pid, exc)


    async def _respond(self, assessment: ThreatAssessment) -> None:
        score = assessment.score

        if score >= self._thresholds.alert:
            await self._alert(assessment)

        if score >= self._thresholds.suspend:
            await self._suspend(assessment)

        if score >= self._thresholds.quarantine:
            await self._quarantine(assessment)
            if self._response.auto_kill:
                await self._kill(assessment)

    async def run(self) -> None:
        log.info(
            "ResponseOrchestrator started "
            "(alert>=%d, suspend>=%d, quarantine>=%d)",
            self._thresholds.alert,
            self._thresholds.suspend,
            self._thresholds.quarantine,
        )
        async for event in self._bus.subscribe(ThreatAssessment):
            try:
                await self._respond(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("ResponseOrchestrator error processing assessment")
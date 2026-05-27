from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class ExtensionRenameDetector:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._enabled = cfg.analysis.extension_rename.enabled
        self._bad_extensions: set[str] = {
            ext.lower()
            for ext in cfg.analysis.extension_rename.known_bad_extensions
        }
        self._weight = cfg.threat_scoring.weights.known_bad_extension

    async def _check(self, event: FileEvent) -> None:
        dest = event.path
        src = event.src_path
        dest_ext = dest.suffix.lower()
        src_ext = src.suffix.lower() if src else dest_ext
        is_bad_ext = dest_ext in self._bad_extensions
        is_any_rename = src_ext != dest_ext

        if not (is_bad_ext or is_any_rename):
            return

        if is_bad_ext:
            contribution = self._weight
            detail = (
                f"known ransomware extension: {src.name!r} → {dest.name!r}"
                if src else f"known ransomware extension: {dest.name!r}"
            )
            log.warning("Bad extension rename: %s", detail)
        else:
            contribution = max(self._weight // 3, 5)
            detail = f"extension changed: {src_ext!r} → {dest_ext!r} ({dest.name!r})"
            log.debug("Extension rename (not in bad list): %s", detail)

        await self._bus.publish(ThreatSignal(
            kind=SignalKind.EXTENSION_RENAMED,
            score_contribution=contribution,
            path=dest,
            pid=event.pid,
            detail=detail,
        ))

    async def run(self) -> None:
        if not self._enabled:
            log.info("ExtensionRenameDetector disabled — skipping")
            return

        log.info(
            "ExtensionRenameDetector started (%d known bad extensions)",
            len(self._bad_extensions),
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op == FileOp.MOVED:
                    await self._check(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("ExtensionRenameDetector error processing event")
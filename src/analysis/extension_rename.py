from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal
from pathlib import PurePath

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_SAFE_EXTENSIONS: frozenset[str] = frozenset({
    ".tmp",
    ".bak",
    ".swp",
    ".old",
    ".orig",
    ".part",
    ".download",
    ".crdownload",
    ".log",
    ".cache",
    ".temp",
})

_DOCS_EXTENSIONS: frozenset[str] = frozenset({
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".txt",
    ".csv",
    ".rtf",
    ".odt",
    ".ods",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".mkv",
    ".zip",
    ".rar",
    ".7z",
})

class ExtensionRenameDetector:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._enabled = cfg.analysis.extension_rename.enabled
        self._bad_extensions: set[str] = {
            ext.lower()
            for ext in cfg.analysis.extension_rename.known_bad_extensions
        }
        self._weight = cfg.threat_scoring.weights.known_bad_extension

    @staticmethod
    def _double_extension(dest_name: str) -> bool:
        inner = PurePath(PurePath(dest_name).stem).suffix.lower()
        return inner in _DOCS_EXTENSIONS

    async def _check(self, event: FileEvent) -> None:
        dest = event.path
        src = event.src_path
        dest_ext = dest.suffix.lower()
        if dest_ext in _SAFE_EXTENSIONS:
            return
        src_ext = src.suffix.lower() if src else dest_ext
        is_bad_ext = dest_ext in self._bad_extensions
        is_any_rename = src_ext != dest_ext
        is_double = self._double_extension(dest.name)

        if not (is_bad_ext or is_double or is_any_rename):
            return

        if is_bad_ext:
            contribution = self._weight
            detail = (
                f"Known ransomware extension: {src.name!r} to {dest.name!r}"
                if src else f"Known ransomware extension: {dest.name!r}"
            )
            log.warning(
                "Bad extension rename: %s", detail
            )

        elif is_double:
            contribution = int(self._weight * 0.6)
            detail = (
                f"Double extension: {src.name!r} to {dest.name!r}"
                if src else f"Double extension: {dest.name!r}"
            )
            log.warning(
                "Double extension: %s", detail
            )
        
        else:
            contribution = max(self._weight // 3, 5)
            detail = f"Extension changed: {src_ext!r} to {dest_ext!r} ({dest.name!r})"
            log.debug(
                "Extension rename: %s", detail
            )

        await self._bus.publish(ThreatSignal(
            kind=SignalKind.EXTENSION_RENAMED,
            score_contribution=contribution,
            path=dest,
            pid=event.pid,
            detail=detail,
        ))

    async def run(self) -> None:
        if not self._enabled:
            log.info("Extension rename detector disabled")
            return

        log.info(
            "Extension rename detector started"
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op == FileOp.MOVED:
                    await self._check(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Extension rename detector error processing event")
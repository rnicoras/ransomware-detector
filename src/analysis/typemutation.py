from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_MAGIC: dict[str, list[bytes]] = {
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
    ".doc":  [b"\xd0\xcf\x11\xe0"],
    ".xls":  [b"\xd0\xcf\x11\xe0"],
    ".ppt":  [b"\xd0\xcf\x11\xe0"],
    ".pdf":  [b"%PDF"],
    ".png":  [b"\x89PNG"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".webp": [b"RIFF"],
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06"],
    ".gz":   [b"\x1f\x8b"],
    ".7z":   [b"7z\xbc\xaf"],
    ".rar":  [b"Rar!"],
    ".exe":  [b"MZ"],
    ".dll":  [b"MZ"],
}

# how many bytes to read for the magic check
_PEEK = 8

def _read_magic(path: Path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(_PEEK)

def _is_mutated(path: Path) -> tuple[bool, str]:
    ext = path.suffix.lower()
    expected_list = _MAGIC.get(ext)
    if expected_list is None:
        return False, ""

    try:
        actual = _read_magic(path)
    except OSError:
        return False, ""

    for expected in expected_list:
        if actual.startswith(expected):
            return False, ""

    return (
        True,
        f"ext={ext} expected_magic={[e.hex() for e in expected_list]} "
        f"actual={actual[:4].hex()}",
    )


class TypeMutationDetector:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._enabled = cfg.analysis.type_mutation.enabled
        self._weight = cfg.threat_scoring.weights.type_mutation

    async def _check(self, event: FileEvent) -> None:
        path = event.path
        if not path.exists():
            return

        loop = asyncio.get_running_loop()
        mutated, detail = await loop.run_in_executor(None, _is_mutated, path)

        if mutated:
            log.warning("Type mutation detected: %s", detail)
            await self._bus.publish(ThreatSignal(
                kind=SignalKind.TYPE_MUTATION,
                score_contribution=self._weight,
                path=path,
                pid=event.pid,
                detail=detail,
            ))

    async def run(self) -> None:
        if not self._enabled:
            log.info("TypeMutationDetector disabled — skipping")
            return

        log.info("TypeMutationDetector started")
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op in (FileOp.CREATED, FileOp.MODIFIED):
                    await self._check(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("TypeMutationDetector error processing event")
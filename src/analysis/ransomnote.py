from __future__ import annotations
import asyncio
import logging
import re
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_NOTE_PATTERNS: list[re.Pattern] = [
    re.compile(pattern, re.IGNORECASE) for pattern in [
        r"^readme\.txt$",
        r"^readme\.html$",
        r"^how.?to.?decrypt.*\.(txt|html|hta)$",
        r"^decrypt.?instruction.*\.(txt|html|hta)$",
        r"^restore.?files.*\.(txt|html|hta)$",
        r"^recovery.?instructions?.*\.(txt|html|hta)$",
        r"^!+.*read.*me.*!+.*\.(txt|html)$",
        r"^your.?files.*\.(txt|html|hta)$",
        r"^ransom.*note.*\.(txt|html)$",
        r"^help.?recover.*\.(txt|html|hta)$",
        r"^@please_read_me@.*\.txt$",
    ]
]

def _is_ransom_note(filename: str) -> bool:
    for pattern in _NOTE_PATTERNS:
        if pattern.match(filename):
            return True
    return False
    
class Ransomnote:
    def __init__(self, cfg: "AppConfig", bus: "EventBus"):
        self._bus = bus
        self._weight = cfg.threat_scoring.weights.ransom_note
        self._seen: set[str] = set() # don't alert on same note twice
    
    async def _check(self, event: FileEvent):
        filename = event.path.name
        path_key = str(event.path)

        if path_key in self._seen:
            return
        
        if not _is_ransom_note(filename):
            return
        
        self._seen.add(path_key)
        log.warning(
            "Ransom note detected: %r in %s", filename, event.path.parent
        )

        await self._bus.publish(ThreatSignal(
            kind=SignalKind.RANSOM_NOTE,
            score_contribution=self._weight,
            path=event.path,
            pid=event.pid,
            detail=f"Ransom note detected: {filename!r} in {event.path.parent}"
        ))

    async def run(self):
        log.info(
            "Ransom note detector started"
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op == FileOp.CREATED:
                    await self._check(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(
                    "Ransom note detector error processing event"
                )
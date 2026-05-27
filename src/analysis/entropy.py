# we compute Shannon entropy for modified files then flag those that look encrypted
# with this we measure randomness in a byte sequence (0 to 8 bits)
# for ex, compressed files have high entropy so we skip them to avoid false positives
# but ransomware overwrites files with ciphertext pushing entropy towards 8 bits so we check
# according to what threshold we set earlier in settings

from __future__ import annotations
import asyncio
import logging
import math
from pathlib import Path
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_ALREADY_COMPRESSED = {
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov",
    ".pdf",
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _should_skip(path: Path, min_size: int) -> tuple[bool, str]:
    if not path.exists():
        return True, "file no longer exists"
    if path.stat().st_size < min_size:
        return True, f"too small ({path.stat().st_size} < {min_size} bytes)"
    if path.suffix.lower() in _ALREADY_COMPRESSED:
        return True, f"known compressed format ({path.suffix})"
    return False, ""


class EntropyAnalyser:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._threshold = cfg.analysis.entropy.high_entropy_threshold
        self._min_size = cfg.analysis.entropy.min_file_size_bytes
        self._weight = cfg.threat_scoring.weights.high_entropy

    async def _analyse(self, event: FileEvent) -> None:
        path = event.path
        skip, reason = _should_skip(path, self._min_size)
        if skip:
            log.debug("EntropyAnalyser skipping %s: %s", path.name, reason)
            return

        loop = asyncio.get_running_loop()
        try:
            data: bytes = await loop.run_in_executor(None, path.read_bytes)
        except OSError as exc:
            log.debug("EntropyAnalyser could not read %s: %s", path.name, exc)
            return

        entropy = _shannon_entropy(data)
        log.debug("Entropy %.3f for %s", entropy, path.name)

        if entropy >= self._threshold:
            log.warning(
                "High entropy %.3f (threshold=%.1f) on %s",
                entropy,
                self._threshold,
                path.name,
            )
            await self._bus.publish(ThreatSignal(
                kind=SignalKind.HIGH_ENTROPY,
                score_contribution=self._weight,
                path=path,
                pid=event.pid,
                detail=f"entropy={entropy:.3f} threshold={self._threshold}",
            ))

    async def run(self) -> None:
        log.info(
            "EntropyAnalyser started (threshold=%.1f, min_size=%d bytes)",
            self._threshold,
            self._min_size,
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op == FileOp.MODIFIED:
                    await self._analyse(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("EntropyAnalyser error processing event")
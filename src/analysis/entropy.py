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

_MIN_DELTA = 2.0

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
        return True, "File no longer exists"
    if path.stat().st_size < min_size:
        return True, f"Too small ({path.stat().st_size} < {min_size} bytes)"
    if path.suffix.lower() in _ALREADY_COMPRESSED:
        return True, f"Known compressed format ({path.suffix})"
    return False, ""

class EntropyAnalyser:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._bus = bus
        self._threshold = cfg.analysis.entropy.high_entropy_threshold
        self._min_size = cfg.analysis.entropy.min_file_size_bytes
        self._weight = cfg.threat_scoring.weights.high_entropy
        self._entropy_history: dict[str, float] = {}

    async def _analyse(self, event: FileEvent) -> None:
        path = event.path
        skip, reason = _should_skip(path, self._min_size)
        if skip:
            log.debug("Entropy analyser skipping %s: %s", path.name, reason)
            return

        loop = asyncio.get_running_loop()
        try:
            data: bytes = await loop.run_in_executor(None, path.read_bytes)
        except OSError as exc:
            log.debug("Entropy analyser could not read %s: %s", path.name, exc)
            return

        entropy = _shannon_entropy(data)
        path_key = str(path)
        previous_entropy = self._entropy_history.get(path_key)
        self._entropy_history[path_key] = entropy
        log.debug(
            "Entropy %.3f (previous: %.3f) for %s", entropy, previous_entropy or 0.0, path.name
        )
        exceeding_threshold = entropy >= self._threshold
        suspicious_delta = (previous_entropy is not None and (entropy - previous_entropy) >= _MIN_DELTA and entropy >= self._threshold)

        if exceeding_threshold or suspicious_delta:
            log.warning(
                "High entropy %.3f with delta =+ %s on %s",
                entropy,
                entropy - previous_entropy if previous_entropy is not None else "",
                path.name,
            )
            await self._bus.publish(ThreatSignal(
                kind=SignalKind.HIGH_ENTROPY,
                score_contribution=self._weight,
                path=path,
                pid=event.pid,
                detail=f"Entropy={entropy:.3f} Threshold={self._threshold}",
            ))

    async def run(self) -> None:
        log.info(
            "Entropy analyser started"
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op == FileOp.MODIFIED:
                    await self._analyse(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(
                    "Entropy analyser error processing event"
                )
from __future__ import annotations
import asyncio
import math
import logging
import joblib
from pathlib import Path
from typing import TYPE_CHECKING
from src.events import FileEvent, FileOp, SignalKind, ThreatSignal
import numpy as np
import time

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)
_MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "ransomware_detector.joblib"
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
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06"],
}

# minimum probability to emit a signal
_THRESHOLD = 0.65
# time window between rescoring the same file
_TIME = 10.0

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

def _chi_square(data: bytes) -> float:
    # measure how uniform the byte distribution is; if it's perfectly uniform (encrypted) means low chi_square per byte
    # structured data = high chi_square
    if not data:
        return 0.0
    length = len(data)
    expected = length / 256.0
    if expected == 0:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    chi_sq = sum((f - expected) ** 2 / expected for f in freq)
    return chi_sq / length # normalize by length so we can compare across file sizes

def _header_matches_magicbyte(data: bytes, extension: str) -> bool:
    # check if file header matches expected magic bytes for the extension
    extension = extension.lower()
    expected_list = _MAGIC.get(extension)
    if expected_list is None:
        return False # unknown extension
    for expected in expected_list:
        if data[:len(expected)] == expected:
            return True
    return False

class MLScorer:
    def __init__(self, cfg: "AppConfig", bus: "EventBus"):
        self._bus = bus
        self._weight = cfg.threat_scoring.weights.ml_prediction
        self._model = None
        self._scored: dict[str, float] = {}

    def _load_model(self) -> bool:
        if not _MODEL_PATH.exists():
            log.warning(
                "Model not found at %s", _MODEL_PATH
            )
            return False
        try:
            self._model = joblib.load(_MODEL_PATH)
            log.info(
                "Model loaded from %s", _MODEL_PATH
            )
            return True
        except Exception as e:
            log.error(
                "Failed to load model: %s", e
            )
            return False
        
    def _extract_features(self, data: bytes, extension: str) -> np.ndarray:
        entropy = _shannon_entropy(data)
        filesize = len(data)
        chi_sq = _chi_square(data)
        magic = 1 if _header_matches_magicbyte(data, extension) else 0
        return np.array([[entropy, filesize, chi_sq, magic]])
    
    def _detect_extension(self, path: Path) -> str:
        # if the file has a double extension like document.docx.wncry we wanna use the inner extension for the magic byte checking
        extension = path.suffix.lower()
        inner = Path(path.stem).suffix.lower()
        if inner and inner in _MAGIC:
            return inner
        return extension
    
    async def _analyse(self, event: FileEvent) -> None:
        path = event.path
        path_key = str(path)
        now = time.time()
        last_scored = self._scored.get(path_key, 0)
        if now - last_scored < _TIME:
            return
        if not path.exists() or not path.is_file():
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size < 64:
            return
        loop = asyncio.get_running_loop()
        try:
            data = await loop.run_in_executor(None, path.read_bytes)
        except OSError as e:
            log.debug(
                "Scorer could not read %s: %s", path.name, e
            )
            return
        
        extension = self._detect_extension(path)
        features = self._extract_features(data, extension)
        probabilities = self._model.predict_proba(features)[0]
        ransomware_probability = probabilities[1]
        self._scored[path_key] = now
        if ransomware_probability >= _THRESHOLD:
            contribution = int(self._weight * ransomware_probability)
            detail = f"Model prediction: {ransomware_probability:.1%} ransomware probability"
            log.warning(
                "Model scored %s as RANSOMWARE (%.1f%% confidence)", path.name, ransomware_probability * 100,
            )
            await self._bus.publish(ThreatSignal(
                kind=SignalKind.ML_PREDICTION,
                score_contribution=contribution,
                path=path,
                pid=event.pid,
                detail=detail,
            ))
        else:
            log.debug(
                "Model scored %s as SAFE (%.1f%% ransomware probability)", path.name, ransomware_probability * 100,
            )
    
    async def run(self) -> None:
        if not self._load_model():
            return

        log.info(
            "Scorer started"
        )
        async for event in self._bus.subscribe(FileEvent):
            try:
                if event.op in (FileOp.CREATED, FileOp.MODIFIED):
                    await self._analyse(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(
                    "Scorer error processing event"
                )
from __future__ import annotations
import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.settings import LoggingConfig

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key in ("path", "pid", "score", "signal", "action"):
            if hasattr(record, key):
                payload[key] = str(getattr(record, key))
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(cfg: "LoggingConfig") -> None:
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    log_file = cfg.log_dir / "ransomware-detector.log"
    level = getattr(logging, cfg.level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=cfg.max_bytes, backupCount=cfg.backup_count, encoding="utf-8",
    )
    file_handler.setFormatter(_JsonFormatter())
    file_handler.setLevel(level)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    ))
    stream_handler.setLevel(level)

    root.addHandler(file_handler)
    root.addHandler(stream_handler)
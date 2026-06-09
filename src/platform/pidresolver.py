from __future__ import annotations
import logging
from pathlib import Path
import psutil
from typing import Optional

log = logging.getLogger(__name__)

# we only scan open_files() for processes writing over the rate of 512 kb/s
# and we set it lower than the threshold of the process inspector so we can catch the processes earlier
_MIN_WRITE_RATE = 512 * 1024
_SCAN_INTERVAL = 2.0

class PIDResolver:
    # each scan cycle it identifies processes with high write i/o and records which files they have open
    # the watcher calls resolve(path) from the watchdog thread to get a pid
    # for _cache we have an atomic replacement which is safe for concurrent reads from watchdog thread
    # basically when the watchdog thread reads, the asyncio thread writes

    def __init__(self):
        self._cache: dict[str, int] = {}
        self._previous_write: dict[int, int] = {}
    
    def resolve(self, path: Path) -> Optional[int]:
        return self._cache.get(str(path)) # called from watchdog thread
    
    def _scan(self):
        new_cache: dict[str, int] = {}
        for process in psutil.process_iter(attrs=["pid", "io_counters"]):
            try:
                info = process.info
                io = info.get("io_counters")
                if io is None:
                    continue
                pid: int = info["pid"]
                write_bytes: int = io.write_bytes
                previous = self._previous_write.get(pid, write_bytes)
                write_delta = write_bytes - previous
                self._previous_write[pid] = write_bytes
                write_rate = write_delta / _SCAN_INTERVAL
                if write_rate < _MIN_WRITE_RATE:
                    continue
                try:
                    for file in process.open_files():
                        new_cache[file.path] = pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # atomic replacement
        self._cache = new_cache
        # cleanup dead pids from previous_write
        if len(self._previous_write) > 500:
            alive = set(psutil.pids())
            dead = set(self._previous_write) - alive
            for pid in dead:
                del self._previous_write[pid]

    async def run(self) -> None:
        import asyncio
        log.info(
            "PID resolver started"
        )
        try:
            while True:
                await asyncio.sleep(_SCAN_INTERVAL)
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._scan)
        except asyncio.CancelledError:
            log.info(
                "PID resolver shutting down"
            )
        finally:
            log.info(
                "PID resolver stopped"
            )
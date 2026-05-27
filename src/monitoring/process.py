from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING
import psutil
from src.events import ProcessEvent

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_POLL_INTERVAL = 2.0

# write bytes/sec threshold to flag a process as high-I/O.

_WRITE_RATE_THRESHOLD = 10 * 1024 * 1024


class ProcessInspector:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus
        self._prev_write: dict[int, int] = {}

    def _sample(self) -> list[ProcessEvent]:
        events: list[ProcessEvent] = []

        for proc in psutil.process_iter(
            attrs=["pid", "name", "ppid", "cmdline", "io_counters"]
        ):
            try:
                info = proc.info
                io = info.get("io_counters")
                if io is None:
                    continue

                pid: int = info["pid"]
                write_bytes: int = io.write_bytes
                prev = self._prev_write.get(pid, write_bytes)
                write_delta = write_bytes - prev
                self._prev_write[pid] = write_bytes

                write_rate = write_delta / _POLL_INTERVAL

                if write_rate >= _WRITE_RATE_THRESHOLD:
                    cmdline = info.get("cmdline") or []
                    events.append(ProcessEvent(
                        pid=pid,
                        name=info.get("name") or "unknown",
                        io_read_bytes=io.read_bytes,
                        io_write_bytes=write_bytes,
                        parent_pid=info.get("ppid"),
                        cmdline=" ".join(cmdline) if cmdline else None,
                    ))
                    log.debug(
                        "High write I/O: pid=%d name=%s rate=%.1f MB/s",
                        pid,
                        info.get("name"),
                        write_rate / 1024 / 1024,
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return events

    def _cleanup_dead_pids(self) -> None:
        live_pids = {p.pid for p in psutil.process_iter()}
        dead = set(self._prev_write) - live_pids
        for pid in dead:
            del self._prev_write[pid]

    async def run(self) -> None:
        log.info("ProcessInspector started (poll interval=%.1fs)", _POLL_INTERVAL)
        cleanup_counter = 0

        try:
            while True:
                await asyncio.sleep(_POLL_INTERVAL)
                loop = asyncio.get_running_loop()
                events = await loop.run_in_executor(None, self._sample)

                for event in events:
                    await self._bus.publish(event)

                cleanup_counter += 1
                if cleanup_counter >= 30:
                    await loop.run_in_executor(None, self._cleanup_dead_pids)
                    cleanup_counter = 0

        except asyncio.CancelledError:
            log.info("ProcessInspector shutting down")
        finally:
            log.info("ProcessInspector stopped")
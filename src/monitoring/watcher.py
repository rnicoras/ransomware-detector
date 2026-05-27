from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    PatternMatchingEventHandler,
)
from watchdog.observers import Observer
from src.events import FileEvent, FileOp

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class _Handler(PatternMatchingEventHandler):
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        bus: "EventBus",
        ignore_patterns: list[str],
    ) -> None:
        super().__init__(
            patterns=["*"],
            ignore_patterns=ignore_patterns,
            ignore_directories=True,
            case_sensitive=True,
        )
        self._loop = loop
        self._bus = bus

    def _publish(self, event: FileEvent) -> None:
        self._loop.call_soon_threadsafe(
            self._loop.create_task,
            self._bus.publish(event),
        )

    def on_created(self, event: FileSystemEvent) -> None:
        self._publish(FileEvent(
            op=FileOp.CREATED,
            path=Path(event.src_path),
        ))

    def on_modified(self, event: FileSystemEvent) -> None:
        self._publish(FileEvent(
            op=FileOp.MODIFIED,
            path=Path(event.src_path),
        ))

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._publish(FileEvent(
            op=FileOp.DELETED,
            path=Path(event.src_path),
        ))

    def on_moved(self, event: FileMovedEvent) -> None:
        self._publish(FileEvent(
            op=FileOp.MOVED,
            path=Path(event.dest_path),
            src_path=Path(event.src_path),
        ))

class FileSystemWatcher:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        observer = Observer()

        handler = _Handler(
            loop=loop,
            bus=self._bus,
            ignore_patterns=self._cfg.monitor.ignore_patterns,
        )

        watch_paths = self._cfg.monitor.watch_paths
        for path in watch_paths:
            if not path.exists():
                log.warning("Watch path does not exist, skipping: %s", path)
                continue
            observer.schedule(handler, str(path), recursive=self._cfg.monitor.recursive)
            log.info("Watching: %s (recursive=%s)", path, self._cfg.monitor.recursive)

        observer.start()
        log.info("FileSystemWatcher started (%d path(s))", len(watch_paths))

        try:
            while True:
                await asyncio.sleep(1)
                if not observer.is_alive():
                    log.error("Watchdog observer died unexpectedly — restarting")
                    observer.stop()
                    observer.join()
                    observer = Observer()
                    for path in watch_paths:
                        if path.exists():
                            observer.schedule(
                                handler, str(path), recursive=self._cfg.monitor.recursive
                            )
                    observer.start()
        except asyncio.CancelledError:
            log.info("FileSystemWatcher shutting down")
        finally:
            observer.stop()
            observer.join()
            log.info("FileSystemWatcher stopped")
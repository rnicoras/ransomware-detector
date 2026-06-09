from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional
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
    from src.platform.pidresolver import PIDResolver

log = logging.getLogger(__name__)

class _Handler(PatternMatchingEventHandler):
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        bus: "EventBus",
        ignore_patterns: list[str],
        resolver: Optional["PIDResolver"] = None,
    ):
        super().__init__(
            patterns=["*"],
            ignore_patterns=ignore_patterns,
            ignore_directories=True,
            case_sensitive=True,
        )
        self._loop = loop
        self._bus = bus
        self._resolver = resolver

    def _resolve_pid(self, path: Path) -> Optional[int]:
        if self._resolver is None:
            return None
        return self._resolver.resolve(path)

    def _publish(self, event: FileEvent):
        self._loop.call_soon_threadsafe(
            self._loop.create_task,
            self._bus.publish(event),
        )

    def on_created(self, event: FileSystemEvent):
        path = Path(event.src_path)
        self._publish(FileEvent(
            op=FileOp.CREATED,
            path=path,
            pid=self._resolve_pid(path),
        ))

    def on_modified(self, event: FileSystemEvent):
        path = Path(event.src_path)
        self._publish(FileEvent(
            op=FileOp.MODIFIED,
            path=path,
            pid=self._resolve_pid(path)
        ))

    def on_deleted(self, event: FileSystemEvent):
        path = Path(event.src_path)
        self._publish(FileEvent(
            op=FileOp.DELETED,
            path=path,
            pid=self._resolve_pid(path),
        ))

    def on_moved(self, event: FileMovedEvent):
        dest = Path(event.dest_path)
        self._publish(FileEvent(
            op=FileOp.MOVED,
            path=dest,
            src_path=Path(event.src_path),
            pid=self._resolve_pid(dest),
        ))

class FileSystemWatcher:
    def __init__(self, cfg: "AppConfig", bus: "EventBus", resolver: Optional["PIDResolver"] = None):
        self._cfg = cfg
        self._bus = bus
        self._resolver = resolver

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        observer = Observer()
        handler = _Handler(
            loop=loop,
            bus=self._bus,
            ignore_patterns=self._cfg.monitor.ignore_patterns,
            resolver=self._resolver,
        )

        watch_paths = self._cfg.monitor.watch_paths
        for path in watch_paths:
            if not path.exists():
                log.warning(
                    "Watch path does not exist: %s", path
                )
                continue
            observer.schedule(handler, str(path), recursive=self._cfg.monitor.recursive)
            log.info(
                "Watching: %s (recursive=%s)", path, self._cfg.monitor.recursive
            )

        observer.start()
        log.info(
            "File System watcher started (%d path(s))", len(watch_paths)
        )

        try:
            while True:
                await asyncio.sleep(1)
                if not observer.is_alive():
                    log.error(
                        "Watchdog observer died unexpectedly. Restarting"
                    )
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
            log.info(
                "File System watcher shutting down"
            )
        finally:
            observer.stop()
            observer.join()
            log.info(
                "File System watcher stopped"
            )
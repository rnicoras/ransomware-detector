from __future__ import annotations
import asyncio
import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from src.events import FileOp, HoneyfileEvent
import random

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

_DECOY_CONTENT: dict[str, bytes] = {
    ".docx": b"PK\x03\x04" + b"\x00" * 20,
    ".xlsx": b"PK\x03\x04" + b"\x00" * 20,
    ".pdf":  b"%PDF-1.4\n%decoy",
    ".txt":  b"Confidential\n",
    ".zip":  b"PK\x05\x06" + b"\x00" * 18,
}
_DEFAULT_CONTENT = b"DECOY_FILE\n"


def _make_content(name: str) -> bytes:
    suffix = Path(name).suffix.lower()
    return _DECOY_CONTENT.get(suffix, _DEFAULT_CONTENT)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


class _HoneyHandler(PatternMatchingEventHandler):
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        bus: "EventBus",
        honeyfile_paths: set[Path],
    ) -> None:
        super().__init__(patterns=["*"], ignore_directories=True, case_sensitive=True)
        self._loop = loop
        self._bus = bus
        self._honeyfile_paths = honeyfile_paths

    def _publish(self, event: HoneyfileEvent):
        self._loop.call_soon_threadsafe(
            self._loop.create_task,
            self._bus.publish(event),
        )

    def _handle(self, op: FileOp, src_path: str):
        path = Path(src_path)
        if path in self._honeyfile_paths:
            log.warning(
                "Honeyfile %s: %s", op.name, path.name
            )
            self._publish(HoneyfileEvent(path=path, op=op))

    def on_modified(self, event: FileSystemEvent):
        self._handle(FileOp.MODIFIED, event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        self._handle(FileOp.DELETED, event.src_path)

    def on_created(self, event: FileSystemEvent):
        # triggered if a honeyfile is replaced
        self._handle(FileOp.CREATED, event.src_path)

    def on_moved(self, event):
        self._handle(FileOp.MOVED, event.src_path)


class HoneyfileSentinel:
    def __init__(self, cfg: "AppConfig", bus: "EventBus") -> None:
        self._cfg = cfg
        self._bus = bus
        self._directory = cfg.honeyfiles.directory
        self._names: list[str] = cfg.honeyfiles.names[: cfg.honeyfiles.count]
        self._checksums: dict[Path, str] = {}
        self._watch_paths: list[Path] = cfg.monitor.watch_paths

    def _collect_subdirs(self) -> list[Path]:
        subdirs: list[Path] = []
        for watch_path in self._watch_paths:
            if not watch_path.exists():
                continue
            subdirs.append(watch_path)
            try:
                for child in watch_path.iterdir():
                    if child.is_dir() and not child.name.startswith("."):
                        subdirs.append(child)
            except PermissionError:
                log.debug(
                    "Can't list %s. Skipping", watch_path
                )
        return subdirs
    
    def _plant_in_directory(self, directory: Path, name: str) -> Path:
        # plant a single honeyfile in the given directory
        path = directory / name
        if not path.exists():
            content = _make_content(name)
            path.write_bytes(content)
            log.info(
                "Planted honeyfile: %s", path
            )
        self._checksums[path] = _sha256(path)
        return path

    def _plant(self) -> set[Path]:
        # create the honeyfile directory and write all decoy files
        self._directory.mkdir(parents=True, exist_ok=True)
        planted: set[Path] = set()
        for name in self._names:
            path = self._plant_in_directory(self._directory, name)
            planted.add(path)
        
        subdirs = self._collect_subdirs()
        if subdirs and self._names:
            for subdir in subdirs:
                name = random.choice(self._names)
                try:
                    path = self._plant_in_directory(subdir, name)
                    planted.add(path)
                except PermissionError:
                    log.debug(
                        "Can't plant in %s", subdir
                    )
                except OSError as exc:
                    log.debug(
                        "Failed to plant in %s: %s", subdir, exc
                    )

        log.info(
            "Planted %d honeyfiles", len(planted)
        )
        return planted

    def _restore(self, path: Path) -> None:
        content = _make_content(path.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        self._checksums[path] = _sha256(path)
        log.info("Restored honeyfile: %s", path.name)

    async def _integrity_loop(self, honeyfile_paths: set[Path]) -> None:
        while True:
            await asyncio.sleep(30)
            for path in honeyfile_paths:
                if not path.exists():
                    log.warning(
                        "Honeyfile missing. Restoring: %s", path.name
                    )
                    self._restore(path)
                else:
                    current = _sha256(path)
                    if current != self._checksums.get(path):
                        log.warning(
                            "Honeyfile tampered. Restoring: %s", path.name
                        )
                        await self._bus.publish(
                            HoneyfileEvent(path=path, op=FileOp.MODIFIED)
                        )
                        self._restore(path)

    async def run(self) -> None:
        if not self._cfg.honeyfiles.enabled:
            log.info(
                "Honeyfile sentinel disabled"
            )
            return

        honeyfile_paths = self._plant()
        log.info(
            "Honeyfile sentinel active (%d decoys)", len(honeyfile_paths)
        )

        loop = asyncio.get_running_loop()
        observer = Observer()
        handler = _HoneyHandler(
            loop=loop,
            bus=self._bus,
            honeyfile_paths=honeyfile_paths,
        )
        observer.schedule(handler, str(self._directory), recursive=False)
        watched_dirs: set[str] = {str(self._directory)}
        for path in honeyfile_paths:
            parent = str(path.parent)
            if parent not in watched_dirs:
                observer.schedule(handler, parent, recursive=False)
                watched_dirs.add(parent)

        observer.start()
        integrity_task = asyncio.create_task(self._integrity_loop(honeyfile_paths))
        try:
            while True:
                await asyncio.sleep(1)
                if not observer.is_alive():
                    log.error(
                        "Honeyfile observer died"
                    )
                    observer.stop()
                    observer.join()
                    observer = Observer()
                    for d in watched_dirs:
                        observer.schedule(handler, d, recursive=False)

                    observer.start()
        except asyncio.CancelledError:
            log.info(
                "Honeyfile sentinel shutting down"
            )
        finally:
            integrity_task.cancel()
            observer.stop()
            observer.join()
            log.info(
                "HoneyfileSentinel stopped"
            )
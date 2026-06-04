from __future__ import annotations
import asyncio
import logging
import time
import shutil
from src.events import ResponseAction, ResponseKind
from src.backup.integrity import IntegrityDB
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from src.settings import AppConfig
    from src.bus import EventBus

log = logging.getLogger(__name__)

class Backup:
    def __init__(self, cfg: "AppConfig", bus: "EventBus"):
        self._cfg = cfg
        self._bus = bus
        self._db = IntegrityDB(cfg)
        self._backup_dir = cfg.backup.backup_dir
        self._max_versions = cfg.backup.max_versions
        self._interval = cfg.backup.interval_seconds
        self._backup_paths: list[Path] = (
            cfg.backup.backup_paths if cfg.backup.backup_paths else cfg.monitor.watch_paths
        )

    def _backup_path(self, original: Path, version: str) -> Path:
        try:
            rel_path = original.relative_to(original.anchor)
        except ValueError:
            rel_path = Path(original.name)

        dest = self._backup_dir / rel_path.parent / f"{original.stem}.v{version}{original.suffix}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest
    
    def _next_version(self, original: Path) -> int:
        # next version number of a file
        versions = self._db.get_allversions(original)
        if not versions:
            return 1
        return versions[-1][0] + 1
    
    def _delete_oldest_version(self, original: Path):
        # the principle behind the backup is that whenever the max_versions is exceeding its limit, we del the oldest version saved
        versions = self._db.get_allversions(original)
        while len(versions) > self._max_versions:
            oldest_version, oldest_backup_path, _ = versions.pop(0)
            backup_file = Path(oldest_backup_path)
            if backup_file.exists():
                backup_file.unlink()
                log.debug(
                    "Deleted old backup: %s v%d", original.name, oldest_version
                )
            self._db.delete_version(original, oldest_version)

    def _backup_file(self, path: Path) -> bool:
        # copy path to backup storage and record its checksum
        # return true on success, false otherwise
        if not path.exists() or not path.is_file():
            return False
        
        version = self._next_version(path)
        destination = self._backup_path(path, version)
        try:
            shutil.copy2(str(path), str(destination))
            self._db.record(path, destination, version)
            self._delete_oldest_version(path)
            log.debug(
                "Backed up: %s v%d", path.name, version
            )
            return True
        except Exception as e:
            log.error(
                "Backup failed for %s: %s", path, e
            )
            return False
        
    def _backup_directory(self, directory: Path):
        # backup all files in a dir recursively
        success = 0
        failure = 0
        for path in directory.rglob("*"):
            if path.is_file():
                if self._backup_file(path):
                    success += 1
                else:
                    failure += 1
        return success, failure
            
    async def restore(self, original: Path, version: Optional[int] = None) -> bool:
        # restore a file from backup, if its version is none then we restore the latest verified version
        # return true on success
        if version is None:
            result = self._db.get_latest_version(original)
            if result is None:
                log.error(
                    "No backup for %s", original
                    )
                return False
            version, backup_path_str = result
        else:
            versions = self._db.get_allversions(original)
            match = [(vers, bckp) for vers, bckp, _ in versions if vers == version]
            if not match:
                log.error(
                    "Version %d for %s was not found", version, original
                )
                return False
            _, backup_path_str = match[0]

        backup_path = Path(backup_path_str)

        if not self._db.verify(backup_path, original, version):
            log.error(
                "Integrity check failed for %s v%d", original.name, version
            )
            return False
        
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, shutil.copy2, str(backup_path), str(original))
            log.info(
                "%s restored from v%d", original.name, version
            )
            return True
        except Exception as e:
            log.error(
                "%s failed to restore: %s", original.name, e
            )
            return False
        
    async def _scheduled_loop(self) -> None:
        # run a full backup of all configured paths on a schedule
        while True:
            await asyncio.sleep(self._interval)
            log.info(
                "Scheduled backup starting"
            )
            start = time.time()
            total_ok = total_fail = 0

            loop = asyncio.get_running_loop()
            for backup_path in self._backup_paths:
                if backup_path.exists():
                    ok, fail = await loop.run_in_executor(None, self._backup_directory, backup_path)
                    total_ok += ok
                    total_fail += fail

            elapsed = time.time() - start
            log.info(
                "Scheduled backup complete: %d files backed up, "
                "%d failed, %.1fs elapsed",
                total_ok, total_fail, elapsed,
            )

       
    async def _handle_response_action(self, action: ResponseAction) -> None:
        if action.kind != ResponseKind.QUARANTINE:
            return
        if action.path is None:
            return

        directory = action.path.parent
        log.info(
            "Reactive backup triggered for directory: %s", directory
        )
        loop = asyncio.get_running_loop()
        ok, fail = await loop.run_in_executor(
            None, self._backup_directory, directory
        )
        log.info(
            "Reactive backup complete: %d backed up, %d failed", ok, fail
        )

    async def run(self) -> None:
        if not self._cfg.backup.enabled:
            log.info(
                "Backup orchestrator disabled"
            )
            return

        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._db.open()

        log.info(
            "Backup Orchestrator started (interval=%ds, max_versions=%d)",
            self._interval,
            self._max_versions,
        )

        # run initial backup immediately on startup
        loop = asyncio.get_running_loop()
        log.info(
            "Running initial backup"
        )
        for path in self._backup_paths:
            if path.exists():
                await loop.run_in_executor(None, self._backup_directory, path)

        scheduled_task = asyncio.create_task(
            self._scheduled_loop(), name="backup_scheduled"
        )

        try:
            async for action in self._bus.subscribe(ResponseAction):
                await self._handle_response_action(action)
        except asyncio.CancelledError:
            log.info(
                "Backup Orchestrator shutting down"
            )
        finally:
            scheduled_task.cancel()
            await asyncio.gather(scheduled_task, return_exceptions=True)
            self._db.close()
            log.info(
                "Backup Orchestrator stopped"
            )
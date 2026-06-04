from __future__ import annotations
import sqlite3
import hashlib
from pathlib import Path
import time
from typing import Optional, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from src.settings import AppConfig

log = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS checksums(
path TEXT NOT NULL,
backup_path TEXT NOT NULL,
algorithm TEXT NOT NULL,
checksum TEXT NOT NULL,
version INTEGER NOT NULL,
created_at REAL NOT NULL,
PRIMARY KEY (path, version)
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS index_path ON checksums(path);
"""

def _compute(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

class IntegrityDB:
    def __init__(self, cfg: "AppConfig") -> None:
        self._db_path = cfg.integrity.db_path
        self._algorithm = cfg.integrity.algorithm
        self._conn: Optional[sqlite3.Connection] = None

    def open(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_CREATE_TABLE)
        self._conn.execute(_CREATE_INDEX)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # write
    def record(self, original: Path, backup: Path, version: int) -> str:
        # compute and store the checksum of the backup
        checksum = _compute(backup, self._algorithm)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO checksums
                (path, backup_path, algorithm, checksum, version, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(original), str(backup), self._algorithm, checksum, version, time.time()),
        )
        self._conn.commit()
        log.debug(
            "Recorded %s v%d checksum=%s", original.name, version, checksum[:12]
        )
        return checksum

    def delete_version(self, original: Path, version: int) -> None:
        self._conn.execute(
            "DELETE FROM checksums WHERE path = ? AND version = ?",
            (str(original), version),
        )
        self._conn.commit()

    # read
    def verify(self, backup: Path, original: Path, version: int) -> bool:
        # recompute the checksum of backup and compare against the stored value; it returns true if file's intact or false if something's missing or has been modified
        row = self._conn.execute(
            "SELECT checksum, algorithm FROM checksums WHERE path = ? AND version = ?",
            (str(original), version),
        ).fetchone()

        if row is None:
            log.warning(
                "No checksum record for %s v%d", original.name, version
            )
            return False

        stored_checksum, algorithm = row
        try:
            actual = _compute(backup, algorithm)
        except OSError as exc:
            log.error(
                "Cannot read backup file %s: %s", backup, exc
            )
            return False

        ok = actual == stored_checksum
        if not ok:
            log.warning(
                "Integrity check FAILED for %s v%d "
                "stored=%s actual=%s",
                original.name, version, stored_checksum[:12], actual[:12],
            )
        return ok

    def get_allversions(self, original: Path) -> list[tuple[int, str, float]]:
        # returns all versions of a file as version, backup_path, created_at from oldest to newest
        rows = self._conn.execute(
            """
            SELECT version, backup_path, created_at FROM checksums WHERE path = ? ORDER BY version ASC
            """,
            (str(original),),
        ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]

    def get_latest_version(self, original: Path) -> Optional[tuple[int, str]]:
        # version and backup_path from the most recent backup of a file
        row = self._conn.execute(
            """
            SELECT version, backup_path FROM checksums WHERE path = ? ORDER BY version DESC LIMIT 1
            """,
            (str(original),),
        ).fetchone()
        return (row[0], row[1]) if row else None
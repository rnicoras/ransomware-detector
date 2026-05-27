from __future__ import annotations
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

class FileOp(Enum):
    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    MOVED = auto()


class SignalKind(Enum):
    HONEYFILE_TOUCHED = auto()
    BURST_DETECTED = auto()
    HIGH_ENTROPY = auto()
    TYPE_MUTATION = auto()
    EXTENSION_RENAMED = auto()


class ResponseKind(Enum):
    ALERT = auto()
    SUSPEND = auto()
    QUARANTINE = auto()
    KILL = auto()


@dataclass
class FileEvent:
    op: FileOp
    path: Path
    timestamp: float = field(default_factory=time.time)
    src_path: Optional[Path] = None
    pid: Optional[int] = None
    file_size: Optional[int] = None


@dataclass
class HoneyfileEvent:
    path: Path
    op: FileOp
    timestamp: float = field(default_factory=time.time)
    pid: Optional[int] = None


@dataclass
class ProcessEvent:
    pid: int
    name: str
    io_read_bytes: int
    io_write_bytes: int
    timestamp: float = field(default_factory=time.time)
    parent_pid: Optional[int] = None
    cmdline: Optional[str] = None


@dataclass
class ThreatSignal:
    kind: SignalKind
    score_contribution: int
    path: Optional[Path] = None
    pid: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    detail: str = ""


@dataclass
class ThreatAssessment:
    score: int
    signals: list[ThreatSignal] = field(default_factory=list)
    path: Optional[Path] = None
    pid: Optional[int] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> str:
        kinds = ", ".join(s.kind.name for s in self.signals)
        return f"score={self.score} signals=[{kinds}] path={self.path} pid={self.pid}"


@dataclass
class ResponseAction:
    kind: ResponseKind
    score: int
    path: Optional[Path] = None
    pid: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    detail: str = ""
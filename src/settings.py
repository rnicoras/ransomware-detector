from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import yaml

def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()


@dataclass
class MonitorConfig:
    watch_paths: List[Path]
    recursive: bool = True
    ignore_patterns: List[str] = field(default_factory=list)


@dataclass
class HoneyfileConfig:
    enabled: bool = True
    directory: Path = Path("~/.ransomware-detector/honeyfiles")
    count: int = 5
    names: List[str] = field(default_factory=list)


@dataclass
class BurstConfig:
    threshold_ops_per_sec: int = 20
    window_seconds: int = 5


@dataclass
class EntropyConfig:
    high_entropy_threshold: float = 7.2
    min_file_size_bytes: int = 512


@dataclass
class TypeMutationConfig:
    enabled: bool = True
    check_magic_bytes: bool = True


@dataclass
class ExtensionRenameConfig:
    enabled: bool = True
    known_bad_extensions: List[str] = field(default_factory=list)


@dataclass
class AnalysisConfig:
    burst: BurstConfig = field(default_factory=BurstConfig)
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    type_mutation: TypeMutationConfig = field(default_factory=TypeMutationConfig)
    extension_rename: ExtensionRenameConfig = field(default_factory=ExtensionRenameConfig)


@dataclass
class ThreatWeights:
    honeyfile_touch: int = 60
    burst_activity: int = 20
    high_entropy: int = 15
    type_mutation: int = 25
    known_bad_extension: int = 40


@dataclass
class ThreatThresholds:
    alert: int = 30
    suspend: int = 55
    quarantine: int = 75


@dataclass
class ThreatScoringConfig:
    weights: ThreatWeights = field(default_factory=ThreatWeights)
    thresholds: ThreatThresholds = field(default_factory=ThreatThresholds)


@dataclass
class ResponseConfig:
    auto_suspend: bool = True
    auto_quarantine: bool = True
    quarantine_dir: Path = Path("~/.ransomware-detector/quarantine")
    auto_kill: bool = False


@dataclass
class BackupConfig:
    enabled: bool = True
    backup_dir: Path = Path("~/.ransomware-detector/backups")
    backup_paths: List[Path] = field(default_factory=list)
    max_versions: int = 5
    interval_seconds: int = 300


@dataclass
class IntegrityConfig:
    db_path: Path = Path("~/.ransomware-detector/checksums.db")
    algorithm: str = "sha256"


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_dir: Path = Path("~/.ransomware-detector/logs")
    max_bytes: int = 10_485_760
    backup_count: int = 5


@dataclass
class AppConfig:
    monitor: MonitorConfig
    honeyfiles: HoneyfileConfig
    analysis: AnalysisConfig
    threat_scoring: ThreatScoringConfig
    response: ResponseConfig
    backup: BackupConfig
    integrity: IntegrityConfig
    dashboard: DashboardConfig
    logging: LoggingConfig


_DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "default.yaml"

def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config(user_config_path: Optional[str | Path] = None) -> AppConfig:
    with open(_DEFAULT_CONFIG, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if user_config_path is not None:
        with open(user_config_path, "r", encoding="utf-8") as fh:
            user_raw = yaml.safe_load(fh) or {}
        raw = _deep_merge(raw, user_raw)

    return _parse(raw)


def _parse(raw: dict) -> AppConfig:
    m = raw["monitor"]
    monitor = MonitorConfig(
        watch_paths=[_expand(p) for p in m["watch_paths"]],
        recursive=m.get("recursive", True),
        ignore_patterns=m.get("ignore_patterns", []),
    )

    h = raw["honeyfiles"]
    honeyfiles = HoneyfileConfig(
        enabled=h.get("enabled", True),
        directory=_expand(h["directory"]),
        count=h.get("count", 5),
        names=h.get("names", []),
    )

    a = raw["analysis"]
    analysis = AnalysisConfig(
        burst=BurstConfig(**a["burst"]),
        entropy=EntropyConfig(**a["entropy"]),
        type_mutation=TypeMutationConfig(**a["type_mutation"]),
        extension_rename=ExtensionRenameConfig(**a["extension_rename"]),
    )

    ts = raw["threat_scoring"]
    threat_scoring = ThreatScoringConfig(
        weights=ThreatWeights(**ts["weights"]),
        thresholds=ThreatThresholds(**ts["thresholds"]),
    )

    r = raw["response"]
    response = ResponseConfig(
        auto_suspend=r.get("auto_suspend", True),
        auto_quarantine=r.get("auto_quarantine", True),
        quarantine_dir=_expand(r["quarantine_dir"]),
        auto_kill=r.get("auto_kill", False),
    )

    b = raw["backup"]
    backup = BackupConfig(
        enabled=b.get("enabled", True),
        backup_dir=_expand(b["backup_dir"]),
        backup_paths=[_expand(p) for p in b.get("backup_paths", [])],
        max_versions=b.get("max_versions", 5),
        interval_seconds=b.get("interval_seconds", 300),
    )

    i = raw["integrity"]
    integrity = IntegrityConfig(
        db_path=_expand(i["db_path"]),
        algorithm=i.get("algorithm", "sha256"),
    )

    d = raw["dashboard"]
    dashboard = DashboardConfig(**d)

    lg = raw["logging"]
    logging_cfg = LoggingConfig(
        level=lg.get("level", "INFO"),
        log_dir=_expand(lg["log_dir"]),
        max_bytes=lg.get("max_bytes", 10_485_760),
        backup_count=lg.get("backup_count", 5),
    )

    return AppConfig(
        monitor=monitor,
        honeyfiles=honeyfiles,
        analysis=analysis,
        threat_scoring=threat_scoring,
        response=response,
        backup=backup,
        integrity=integrity,
        dashboard=dashboard,
        logging=logging_cfg,
    )
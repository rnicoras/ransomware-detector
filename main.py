from __future__ import annotations
import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from src.settings import load_config
from src.logger import setup_logging
from src.bus import EventBus

log = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ransomware Early-Stage Detector & Safe Backup Orchestrator"
    )
    parser.add_argument("--config", metavar="PATH", default=None)
    parser.add_argument("--watch", metavar="PATH", nargs="+", default=None)
    return parser.parse_args()


async def _main(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    if args.watch:
        cfg.monitor.watch_paths = [Path(p).expanduser().resolve() for p in args.watch]

    setup_logging(cfg.logging)
    log.info("Starting ransomware detector")
    log.info("Watching: %s", [str(p) for p in cfg.monitor.watch_paths])

    bus = EventBus()
    tasks: list[asyncio.Task] = []

    from src.monitoring.watcher import FileSystemWatcher
    from src.monitoring.honeyfiles import HoneyfileSentinel
    from src.monitoring.process import ProcessInspector
    from src.analysis.engine import AnalysisEngine
    from src.analysis.score import ThreatScoringEngine
    from src.response.orchestrator import ResponseOrchestrator

    tasks.append(asyncio.create_task(FileSystemWatcher(cfg, bus).run(), name="fs_watcher"))
    tasks.append(asyncio.create_task(HoneyfileSentinel(cfg, bus).run(), name="honeyfile"))
    tasks.append(asyncio.create_task(ProcessInspector(cfg, bus).run(), name="proc_inspector"))
    tasks.append(asyncio.create_task(AnalysisEngine(cfg, bus).run(), name="analysis"))
    tasks.append(asyncio.create_task(ThreatScoringEngine(cfg, bus).run(), name="scoring"))
    tasks.append(asyncio.create_task(ResponseOrchestrator(cfg, bus).run(), name="response"))

    stop = asyncio.Event()

    def _signal_handler(*_) -> None:
        log.info("Shutdown signal received")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            signal.signal(sig, _signal_handler)

    log.info("Detector running — press Ctrl+C to stop")
    await stop.wait()

    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    log.info("Shutdown complete. Bus stats: %s", bus.stats)


def main() -> None:
    args = _parse_args()
    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()

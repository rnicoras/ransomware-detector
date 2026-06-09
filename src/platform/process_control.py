from __future__ import annotations
import logging
import psutil

log = logging.getLogger(__name__)

def suspend_process(pid: int) -> str:
    process = psutil.Process(pid)
    name = process.name()
    process.suspend()
    log.info(
        "Suspended pid=%d name=%s", pid, name
    )
    return name

def resume_process(pid: int) -> str:
    process = psutil.Process(pid)
    name = process.name()
    process.resume()
    log.info(
        "Resumed pid=%d name=%s", pid, name
    )
    return name

def kill_process(pid: int) -> str:
    process = psutil.Process(pid)
    name = process.name()
    process.kill()
    log.info(
        "Killed pid=%d name=%s", pid, name
    )
    return name

def is_alive(pid: int) -> bool:
    try:
        process = psutil.Process(pid)
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False
    
def get_process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"
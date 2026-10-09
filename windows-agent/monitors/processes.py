
"""Read-only process monitoring for Windows."""

from datetime import datetime, timezone
from pathlib import Path
import os

import psutil


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def inspect_process(pid: int) -> dict | None:
    try:
        process = psutil.Process(pid)

        with process.oneshot():
            name = process.name()
            executable = process.exe() or None
            parent_pid = process.ppid()
            created = process.create_time()

        reasons = []

        if executable:
            try:
                path = Path(executable).resolve()
                home = Path.home().resolve()
                temp = Path(os.environ.get("TEMP", str(home))).resolve()

                if path.is_relative_to(home) or path.is_relative_to(temp):
                    reasons.append(
                        "Executable is inside a user-writable location"
                    )
            except (OSError, ValueError):
                pass

        return {
            "event_type": "process_observed",
            "timestamp": datetime.fromtimestamp(
                created, timezone.utc
            ).isoformat(),
            "pid": pid,
            "parent_pid": parent_pid,
            "process_name": name,
            "executable": executable,
            "process_started_at": datetime.fromtimestamp(
                created, timezone.utc
            ).isoformat(),
            "reasons": reasons,
            "severity": "medium" if reasons else "info",
        }

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError,
    ):
        return None


def snapshot_processes() -> dict[int, dict]:
    snapshot = {}

    for process in psutil.process_iter(["pid"]):
        pid = process.info["pid"]

        if pid is None:
            continue

        event = inspect_process(pid)

        if event:
            snapshot[pid] = event

    return snapshot


def find_new_processes(
    previous: dict[int, dict],
    current: dict[int, dict],
) -> list[dict]:
    return [
        current[pid]
        for pid in current
        if pid not in previous
    ]

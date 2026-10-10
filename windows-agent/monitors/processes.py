"""Process monitoring and change detection for Windows."""

from datetime import datetime, timezone
import os
from pathlib import Path

import psutil

from monitors.file_metadata import inspect_file_metadata


def utc_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def inspect_process(pid: int) -> dict | None:
    """
    Inspect a process by PID, collecting metadata:
    - Name, PID, PPID, parent process name
    - Executable path and file metadata (size, timestamps, sha256)
    - Creation time
    - Command-line arguments where permitted
    - Username and execution status
    """
    try:
        process = psutil.Process(pid)

        with process.oneshot():
            name = process.name()
            try:
                executable = process.exe() or None
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                executable = None

            try:
                parent_pid = process.ppid()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                parent_pid = None

            try:
                created = process.create_time()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                created = None

            try:
                cmdline_list = process.cmdline()
                command_line = " ".join(cmdline_list) if cmdline_list else None
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                command_line = None

            try:
                username = process.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                username = None

            try:
                status = process.status()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                status = None

        parent_name = None
        if parent_pid is not None:
            try:
                parent_process = psutil.Process(parent_pid)
                parent_name = parent_process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                parent_name = None

        file_meta = inspect_file_metadata(executable) if executable else None
        reasons = []

        if file_meta and file_meta.get("is_writable_location"):
            reasons.append("Executable is inside a user-writable location")

        started_at = (
            datetime.fromtimestamp(created, timezone.utc).isoformat()
            if created
            else None
        )

        return {
            "event_type": "process_observed",
            "timestamp": started_at or utc_now(),
            "pid": pid,
            "create_time": created,
            "process_identity": f"{pid}_{int(created or 0)}",
            "parent_pid": parent_pid,
            "parent_name": parent_name,
            "process_name": name,
            "executable": executable,
            "command_line": command_line,
            "username": username,
            "status": status,
            "process_started_at": started_at,
            "file_metadata": file_meta,
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
    """Capture a snapshot of all active processes."""
    snapshot = {}

    for process in psutil.process_iter(["pid"]):
        try:
            pid = process.info["pid"]
            if pid is None:
                continue

            event = inspect_process(pid)
            if event:
                snapshot[pid] = event
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue

    return snapshot


def find_new_processes(
    previous: dict[int, dict],
    current: dict[int, dict],
) -> list[dict]:
    """Identify processes present in current snapshot but missing from previous snapshot (accounting for PID reuse)."""
    new_procs = []
    for pid, proc in current.items():
        prev_proc = previous.get(pid)
        is_new = prev_proc is None or (
            proc.get("create_time") is not None
            and prev_proc.get("create_time") is not None
            and proc.get("create_time") != prev_proc.get("create_time")
        )
        if is_new:
            event = dict(proc)
            event["event_type"] = "process_started"
            new_procs.append(event)
    return new_procs


def find_terminated_processes(
    previous: dict[int, dict],
    current: dict[int, dict],
) -> list[dict]:
    """Identify processes present in previous snapshot but missing from current snapshot (accounting for PID reuse)."""
    terminated = []
    now = utc_now()
    for pid, proc in previous.items():
        curr_proc = current.get(pid)
        is_terminated = curr_proc is None or (
            proc.get("create_time") is not None
            and curr_proc.get("create_time") is not None
            and proc.get("create_time") != curr_proc.get("create_time")
        )
        if is_terminated:
            event = dict(proc)
            event["event_type"] = "process_terminated"
            event["terminated_at"] = now
            event["timestamp"] = now
            terminated.append(event)
    return terminated


def detect_process_changes(
    previous: dict[int, dict],
    current: dict[int, dict],
) -> dict[str, list[dict]]:
    """Detect both newly started and terminated processes (accounting for PID reuse)."""
    started = find_new_processes(previous, current)
    terminated = find_terminated_processes(previous, current)
    return {
        "started": started,
        "new": started,
        "terminated": terminated,
    }

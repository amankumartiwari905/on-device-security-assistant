"""Scheduled task monitoring for Windows using schtasks."""

import csv
from datetime import datetime, timezone
import io
import subprocess


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def snapshot_scheduled_tasks() -> dict[str, dict]:
    """
    Capture a snapshot of all configured Windows Scheduled Tasks.
    Returns a dictionary keyed by task_name.
    """
    tasks = {}

    try:
        result = subprocess.run(
            ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

        output = result.stdout
        if not output and result.stderr:
            # Fallback without verbose if /v is unavailable
            fallback = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "CSV"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
            output = fallback.stdout

        if not output:
            return tasks

        reader = csv.DictReader(io.StringIO(output))
        for row in reader:
            task_name = row.get("TaskName") or row.get("Task Name")
            if not task_name:
                continue

            task_name = task_name.strip()
            task_to_run = (row.get("Task To Run") or row.get("Task to Run") or "").strip()
            status = (row.get("Status") or row.get("Scheduled Task State") or "").strip()
            author = (row.get("Author") or "").strip()
            run_as_user = (row.get("Run As User") or "").strip()
            next_run = (row.get("Next Run Time") or "").strip()
            last_run = (row.get("Last Run Time") or "").strip()

            tasks[task_name] = {
                "task_name": task_name,
                "status": status,
                "task_to_run": task_to_run,
                "author": author,
                "run_as_user": run_as_user,
                "next_run_time": next_run,
                "last_run_time": last_run,
            }

    except (OSError, subprocess.TimeoutExpired, csv.Error):
        pass

    return tasks


def find_task_changes(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> dict[str, list[dict]]:
    """
    Detect newly created, modified, and deleted scheduled tasks.
    """
    created = []
    modified = []
    deleted = []
    now = utc_now()

    for name, task in current.items():
        if name not in previous:
            event = dict(task)
            event["event_type"] = "scheduled_task_created"
            event["timestamp"] = now
            created.append(event)
        else:
            prev = previous[name]
            # Check if action/command or state changed
            if task.get("task_to_run") != prev.get("task_to_run") or task.get("run_as_user") != prev.get("run_as_user"):
                event = dict(task)
                event["event_type"] = "scheduled_task_modified"
                event["previous_task_to_run"] = prev.get("task_to_run")
                event["timestamp"] = now
                modified.append(event)

    for name, task in previous.items():
        if name not in current:
            event = dict(task)
            event["event_type"] = "scheduled_task_deleted"
            event["timestamp"] = now
            deleted.append(event)

    return {
        "created": created,
        "modified": modified,
        "deleted": deleted,
    }


"""Windows service monitoring for installed and modified services."""

from datetime import datetime, timezone

import psutil


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def snapshot_services() -> dict[str, dict]:
    """
    Capture a snapshot of all Windows services.
    Returns a dictionary keyed by lowercase service name.
    """
    services = {}

    if not hasattr(psutil, "win_service_iter"):
        return services

    for svc in psutil.win_service_iter():
        try:
            name = svc.name()
            try:
                display_name = svc.display_name()
            except Exception:
                display_name = name

            try:
                binpath = svc.binpath() or ""
            except Exception:
                binpath = ""

            try:
                status = svc.status()
            except Exception:
                status = "unknown"

            try:
                start_type = svc.start_type()
            except Exception:
                start_type = "unknown"

            try:
                username = svc.username()
            except Exception:
                username = None

            try:
                description = svc.description()
            except Exception:
                description = None

            key = name.lower()
            services[key] = {
                "name": name,
                "display_name": display_name,
                "binpath": binpath,
                "status": status,
                "start_type": start_type,
                "username": username,
                "description": description,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue

    return services


def find_service_changes(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> dict[str, list[dict]]:
    """
    Detect newly installed, modified, and removed Windows services.
    """
    installed = []
    modified = []
    removed = []
    now = utc_now()

    for key, svc in current.items():
        if key not in previous:
            event = dict(svc)
            event["event_type"] = "service_installed"
            event["timestamp"] = now
            installed.append(event)
        else:
            prev = previous[key]
            # Check if binary path, status, or start type changed
            if (
                svc.get("binpath") != prev.get("binpath")
                or svc.get("start_type") != prev.get("start_type")
                or svc.get("status") != prev.get("status")
            ):
                event = dict(svc)
                event["event_type"] = "service_modified"
                event["previous_binpath"] = prev.get("binpath")
                event["previous_status"] = prev.get("status")
                event["previous_start_type"] = prev.get("start_type")
                event["timestamp"] = now
                modified.append(event)

    for key, svc in previous.items():
        if key not in current:
            event = dict(svc)
            event["event_type"] = "service_removed"
            event["timestamp"] = now
            removed.append(event)

    return {
        "installed": installed,
        "modified": modified,
        "removed": removed,
    }


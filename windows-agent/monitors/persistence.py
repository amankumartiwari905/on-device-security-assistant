"""Startup persistence monitoring for Windows (Registry Run keys & Startup folders)."""

from datetime import datetime, timezone
import os
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows or mocked testing


REGISTRY_RUN_LOCATIONS = [
    (
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "user",
    ),
    (
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "user",
    ),
    (
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "system",
    ),
    (
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "system",
    ),
    (
        "HKEY_LOCAL_MACHINE",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "system",
    ),
    (
        "HKEY_LOCAL_MACHINE",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "system",
    ),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_startup_folders() -> list[tuple[str, Path, str]]:
    """Return list of (label, path, scope) for Windows startup folders."""
    folders = []

    appdata = os.environ.get("APPDATA")
    if appdata:
        user_startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        folders.append(("User Startup Folder", user_startup, "user"))

    progdata = os.environ.get("PROGRAMDATA")
    if progdata:
        common_startup = Path(progdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        folders.append(("Common Startup Folder", common_startup, "system"))

    return folders


def _query_registry_location(root_name: str, subkey: str, scope: str) -> dict[str, dict]:
    """Query a single registry run key."""
    items = {}
    if not winreg:
        return items

    root_key = (
        winreg.HKEY_CURRENT_USER
        if root_name == "HKEY_CURRENT_USER"
        else winreg.HKEY_LOCAL_MACHINE
    )

    try:
        with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                try:
                    name, command, _type = winreg.EnumValue(key, i)
                    item_id = f"{root_name}\\{subkey}\\{name}"
                    items[item_id] = {
                        "item_id": item_id,
                        "name": str(name),
                        "command": str(command),
                        "location": f"{root_name}\\{subkey}",
                        "location_type": "registry",
                        "scope": scope,
                    }
                except (OSError, ValueError):
                    continue
    except (OSError, FileNotFoundError, PermissionError):
        pass

    return items


def _query_startup_folder(label: str, folder_path: Path, scope: str) -> dict[str, dict]:
    """Inspect files inside a Startup folder."""
    items = {}
    if not folder_path.is_dir():
        return items

    try:
        for entry in folder_path.iterdir():
            if entry.name.lower() in {"desktop.ini"}:
                continue
            item_id = f"Folder:{str(entry)}"
            items[item_id] = {
                "item_id": item_id,
                "name": entry.name,
                "command": str(entry),
                "location": str(folder_path),
                "location_type": "folder",
                "scope": scope,
            }
    except (OSError, PermissionError):
        pass

    return items


def snapshot_startup_items() -> dict[str, dict]:
    """Capture a snapshot of all active Windows startup persistence locations."""
    snapshot = {}

    for root_name, subkey, scope in REGISTRY_RUN_LOCATIONS:
        snapshot.update(_query_registry_location(root_name, subkey, scope))

    for label, folder, scope in get_startup_folders():
        snapshot.update(_query_startup_folder(label, folder, scope))

    return snapshot


def find_startup_changes(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> dict[str, list[dict]]:
    """
    Detect newly added, modified, and removed startup persistence items.
    """
    added = []
    removed = []
    modified = []
    now = utc_now()

    for item_id, item in current.items():
        if item_id not in previous:
            event = dict(item)
            event["event_type"] = "startup_item_added"
            event["timestamp"] = now
            added.append(event)
        elif item.get("command") != previous[item_id].get("command"):
            event = dict(item)
            event["event_type"] = "startup_item_modified"
            event["previous_command"] = previous[item_id].get("command")
            event["timestamp"] = now
            modified.append(event)

    for item_id, item in previous.items():
        if item_id not in current:
            event = dict(item)
            event["event_type"] = "startup_item_removed"
            event["timestamp"] = now
            removed.append(event)

    return {
        "added": added,
        "modified": modified,
        "removed": removed,
    }


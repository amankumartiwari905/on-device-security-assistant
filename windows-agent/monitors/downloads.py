"""File download and drop monitoring for Windows user directories."""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from monitors.file_metadata import inspect_file_metadata
from monitors.signatures import inspect_signature


TEMPORARY_DOWNLOAD_EXTENSIONS = {
    ".crdownload",  # Chrome / Chromium / Edge
    ".part",        # Firefox
    ".download",    # Safari / WebKit
    ".tmp",         # Generic temp download
}

MONITORED_EXTENSIONS = {
    ".exe",
    ".msi",
    ".dll",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".scr",
    ".iso",
    ".img",
    ".zip",
    ".rar",
    ".7z",
    ".jar",
    ".pif",
    ".cpl",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_watched_download_directories(
    custom_dirs: list[str | Path] | None = None,
) -> list[Path]:
    """Retrieve directories to monitor for newly downloaded or dropped files."""
    watched: list[Path] = []
    home = Path.home()

    # User's default Downloads and Desktop
    downloads_dir = home / "Downloads"
    if downloads_dir.exists():
        watched.append(downloads_dir)

    desktop_dir = home / "Desktop"
    if desktop_dir.exists():
        watched.append(desktop_dir)

    if custom_dirs:
        for d in custom_dirs:
            p = Path(d).resolve()
            if p.exists() and p not in watched:
                watched.append(p)

    return watched


def snapshot_download_directory(
    directories: list[str | Path] | None = None,
) -> dict[str, dict]:
    """
    Take a point-in-time snapshot of files in monitored download folders.
    Returns mapping of resolved file path to metadata.
    """
    target_dirs = (
        [Path(d).resolve() for d in directories]
        if directories
        else get_watched_download_directories()
    )

    snapshot: dict[str, dict] = {}
    for folder in target_dirs:
        if not folder.is_dir():
            continue
        try:
            for entry in os.scandir(folder):
                try:
                    if entry.is_file(follow_symlinks=False):
                        ext = Path(entry.name).suffix.lower()
                        st = entry.stat()
                        snapshot[str(Path(entry.path).resolve())] = {
                            "path": str(Path(entry.path).resolve()),
                            "name": entry.name,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                            "ext": ext,
                            "is_temp_download": ext in TEMPORARY_DOWNLOAD_EXTENSIONS,
                        }
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue

    return snapshot


def find_download_changes(
    previous_snapshot: dict[str, dict],
    current_snapshot: dict[str, dict],
) -> list[dict]:
    """
    Detect newly downloaded or finished download files between two snapshots.
    Filters out transient in-progress files (.crdownload) until the final file appears.
    """
    new_files: list[dict] = []

    for path, meta in current_snapshot.items():
        # Skip temporary files still downloading
        if meta.get("is_temp_download"):
            continue

        prev_meta = previous_snapshot.get(path)
        # 1. Completely new file
        if prev_meta is None:
            new_files.append(meta)
        # 2. File completed and size finalized after download
        elif prev_meta.get("is_temp_download") and not meta.get("is_temp_download"):
            new_files.append(meta)

    return new_files


def inspect_downloaded_file(file_path: str | Path) -> dict:
    """
    Collect comprehensive file information for an observed downloaded file:
    - SHA-256 hash
    - Digital Authenticode signature
    - File location & metadata
    - Mark-of-the-Web (Zone.Identifier: ZoneId, HostUrl, ReferrerUrl)
    """
    p = Path(file_path).resolve()
    meta = inspect_file_metadata(p)
    sig = inspect_signature(str(p)) if meta.get("exists") else {
        "status": "unavailable",
        "signer": None,
        "is_valid": False,
        "message": "File not found",
    }

    zone_info = meta.get("zone_identifier") or {}

    return {
        "event_type": "file_download_observed",
        "timestamp": utc_now(),
        "file_path": str(p),
        "filename": p.name,
        "extension": p.suffix.lower(),
        "sha256": meta.get("sha256"),
        "size_bytes": meta.get("size_bytes", 0),
        "size_formatted": meta.get("size_formatted", "0 B"),
        "is_writable_location": meta.get("is_writable_location", True),
        "file_metadata": meta,
        "signature": sig,
        "mark_of_the_web": meta.get("has_mark_of_the_web", False),
        "zone_id": meta.get("zone_id"),
        "download_url": meta.get("download_url"),
        "referrer_url": zone_info.get("referrer_url"),
    }


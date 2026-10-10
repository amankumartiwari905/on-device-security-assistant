"""File metadata analysis for executables and system binaries."""

from datetime import datetime, timezone
import functools
import hashlib
import os
from pathlib import Path


WRITABLE_DIRECTORY_NAMES = {
    "downloads",
    "temp",
    "tmp",
    "appdata",
    "roaming",
    "local",
}


def format_file_size(size_bytes: int) -> str:
    """Format bytes into a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def is_potentially_writable_location(path: Path) -> bool:
    """Check if the path resides inside user-writable directories (Temp, Downloads, AppData, etc.)."""
    try:
        resolved = path.resolve()
        home = Path.home().resolve()
        temp = Path(os.environ.get("TEMP", str(home))).resolve()

        if resolved.is_relative_to(temp) or resolved.is_relative_to(home):
            return True

        parts = {p.lower() for p in resolved.parts}
        return bool(parts & WRITABLE_DIRECTORY_NAMES)
    except (OSError, ValueError):
        return False


@functools.lru_cache(maxsize=1024)
def _compute_sha256_cached(resolved_path: str, mtime: float, size: int) -> str | None:
    """Compute SHA-256 hash with caching based on path, mtime, and size."""
    try:
        hasher = hashlib.sha256()
        with open(resolved_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def calculate_file_hash(file_path: str | Path) -> str | None:
    """Calculate the SHA-256 hash of a file safely."""
    try:
        p = Path(file_path).resolve()
        if not p.is_file():
            return None
        st = p.stat()
        return _compute_sha256_cached(str(p), st.st_mtime, st.st_size)
    except (OSError, ValueError):
        return None


def inspect_zone_identifier(file_path: str | Path | None) -> dict:
    """
    Inspect the NTFS Zone.Identifier Alternate Data Stream (Mark of the Web).
    Determines if a file was downloaded from the Internet (ZoneId=3) and
    extracts the origin HostUrl and ReferrerUrl if recorded by the browser.
    """
    if not file_path:
        return {
            "has_mark_of_the_web": False,
            "zone_id": None,
            "host_url": None,
            "referrer_url": None,
        }

    ads_path = f"{file_path}:Zone.Identifier"
    try:
        with open(ads_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (FileNotFoundError, OSError, PermissionError):
        return {
            "has_mark_of_the_web": False,
            "zone_id": None,
            "host_url": None,
            "referrer_url": None,
        }

    zone_id = None
    host_url = None
    referrer_url = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("ZoneId="):
            try:
                zone_id = int(line.split("=", 1)[1])
            except ValueError:
                pass
        elif line.startswith("HostUrl="):
            host_url = line.split("=", 1)[1].strip()
        elif line.startswith("ReferrerUrl="):
            referrer_url = line.split("=", 1)[1].strip()

    return {
        "has_mark_of_the_web": bool(zone_id is not None),
        "zone_id": zone_id,
        "host_url": host_url,
        "referrer_url": referrer_url,
    }


def inspect_file_metadata(file_path: str | Path | None) -> dict:
    """
    Inspect executable metadata including location, file size, timestamps, and SHA-256 hash.
    """
    if not file_path:
        return {
            "path": None,
            "exists": False,
            "directory": None,
            "filename": None,
            "size_bytes": 0,
            "size_formatted": "0 B",
            "created_at": None,
            "modified_at": None,
            "sha256": None,
            "is_writable_location": False,
            "has_mark_of_the_web": False,
            "zone_id": None,
            "zone_identifier": inspect_zone_identifier(None),
        }

    try:
        path = Path(file_path).resolve()
    except (OSError, ValueError):
        return {
            "path": str(file_path),
            "exists": False,
            "directory": None,
            "filename": None,
            "size_bytes": 0,
            "size_formatted": "0 B",
            "created_at": None,
            "modified_at": None,
            "sha256": None,
            "is_writable_location": False,
            "has_mark_of_the_web": False,
            "zone_id": None,
            "zone_identifier": inspect_zone_identifier(None),
        }

    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "directory": str(path.parent),
            "filename": path.name,
            "size_bytes": 0,
            "size_formatted": "0 B",
            "created_at": None,
            "modified_at": None,
            "sha256": None,
            "is_writable_location": is_potentially_writable_location(path),
            "has_mark_of_the_web": False,
            "zone_id": None,
            "zone_identifier": inspect_zone_identifier(None),
        }

    zone_info = inspect_zone_identifier(path)

    try:
        st = path.stat()
        size_bytes = st.st_size
        created_at = datetime.fromtimestamp(st.st_ctime, timezone.utc).isoformat()
        modified_at = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()
        sha256 = _compute_sha256_cached(str(path), st.st_mtime, size_bytes)
    except (OSError, PermissionError):
        size_bytes = 0
        created_at = None
        modified_at = None
        sha256 = None

    return {
        "path": str(path),
        "exists": True,
        "directory": str(path.parent),
        "filename": path.name,
        "size_bytes": size_bytes,
        "size_formatted": format_file_size(size_bytes),
        "created_at": created_at,
        "modified_at": modified_at,
        "sha256": sha256,
        "is_writable_location": is_potentially_writable_location(path),
        "has_mark_of_the_web": zone_info.get("has_mark_of_the_web", False),
        "zone_id": zone_info.get("zone_id"),
        "download_url": zone_info.get("host_url"),
        "zone_identifier": zone_info,
    }


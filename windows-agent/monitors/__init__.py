"""Monitors package for Windows security agent."""

from monitors.processes import (
    inspect_process,
    snapshot_processes,
    find_new_processes,
    find_terminated_processes,
    detect_process_changes,
)
from monitors.signatures import inspect_signature
from monitors.file_metadata import (
    inspect_file_metadata,
    calculate_file_hash,
    is_potentially_writable_location,
    inspect_zone_identifier,
)
from monitors.persistence import (
    snapshot_startup_items,
    find_startup_changes,
)
from monitors.tasks import (
    snapshot_scheduled_tasks,
    find_task_changes,
)
from monitors.services import (
    snapshot_services,
    find_service_changes,
)
from monitors.network import (
    snapshot_connections,
    find_new_connections,
    ConnectionTracker,
)
from monitors.ip_intelligence import (
    lookup_ip_intelligence,
    check_ip_reputation,
    is_public_ip,
    identify_hosting_provider,
)
from monitors.dns import (
    snapshot_dns_cache,
    find_dns_changes,
    analyze_domain,
    calculate_entropy,
)
from monitors.downloads import (
    snapshot_download_directory,
    find_download_changes,
    inspect_downloaded_file,
    get_watched_download_directories,
)

__all__ = [
    "inspect_process",
    "snapshot_processes",
    "find_new_processes",
    "find_terminated_processes",
    "detect_process_changes",
    "inspect_signature",
    "inspect_file_metadata",
    "calculate_file_hash",
    "is_potentially_writable_location",
    "inspect_zone_identifier",
    "snapshot_startup_items",
    "find_startup_changes",
    "snapshot_scheduled_tasks",
    "find_task_changes",
    "snapshot_services",
    "find_service_changes",
    "snapshot_connections",
    "find_new_connections",
    "ConnectionTracker",
    "lookup_ip_intelligence",
    "check_ip_reputation",
    "is_public_ip",
    "identify_hosting_provider",
    "snapshot_dns_cache",
    "find_dns_changes",
    "analyze_domain",
    "calculate_entropy",
    "snapshot_download_directory",
    "find_download_changes",
    "inspect_downloaded_file",
    "get_watched_download_directories",
]

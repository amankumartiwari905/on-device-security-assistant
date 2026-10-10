"""Storage package for PhishGuard Windows Security Agent."""

from storage.events import (
    initialize_database,
    save_event,
    get_event,
    recent_events,
    query_events,
    get_event_count,
    get_event_stats,
    compute_event_fingerprint,
    utc_now,
)
from storage.queue import (
    fetch_pending_events,
    mark_events_synced,
    mark_event_failed,
    mark_batch_failed,
    reset_failed_events,
    get_queue_stats,
    SyncWorker,
)
from storage.retention import (
    purge_expired_events,
    apply_retention_policy,
)
from storage.logger import (
    setup_logging,
    get_logger,
)

__all__ = [
    "initialize_database",
    "save_event",
    "get_event",
    "recent_events",
    "query_events",
    "get_event_count",
    "get_event_stats",
    "compute_event_fingerprint",
    "utc_now",
    "fetch_pending_events",
    "mark_events_synced",
    "mark_event_failed",
    "mark_batch_failed",
    "reset_failed_events",
    "get_queue_stats",
    "SyncWorker",
    "purge_expired_events",
    "apply_retention_policy",
    "setup_logging",
    "get_logger",
]


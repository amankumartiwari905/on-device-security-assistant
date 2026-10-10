"""Offline queue and background retry worker for event synchronization."""

from collections.abc import Callable
import json
import logging
from pathlib import Path
import sqlite3
import threading
import time
import urllib.error
import urllib.request

from config import (
    DATABASE_PATH,
    SYNC_BATCH_SIZE,
    SYNC_MAX_RETRIES,
    SYNC_INTERVAL_SECONDS,
    BACKEND_API_URL,
)
from storage.events import initialize_database, utc_now

logger = logging.getLogger("phishguard.queue")


def fetch_pending_events(
    batch_size: int = SYNC_BATCH_SIZE,
    max_retries: int = SYNC_MAX_RETRIES,
    db_path: str | Path = DATABASE_PATH,
) -> list[dict]:
    """
    Fetch unsent events from the offline queue.
    Retrieves events that are 'pending' or 'failed' with retry_count < max_retries.
    """
    initialize_database(db_path)
    limit = max(1, min(int(batch_size), 500))

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT * FROM security_events
            WHERE sync_status IN ('pending', 'failed')
              AND retry_count < ?
            ORDER BY id ASC
            LIMIT ?
        """, (max_retries, limit)).fetchall()

    return [dict(row) for row in rows]


def mark_events_synced(
    event_ids: list[int],
    db_path: str | Path = DATABASE_PATH,
) -> int:
    """Mark events as successfully synced to the backend."""
    if not event_ids:
        return 0

    initialize_database(db_path)
    now = utc_now()
    placeholders = ",".join("?" for _ in event_ids)

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        cursor = connection.execute(f"""
            UPDATE security_events
            SET sync_status = 'synced',
                last_sync_attempt = ?,
                error_message = NULL
            WHERE id IN ({placeholders})
        """, [now, *event_ids])
        connection.commit()
        return cursor.rowcount


def mark_event_failed(
    event_id: int,
    error_message: str,
    db_path: str | Path = DATABASE_PATH,
) -> None:
    """Increment retry count and record sync failure message."""
    initialize_database(db_path)
    now = utc_now()

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        connection.execute("""
            UPDATE security_events
            SET sync_status = 'failed',
                retry_count = retry_count + 1,
                last_sync_attempt = ?,
                error_message = ?
            WHERE id = ?
        """, (now, str(error_message)[:500], event_id))
        connection.commit()


def mark_batch_failed(
    event_ids: list[int],
    error_message: str,
    db_path: str | Path = DATABASE_PATH,
) -> None:
    """Mark a batch of events as failed with an incremented retry count."""
    for event_id in event_ids:
        mark_event_failed(event_id, error_message, db_path=db_path)


def reset_failed_events(db_path: str | Path = DATABASE_PATH) -> int:
    """Reset failed events so they can be re-attempted from scratch."""
    initialize_database(db_path)
    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        cursor = connection.execute("""
            UPDATE security_events
            SET sync_status = 'pending',
                retry_count = 0,
                error_message = NULL
            WHERE sync_status = 'failed'
        """)
        connection.commit()
        return cursor.rowcount


def get_queue_stats(db_path: str | Path = DATABASE_PATH) -> dict:
    """Return offline queue metrics and status counts."""
    initialize_database(db_path)
    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        pending_count = connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE sync_status = 'pending'"
        ).fetchone()[0]
        synced_count = connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE sync_status = 'synced'"
        ).fetchone()[0]
        failed_count = connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE sync_status = 'failed'"
        ).fetchone()[0]
        exhausted_count = connection.execute("""
            SELECT COUNT(*) FROM security_events
            WHERE sync_status = 'failed' AND retry_count >= ?
        """, (SYNC_MAX_RETRIES,)).fetchone()[0]

    return {
        "pending": pending_count,
        "synced": synced_count,
        "failed": failed_count,
        "exhausted": exhausted_count,
    }


class SyncWorker:
    """
    Non-blocking background sync worker with exponential backoff.
    
    Reads unsent events from the local SQLite database and uploads them
    to the backend without interrupting the main security monitoring loops.
    """

    def __init__(
        self,
        db_path: str | Path = DATABASE_PATH,
        sync_handler: Callable[[list[dict]], bool] | None = None,
        api_url: str | None = BACKEND_API_URL,
        interval_seconds: float = SYNC_INTERVAL_SECONDS,
        batch_size: int = SYNC_BATCH_SIZE,
        max_retries: int = SYNC_MAX_RETRIES,
        base_backoff: float = 2.0,
        max_backoff: float = 60.0,
        backoff_factor: float = 2.0,
    ) -> None:
        self.db_path = db_path
        self.sync_handler = sync_handler
        self.api_url = api_url
        self.interval_seconds = max(0.5, float(interval_seconds))
        self.batch_size = max(1, int(batch_size))
        self.max_retries = max(1, int(max_retries))
        self.base_backoff = max(0.5, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        self.backoff_factor = max(1.1, float(backoff_factor))

        self._current_delay = self.base_backoff
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _default_http_sync(self, events: list[dict]) -> bool:
        """Transmit events to backend API via standard HTTP POST request."""
        if not self.api_url:
            return False

        payload = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            self.api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.debug("Backend upload failed: %s", exc)
            return False

    def sync_once(self) -> dict:
        """
        Execute a single sync pass:
        1. Fetch pending events.
        2. Attempt transmission.
        3. On success, mark synced and reset backoff.
        4. On failure, increment retry count and apply exponential backoff.
        """
        pending = fetch_pending_events(
            batch_size=self.batch_size,
            max_retries=self.max_retries,
            db_path=self.db_path,
        )

        if not pending:
            return {"synced": 0, "failed": 0, "pending": 0, "status": "idle"}

        event_ids = [e["id"] for e in pending]
        success = False
        error_msg = ""

        try:
            if self.sync_handler is not None:
                success = bool(self.sync_handler(pending))
                if not success:
                    error_msg = "Custom sync_handler returned False"
            elif self.api_url:
                success = self._default_http_sync(pending)
                if not success:
                    error_msg = f"HTTP request to {self.api_url} failed"
            else:
                error_msg = "No sync_handler or api_url configured"
                success = False
        except Exception as exc:
            success = False
            error_msg = f"Sync exception: {exc}"

        if success:
            mark_events_synced(event_ids, db_path=self.db_path)
            self._current_delay = self.base_backoff
            logger.debug("Synced %d events to backend", len(event_ids))
            return {
                "synced": len(event_ids),
                "failed": 0,
                "status": "success",
            }
        else:
            mark_batch_failed(event_ids, error_msg or "Sync error", db_path=self.db_path)
            self._current_delay = min(
                self._current_delay * self.backoff_factor, self.max_backoff
            )
            logger.debug(
                "Sync failed for %d events; backing off to %.1fs (reason: %s)",
                len(event_ids),
                self._current_delay,
                error_msg,
            )
            return {
                "synced": 0,
                "failed": len(event_ids),
                "error": error_msg,
                "status": "failed",
                "next_backoff": self._current_delay,
            }

    def _worker_loop(self) -> None:
        """Background daemon thread worker loop."""
        while not self._stop_event.is_set():
            result = self.sync_once()

            # If there were items synced, check again soon; if failed, apply backoff delay
            sleep_duration = (
                self.interval_seconds
                if result.get("status") == "success"
                else self._current_delay
            )
            self._stop_event.wait(timeout=sleep_duration)

    def start(self) -> None:
        """Start the background sync worker thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker_loop,
            name="PhishGuardSyncWorker",
            daemon=True,
        )
        self._thread.start()
        logger.info("Sync worker thread started.")

    def stop(self, timeout: float = 3.0) -> None:
        """Stop the sync worker gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("Sync worker thread stopped.")

    def is_running(self) -> bool:
        """Check if background worker thread is active."""
        return bool(self._thread and self._thread.is_alive())


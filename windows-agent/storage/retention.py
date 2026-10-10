"""Retention policy enforcement for the local SQLite event database."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from config import (
    DATABASE_PATH,
    RETENTION_DAYS,
    MAX_DB_RECORDS,
    RETENTION_KEEP_HIGH_SEVERITY,
)
from storage.events import initialize_database


def purge_expired_events(
    retention_days: int = RETENTION_DAYS,
    max_records: int = MAX_DB_RECORDS,
    keep_high_severity: bool = RETENTION_KEEP_HIGH_SEVERITY,
    db_path: str | Path = DATABASE_PATH,
) -> dict:
    """
    Apply database retention policies:
    1. Purge events older than `retention_days`.
    2. Enforce `max_records` cap by deleting oldest non-critical records first.
    3. Return execution summary.
    """
    initialize_database(db_path)

    cutoff_date = (
        datetime.now(timezone.utc) - timedelta(days=max(1, int(retention_days)))
    ).isoformat()
    purged_by_age = 0
    purged_by_capacity = 0

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        # Phase 1: Age-based purging
        if keep_high_severity:
            cursor = connection.execute(
                """
                DELETE FROM security_events
                WHERE timestamp < ? AND severity NOT IN ('high', 'critical')
                """,
                (cutoff_date,),
            )
        else:
            cursor = connection.execute(
                "DELETE FROM security_events WHERE timestamp < ?",
                (cutoff_date,),
            )
        purged_by_age = cursor.rowcount

        # Phase 2: Capacity-based pruning
        current_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        if current_count > max_records:
            excess = current_count - max_records
            if keep_high_severity:
                cursor = connection.execute("""
                    DELETE FROM security_events
                    WHERE id IN (
                        SELECT id FROM security_events
                        WHERE severity NOT IN ('high', 'critical')
                        ORDER BY id ASC
                        LIMIT ?
                    )
                """, (excess,))
                purged_by_capacity = cursor.rowcount

                # If still over limit because of high severity items, enforce strict hard limit
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0]
                if remaining > max_records:
                    still_excess = remaining - max_records
                    c2 = connection.execute("""
                        DELETE FROM security_events
                        WHERE id IN (
                            SELECT id FROM security_events
                            ORDER BY id ASC
                            LIMIT ?
                        )
                    """, (still_excess,))
                    purged_by_capacity += c2.rowcount
            else:
                cursor = connection.execute("""
                    DELETE FROM security_events
                    WHERE id IN (
                        SELECT id FROM security_events
                        ORDER BY id ASC
                        LIMIT ?
                    )
                """, (excess,))
                purged_by_capacity = cursor.rowcount

        connection.commit()

        if purged_by_age > 0 or purged_by_capacity > 0:
            connection.execute("PRAGMA optimize;")

        remaining_count = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    return {
        "purged_by_age": purged_by_age,
        "purged_by_capacity": purged_by_capacity,
        "total_purged": purged_by_age + purged_by_capacity,
        "remaining_records": remaining_count,
    }


def apply_retention_policy(
    retention_days: int = RETENTION_DAYS,
    max_records: int = MAX_DB_RECORDS,
    keep_high_severity: bool = RETENTION_KEEP_HIGH_SEVERITY,
    db_path: str | Path = DATABASE_PATH,
) -> dict:
    """Convenience alias for running full retention policy cleanup."""
    return purge_expired_events(
        retention_days=retention_days,
        max_records=max_records,
        keep_high_severity=keep_high_severity,
        db_path=db_path,
    )


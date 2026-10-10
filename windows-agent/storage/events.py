"""Local SQLite storage for security events with history, deduplication, and offline queue status."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from config import DATABASE_PATH, DEDUP_WINDOW_SECONDS


def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def compute_event_fingerprint(event: dict, findings: list[dict] | None = None) -> str:
    """Generate a deterministic SHA-256 fingerprint for database-level deduplication."""
    rule_ids = sorted([f.get("rule_id", "") for f in (findings or []) if f.get("rule_id")])
    target = (
        event.get("executable")
        or event.get("process_name")
        or event.get("domain")
        or event.get("name")
        or event.get("task_name")
        or event.get("service_name")
        or ""
    ).lower()
    event_type = event.get("event_type", "unknown")
    remote_ip = event.get("remote_ip", "")
    remote_port = str(event.get("remote_port", ""))

    key_str = f"{event_type}|{target}|{remote_ip}|{remote_port}|{','.join(rule_ids)}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()


def initialize_database(db_path: str | Path = DATABASE_PATH) -> None:
    """Initialize SQLite database schema and migrate missing columns if needed."""
    db_file = Path(db_path)
    if db_file.parent and not db_file.parent.exists():
        db_file.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(db_file), timeout=10.0) as connection:
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                process_name TEXT,
                pid INTEGER,
                executable TEXT,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                fingerprint TEXT,
                repeat_count INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT,
                sync_status TEXT DEFAULT 'pending',
                retry_count INTEGER DEFAULT 0,
                last_sync_attempt TEXT,
                error_message TEXT
            )
        """)

        # Migration: Check existing columns in case table was created with an earlier schema
        cursor = connection.execute("PRAGMA table_info(security_events)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        migrations = [
            ("fingerprint", "TEXT"),
            ("repeat_count", "INTEGER DEFAULT 1"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
            ("sync_status", "TEXT DEFAULT 'pending'"),
            ("retry_count", "INTEGER DEFAULT 0"),
            ("last_sync_attempt", "TEXT"),
            ("error_message", "TEXT"),
        ]

        for col_name, col_type in migrations:
            if col_name not in existing_cols:
                connection.execute(
                    f"ALTER TABLE security_events ADD COLUMN {col_name} {col_type};"
                )

        # Performance and search indexes
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_sync_status ON security_events(sync_status);"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON security_events(fingerprint);"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);"
        )
        connection.commit()


def save_event(
    event: dict,
    findings: list[dict],
    assessment: dict,
    db_path: str | Path = DATABASE_PATH,
    deduplicate: bool = True,
    dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
) -> int:
    """
    Save or deduplicate a security event in SQLite.
    
    If an event with an identical fingerprint occurred within dedup_window_seconds,
    increments repeat_count and updates last_seen/score instead of inserting a duplicate row.
    """
    initialize_database(db_path)

    process_name = (
        event.get("process_name")
        or event.get("name")
        or event.get("task_name")
        or event.get("service_name")
    )
    executable = (
        event.get("executable")
        or event.get("binpath")
        or event.get("command")
        or event.get("task_to_run")
    )
    pid = event.get("pid")
    timestamp = event.get("timestamp") or utc_now()
    fingerprint = compute_event_fingerprint(event, findings)
    new_score = int(assessment.get("score", 0))
    new_severity = assessment.get("severity", "info")
    new_summary = assessment.get("summary", "")

    excluded_keys = {"timestamp", "event_type"}
    details = {
        "findings": findings,
        **{k: v for k, v in event.items() if k not in excluded_keys and v is not None},
    }

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        if deduplicate and fingerprint:
            cursor = connection.execute("""
                SELECT id, repeat_count, score, last_seen, timestamp
                FROM security_events
                WHERE fingerprint = ?
                ORDER BY id DESC LIMIT 1
            """, (fingerprint,))
            existing = cursor.fetchone()

            if existing:
                existing_id, repeat_count, old_score, last_seen, orig_timestamp = existing
                ref_time_str = last_seen or orig_timestamp
                is_within_window = False
                try:
                    if ref_time_str:
                        t_existing = datetime.fromisoformat(ref_time_str.replace("Z", "+00:00"))
                        t_current = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                        diff_seconds = abs((t_current - t_existing).total_seconds())
                        if diff_seconds <= dedup_window_seconds:
                            is_within_window = True
                except Exception:
                    is_within_window = True

                if is_within_window:
                    updated_score = max(old_score, new_score)
                    updated_repeat = (repeat_count or 1) + 1
                    connection.execute("""
                        UPDATE security_events
                        SET repeat_count = ?,
                            last_seen = ?,
                            score = ?,
                            summary = CASE WHEN ? > score THEN ? ELSE summary END,
                            severity = CASE WHEN ? > score THEN ? ELSE severity END
                        WHERE id = ?
                    """, (
                        updated_repeat,
                        timestamp,
                        updated_score,
                        new_score,
                        new_summary,
                        new_score,
                        new_severity,
                        existing_id,
                    ))
                    connection.commit()
                    return int(existing_id)

        # Insert new record with pending sync status
        cursor = connection.execute("""
            INSERT INTO security_events (
                timestamp, event_type, process_name, pid, executable,
                severity, score, summary, details_json,
                fingerprint, repeat_count, first_seen, last_seen,
                sync_status, retry_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0)
        """, (
            timestamp,
            event.get("event_type", "unknown"),
            process_name,
            pid,
            executable,
            new_severity,
            new_score,
            new_summary,
            json.dumps(details),
            fingerprint,
            1,
            timestamp,
            timestamp,
        ))
        connection.commit()
        return int(cursor.lastrowid)


def get_event(
    event_id: int,
    db_path: str | Path = DATABASE_PATH,
) -> dict | None:
    """Retrieve an event record by primary key id."""
    initialize_database(db_path)
    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM security_events WHERE id = ?", (event_id,)
        ).fetchone()
        return dict(row) if row else None


def recent_events(
    limit: int = 20,
    db_path: str | Path = DATABASE_PATH,
) -> list[dict]:
    """Retrieve recent events ordered by ID descending."""
    limit = max(1, min(int(limit), 500))
    initialize_database(db_path)

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def query_events(
    severity: str | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    event_type: str | None = None,
    sync_status: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db_path: str | Path = DATABASE_PATH,
) -> list[dict]:
    """Query event history with multi-attribute filtering."""
    initialize_database(db_path)
    clauses: list[str] = []
    params: list[Any] = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity.lower())
    if min_score is not None:
        clauses.append("score >= ?")
        params.append(int(min_score))
    if max_score is not None:
        clauses.append("score <= ?")
        params.append(int(max_score))
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if sync_status:
        clauses.append("sync_status = ?")
        params.append(sync_status)
    if start_time:
        clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        clauses.append("timestamp <= ?")
        params.append(end_time)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT * FROM security_events
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    params.extend([max(1, min(int(limit), 1000)), max(0, int(offset))])

    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(query, params).fetchall()

    return [dict(row) for row in rows]


def get_event_count(db_path: str | Path = DATABASE_PATH) -> int:
    """Return total number of records in security_events."""
    initialize_database(db_path)
    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        return connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]


def get_event_stats(db_path: str | Path = DATABASE_PATH) -> dict:
    """Return aggregate statistics across stored security events."""
    initialize_database(db_path)
    with sqlite3.connect(str(db_path), timeout=10.0) as connection:
        total = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]

        severity_counts = {}
        for row in connection.execute(
            "SELECT severity, COUNT(*) FROM security_events GROUP BY severity"
        ).fetchall():
            severity_counts[row[0]] = row[1]

        sync_counts = {}
        for row in connection.execute(
            "SELECT sync_status, COUNT(*) FROM security_events GROUP BY sync_status"
        ).fetchall():
            sync_counts[row[0]] = row[1]

        max_score_row = connection.execute(
            "SELECT MAX(score) FROM security_events"
        ).fetchone()
        max_score = (
            max_score_row[0] if max_score_row and max_score_row[0] is not None else 0
        )

        time_range = connection.execute(
            "SELECT MIN(timestamp), MAX(timestamp) FROM security_events"
        ).fetchone()
        oldest = time_range[0] if time_range else None
        newest = time_range[1] if time_range else None

    return {
        "total_events": total,
        "by_severity": severity_counts,
        "by_sync_status": sync_counts,
        "max_score": max_score,
        "oldest_timestamp": oldest,
        "newest_timestamp": newest,
    }

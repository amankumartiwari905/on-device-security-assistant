"""Local SQLite storage for security events."""

import json
import sqlite3
from pathlib import Path

from config import DATABASE_PATH


def initialize_database(db_path: str | Path = DATABASE_PATH) -> None:
    with sqlite3.connect(str(db_path)) as connection:
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
                details_json TEXT NOT NULL
            )
        """)
        connection.commit()


def save_event(
    event: dict,
    findings: list[dict],
    assessment: dict,
    db_path: str | Path = DATABASE_PATH,
) -> int:
    initialize_database(db_path)

    details = {
        "findings": findings,
        "parent_pid": event.get("parent_pid"),
        "protocol": event.get("protocol"),
        "local_ip": event.get("local_ip"),
        "local_port": event.get("local_port"),
        "remote_ip": event.get("remote_ip"),
        "remote_port": event.get("remote_port"),
        "status": event.get("status"),
    }

    with sqlite3.connect(str(db_path)) as connection:
        cursor = connection.execute("""
            INSERT INTO security_events (
                timestamp, event_type, process_name, pid, executable,
                severity, score, summary, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", ""),
            event.get("event_type", "unknown"),
            event.get("process_name"),
            event.get("pid"),
            event.get("executable"),
            assessment.get("severity", "info"),
            int(assessment.get("score", 0)),
            assessment.get("summary", ""),
            json.dumps(details),
        ))
        connection.commit()
        return int(cursor.lastrowid)


def recent_events(
    limit: int = 20,
    db_path: str | Path = DATABASE_PATH,
) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    initialize_database(db_path)

    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]

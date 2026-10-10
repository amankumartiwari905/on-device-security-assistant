"""Unit tests for SQLite storage of security events, offline queue, retention, and logging."""

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import sqlite3
import time

from storage.events import (
    initialize_database,
    save_event,
    recent_events,
    get_event,
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


def test_database_initialization_and_save(tmp_path: Path):
    db_file = tmp_path / "test_events.db"
    initialize_database(db_file)
    assert db_file.exists()

    event = {
        "timestamp": "2026-10-10T01:00:00Z",
        "event_type": "process_observed",
        "process_name": "calc.exe",
        "pid": 1234,
        "executable": r"C:\Windows\System32\calc.exe",
        "parent_pid": 5678,
    }
    findings = [
        {"rule_id": "PROC_OBSERVED", "title": "Normal process", "severity": "info"}
    ]
    assessment = {
        "score": 0,
        "severity": "info",
        "summary": "Informational finding.",
    }

    event_id = save_event(event, findings, assessment, db_path=db_file)
    assert event_id == 1

    events = recent_events(limit=10, db_path=db_file)
    assert len(events) == 1
    stored = events[0]
    assert stored["id"] == 1
    assert stored["event_type"] == "process_observed"
    assert stored["process_name"] == "calc.exe"
    assert stored["pid"] == 1234
    assert stored["score"] == 0

    details = json.loads(stored["details_json"])
    assert details["parent_pid"] == 5678
    assert len(details["findings"]) == 1


def test_persistence_event_saved_correctly(tmp_path: Path):
    db_file = tmp_path / "test_persist.db"

    event = {
        "timestamp": "2026-10-10T01:05:00Z",
        "event_type": "startup_item_added",
        "name": "MyStartup",
        "command": r"C:\Users\Alice\AppData\tool.exe",
        "location": "HKCU_Run",
    }
    findings = [
        {"rule_id": "PERSIST_WRITABLE_LOCATION", "title": "Writable persistence", "severity": "high"}
    ]
    assessment = {
        "score": 60,
        "severity": "high",
        "summary": "Suspicious startup entry.",
    }

    event_id = save_event(event, findings, assessment, db_path=db_file)
    assert event_id == 1

    events = recent_events(limit=5, db_path=db_file)
    assert len(events) == 1
    assert events[0]["process_name"] == "MyStartup"
    assert events[0]["executable"] == r"C:\Users\Alice\AppData\tool.exe"
    assert events[0]["score"] == 60


def test_task_event_saved_correctly(tmp_path: Path):
    db_file = tmp_path / "test_task.db"

    event = {
        "timestamp": "2026-10-10T01:10:00Z",
        "event_type": "scheduled_task_created",
        "task_name": "\\BadTask",
        "task_to_run": "powershell.exe -enc AAAA",
    }
    findings = [{"rule_id": "TASK_SUSPICIOUS_COMMAND", "title": "Suspicious task", "severity": "high"}]
    assessment = {"score": 60, "severity": "high", "summary": "Suspicious task"}

    save_event(event, findings, assessment, db_path=db_file)
    events = recent_events(limit=5, db_path=db_file)
    assert events[0]["process_name"] == "\\BadTask"
    assert events[0]["executable"] == "powershell.exe -enc AAAA"


def test_schema_migration_from_legacy_database(tmp_path: Path):
    """Test automatic migration when existing database lacks newer queue/dedup columns."""
    db_file = tmp_path / "legacy.db"

    # Create a table simulating the legacy schema (10 columns only)
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute("""
            CREATE TABLE security_events (
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
        conn.execute("""
            INSERT INTO security_events (
                timestamp, event_type, process_name, pid, executable,
                severity, score, summary, details_json
            ) VALUES ('2026-10-10T00:00:00Z', 'legacy_event', 'old.exe', 100, 'c:\\old.exe',
                      'low', 10, 'Old summary', '{}')
        """)
        conn.commit()

    # Run initialize_database which performs dynamic schema migration
    initialize_database(db_file)

    with sqlite3.connect(str(db_file)) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(security_events)").fetchall()}
        assert "fingerprint" in cols
        assert "repeat_count" in cols
        assert "sync_status" in cols
        assert "retry_count" in cols
        assert "last_sync_attempt" in cols
        assert "error_message" in cols

    # Verify existing record was preserved
    legacy_rec = get_event(1, db_path=db_file)
    assert legacy_rec is not None
    assert legacy_rec["process_name"] == "old.exe"
    assert legacy_rec["sync_status"] == "pending"

    # Verify saving new event on migrated database works cleanly
    new_id = save_event(
        {"timestamp": utc_now(), "event_type": "new_type", "process_name": "new.exe"},
        [],
        {"score": 20, "severity": "low", "summary": "New"},
        db_path=db_file,
    )
    assert new_id == 2


def test_event_deduplication_and_repeat_count(tmp_path: Path):
    """Test deduplication increments repeat_count and updates last_seen and score."""
    db_file = tmp_path / "dedup.db"

    event = {
        "timestamp": utc_now(),
        "event_type": "network_connection_observed",
        "process_name": "curl.exe",
        "remote_ip": "198.51.100.1",
        "remote_port": 443,
        "executable": r"C:\Windows\System32\curl.exe",
    }
    findings = [{"rule_id": "NET_OUTBOUND", "title": "Outbound connection"}]
    assessment = {"score": 20, "severity": "low", "summary": "Initial connection"}

    first_id = save_event(event, findings, assessment, db_path=db_file, deduplicate=True)
    assert first_id == 1

    # Save identical event immediately with elevated score
    elevated_assessment = {"score": 75, "severity": "high", "summary": "Elevated threat"}
    second_id = save_event(
        event, findings, elevated_assessment, db_path=db_file, deduplicate=True
    )

    # Must return the same event ID, NOT a new row
    assert second_id == first_id

    records = recent_events(limit=10, db_path=db_file)
    assert len(records) == 1
    assert records[0]["repeat_count"] == 2
    assert records[0]["score"] == 75
    assert records[0]["severity"] == "high"
    assert records[0]["summary"] == "Elevated threat"

    # Distinct event should insert a new record
    distinct_event = {**event, "remote_ip": "203.0.113.50"}
    third_id = save_event(distinct_event, findings, assessment, db_path=db_file)
    assert third_id == 2
    assert len(recent_events(limit=10, db_path=db_file)) == 2


def test_query_events_filtering_and_stats(tmp_path: Path):
    """Test multi-attribute query filtering and statistical aggregation."""
    db_file = tmp_path / "query.db"

    events_to_create = [
        ("proc1", "process_observed", "info", 5, "2026-10-10T01:00:00Z"),
        ("proc2", "process_observed", "medium", 45, "2026-10-10T02:00:00Z"),
        ("proc3", "dns_query_observed", "high", 75, "2026-10-10T03:00:00Z"),
        ("proc4", "network_connection_observed", "critical", 95, "2026-10-10T04:00:00Z"),
    ]

    for name, etype, sev, sc, ts in events_to_create:
        save_event(
            {"timestamp": ts, "event_type": etype, "process_name": name},
            [{"rule_id": f"RULE_{name}"}],
            {"score": sc, "severity": sev, "summary": f"Summary for {name}"},
            db_path=db_file,
            deduplicate=False,
        )

    assert get_event_count(db_path=db_file) == 4

    # Filter by severity
    critical_events = query_events(severity="critical", db_path=db_file)
    assert len(critical_events) == 1
    assert critical_events[0]["process_name"] == "proc4"

    # Filter by minimum score
    high_score_events = query_events(min_score=50, db_path=db_file)
    assert len(high_score_events) == 2

    # Filter by event_type
    dns_events = query_events(event_type="dns_query_observed", db_path=db_file)
    assert len(dns_events) == 1
    assert dns_events[0]["process_name"] == "proc3"

    # Filter by time range
    time_filtered = query_events(
        start_time="2026-10-10T01:30:00Z",
        end_time="2026-10-10T03:30:00Z",
        db_path=db_file,
    )
    assert len(time_filtered) == 2

    # Verify aggregate stats
    stats = get_event_stats(db_path=db_file)
    assert stats["total_events"] == 4
    assert stats["max_score"] == 95
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_sync_status"]["pending"] == 4


def test_offline_queue_sync_and_retry(tmp_path: Path):
    """Test offline queue operations: fetching, marking synced, and retry counting."""
    db_file = tmp_path / "queue.db"

    id1 = save_event(
        {"timestamp": utc_now(), "event_type": "event_1"},
        [],
        {"score": 10, "severity": "info", "summary": "1"},
        db_path=db_file,
        deduplicate=False,
    )
    id2 = save_event(
        {"timestamp": utc_now(), "event_type": "event_2"},
        [],
        {"score": 20, "severity": "info", "summary": "2"},
        db_path=db_file,
        deduplicate=False,
    )
    id3 = save_event(
        {"timestamp": utc_now(), "event_type": "event_3"},
        [],
        {"score": 30, "severity": "info", "summary": "3"},
        db_path=db_file,
        deduplicate=False,
    )

    pending = fetch_pending_events(batch_size=2, db_path=db_file)
    assert len(pending) == 2
    assert [p["id"] for p in pending] == [id1, id2]

    # Mark id1 synced
    synced_count = mark_events_synced([id1], db_path=db_file)
    assert synced_count == 1

    # Mark id2 failed with error
    mark_event_failed(id2, "Backend 503 Unavailable", db_path=db_file)

    ev2 = get_event(id2, db_path=db_file)
    assert ev2["sync_status"] == "failed"
    assert ev2["retry_count"] == 1
    assert "503" in ev2["error_message"]

    stats = get_queue_stats(db_path=db_file)
    assert stats["synced"] == 1
    assert stats["failed"] == 1
    assert stats["pending"] == 1

    # Reset failed events
    reset_count = reset_failed_events(db_path=db_file)
    assert reset_count == 1
    ev2_after = get_event(id2, db_path=db_file)
    assert ev2_after["sync_status"] == "pending"
    assert ev2_after["retry_count"] == 0


def test_sync_worker_success_and_backoff(tmp_path: Path):
    """Test background SyncWorker processing, mock transmitter, and exponential backoff."""
    db_file = tmp_path / "worker.db"

    save_event(
        {"timestamp": utc_now(), "event_type": "proc_1"},
        [],
        {"score": 10, "severity": "info", "summary": "one"},
        db_path=db_file,
        deduplicate=False,
    )
    save_event(
        {"timestamp": utc_now(), "event_type": "proc_2"},
        [],
        {"score": 20, "severity": "info", "summary": "two"},
        db_path=db_file,
        deduplicate=False,
    )

    # 1. Test successful sync
    sent_batches = []

    def mock_successful_sync(batch: list[dict]) -> bool:
        sent_batches.append(batch)
        return True

    worker = SyncWorker(
        db_path=db_file,
        sync_handler=mock_successful_sync,
        batch_size=10,
        base_backoff=1.0,
        backoff_factor=2.0,
    )

    res = worker.sync_once()
    assert res["status"] == "success"
    assert res["synced"] == 2
    assert len(sent_batches) == 1
    assert len(fetch_pending_events(db_path=db_file)) == 0

    # 2. Test failed sync with backoff
    save_event(
        {"timestamp": utc_now(), "event_type": "proc_3"},
        [],
        {"score": 30, "severity": "low", "summary": "three"},
        db_path=db_file,
        deduplicate=False,
    )

    def mock_failing_sync(batch: list[dict]) -> bool:
        return False

    failing_worker = SyncWorker(
        db_path=db_file,
        sync_handler=mock_failing_sync,
        base_backoff=1.0,
        backoff_factor=2.0,
        max_backoff=10.0,
    )

    fail_res = failing_worker.sync_once()
    assert fail_res["status"] == "failed"
    assert fail_res["failed"] == 1
    assert failing_worker._current_delay == 2.0  # 1.0 * 2.0

    # Second failure triggers exponential backoff again
    failing_worker.sync_once()
    assert failing_worker._current_delay == 4.0  # 2.0 * 2.0


def test_sync_worker_thread_lifecycle(tmp_path: Path):
    """Test start and graceful shutdown of background SyncWorker thread."""
    db_file = tmp_path / "lifecycle.db"
    worker = SyncWorker(db_path=db_file, sync_handler=lambda b: True, interval_seconds=0.1)

    assert not worker.is_running()
    worker.start()
    assert worker.is_running()
    time.sleep(0.05)
    worker.stop(timeout=1.0)
    assert not worker.is_running()


def test_retention_policy_age_and_capacity(tmp_path: Path):
    """Test retention policy enforcement by age and capacity, preserving critical alerts."""
    db_file = tmp_path / "retention.db"

    now = datetime.now(timezone.utc)
    old_time = (now - timedelta(days=45)).isoformat()
    recent_time = now.isoformat()

    # 1. Insert aged records (older than 30 days)
    # Old low severity (should be purged)
    save_event(
        {"timestamp": old_time, "event_type": "old_low"},
        [],
        {"score": 10, "severity": "low", "summary": "Old low"},
        db_path=db_file,
        deduplicate=False,
    )
    # Old critical severity (should be preserved when keep_high_severity=True)
    save_event(
        {"timestamp": old_time, "event_type": "old_critical"},
        [],
        {"score": 90, "severity": "critical", "summary": "Old critical"},
        db_path=db_file,
        deduplicate=False,
    )
    # Recent record
    save_event(
        {"timestamp": recent_time, "event_type": "recent_info"},
        [],
        {"score": 5, "severity": "info", "summary": "Recent info"},
        db_path=db_file,
        deduplicate=False,
    )

    assert get_event_count(db_path=db_file) == 3

    # Purge with 30-day retention
    result = purge_expired_events(
        retention_days=30,
        max_records=100,
        keep_high_severity=True,
        db_path=db_file,
    )

    assert result["purged_by_age"] == 1
    assert result["remaining_records"] == 2

    remaining = recent_events(limit=10, db_path=db_file)
    remaining_types = {r["event_type"] for r in remaining}
    assert "old_low" not in remaining_types
    assert "old_critical" in remaining_types
    assert "recent_info" in remaining_types

    # 2. Test capacity cap: insert excess records and purge
    for i in range(10):
        save_event(
            {"timestamp": recent_time, "event_type": f"cap_{i}"},
            [],
            {"score": 15, "severity": "low", "summary": f"Cap {i}"},
            db_path=db_file,
            deduplicate=False,
        )

    # 12 records total, cap at 5
    cap_result = apply_retention_policy(
        retention_days=365,
        max_records=5,
        keep_high_severity=False,
        db_path=db_file,
    )
    assert cap_result["remaining_records"] == 5
    assert get_event_count(db_path=db_file) == 5


def test_log_rotation_handler(tmp_path: Path):
    """Test size-bounded RotatingFileHandler creation and rollover."""
    log_file = tmp_path / "logs" / "agent_test.log"
    logger = setup_logging(
        log_file=log_file,
        max_bytes=500,  # Small limit to trigger quick rotation
        backup_count=2,
        level=logging.DEBUG,
        console=False,
    )

    assert log_file.exists()

    # Write enough log entries to trigger rotation
    for i in range(25):
        logger.info("This is test log line number %03d with extra padding data.", i)

    # Force flushing
    for h in logger.handlers:
        h.flush()

    # The log file should exist, and at least one rotated backup (.1) should exist
    backup_file = Path(f"{log_file}.1")
    assert log_file.exists()
    assert backup_file.exists()

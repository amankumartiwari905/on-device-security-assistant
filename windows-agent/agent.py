"""Read-only Windows security agent with local event storage."""

import time

from config import (
    APP_NAME,
    POLL_INTERVAL_SECONDS,
    DNS_POLL_INTERVAL_SECONDS,
    TASK_POLL_INTERVAL_SECONDS,
    SERVICE_POLL_INTERVAL_SECONDS,
    DATABASE_PATH,
    SYNC_ENABLED,
    SYNC_INTERVAL_SECONDS,
    SYNC_BATCH_SIZE,
    SYNC_MAX_RETRIES,
    BACKEND_API_URL,
    RETENTION_DAYS,
    MAX_DB_RECORDS,
    RETENTION_KEEP_HIGH_SEVERITY,
    LOG_FILE_PATH,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    WATCH_DOWNLOADS,
    WATCHED_DOWNLOAD_DIRECTORIES,
    PREVENTION_ENABLED,
)
from engine.correlation import (
    EventDeduplicator,
    ProcessIdentityTracker,
    correlate_process_and_network,
    global_download_tracker,
)
from engine.download_pipeline import download_pipeline
from engine.rules import (
    analyze_process,
    analyze_network,
    analyze_dns,
    analyze_persistence,
    analyze_scheduled_task,
    analyze_service,
)
from engine.scoring import score_findings
from monitors.processes import snapshot_processes, detect_process_changes
from monitors.network import snapshot_connections, ConnectionTracker
from monitors.dns import snapshot_dns_cache, find_dns_changes
from monitors.persistence import snapshot_startup_items, find_startup_changes
from monitors.tasks import snapshot_scheduled_tasks, find_task_changes
from monitors.services import snapshot_services, find_service_changes
from monitors.downloads import (
    snapshot_download_directory,
    find_download_changes,
    get_watched_download_directories,
)
from storage import (
    initialize_database,
    save_event,
    apply_retention_policy,
    setup_logging,
    get_logger,
    SyncWorker,
)


logger = get_logger("phishguard.agent")


def connection_key(event: dict) -> tuple:
    return (
        event.get("pid"),
        event.get("protocol"),
        event.get("local_ip"),
        event.get("local_port"),
        event.get("remote_ip"),
        event.get("remote_port"),
    )


def record_event(
    event: dict,
    findings: list[dict],
    deduplicator: EventDeduplicator | None = None,
) -> None:
    if deduplicator:
        findings, suppressed = deduplicator.filter_findings(event, findings)
        if not findings and suppressed > 0:
            return

    assessment = score_findings(findings)
    event_id = save_event(event, findings, assessment)

    event_type = event.get("event_type", "unknown")
    target_name = (
        event.get("process_name")
        or event.get("domain")
        or event.get("name")
        or event.get("task_name")
        or event.get("service_name")
        or "unknown"
    )

    logger.info(
        "[%s #%s] Target: %s (PID: %s) | Severity: %s (Score: %d/100) | Findings: %d",
        event_type.upper(),
        event_id,
        target_name,
        event.get("pid", "-"),
        assessment.get("severity", "info").upper(),
        assessment.get("score", 0),
        len(findings),
    )

    print(f"\n[{event_type.upper()} #{event_id}]")
    print(f"  Target:  {target_name}")
    if event.get("pid"):
        print(f"  PID:     {event.get('pid')}")
    if event.get("executable"):
        print(f"  Path:    {event.get('executable')}")
    elif event.get("binpath"):
        print(f"  BinPath: {event.get('binpath')}")
    elif event.get("command"):
        print(f"  Command: {event.get('command')}")
    elif event.get("task_to_run"):
        print(f"  RunCmd:  {event.get('task_to_run')}")

    if event_type == "network_connection_observed":
        print(f"  Local:   {event.get('local_ip')}:{event.get('local_port')}")
        print(f"  Remote:  {event.get('remote_ip')}:{event.get('remote_port')}")
        if event.get("country"):
            loc = f"{event.get('city')}, {event.get('country')}" if event.get("city") else event.get("country")
            print(f"  GeoIP:   {loc}")
        if event.get("hosting_provider"):
            print(f"  Hosting: {event.get('hosting_provider')}")
        if event.get("threat_flagged"):
            print(f"  THREAT:  {event.get('threat_details')}")

    elif event_type == "dns_query_observed":
        print(f"  Domain:  {event.get('domain')}")
        if event.get("resolved_ips"):
            print(f"  Resolved:{', '.join(event['resolved_ips'][:4])}")

    print(
        f"  Risk:    {assessment['severity'].upper()} "
        f"({assessment['score']}/100)"
    )
    print(f"  Summary: {assessment['summary']}")

    for finding in findings:
        print(f"  Finding: {finding['title']}")
        print(f"  Reason:  {finding['reason']}")


def main() -> None:
    # 1. Setup size-bounded rotating file logging
    setup_logging(
        log_file=LOG_FILE_PATH,
        max_bytes=LOG_MAX_BYTES,
        backup_count=LOG_BACKUP_COUNT,
        console=False,
    )

    print("=" * 68)
    print(f"  {APP_NAME.upper()} — WINDOWS SYSTEM & NETWORK MONITORING AGENT")
    print("  Process + Network + DNS + Persistence + Tasks + Services + SQLite")
    print("=" * 68)

    # 2. Database initialization and initial retention cleanup
    initialize_database(DATABASE_PATH)
    retention_stats = apply_retention_policy(
        retention_days=RETENTION_DAYS,
        max_records=MAX_DB_RECORDS,
        keep_high_severity=RETENTION_KEEP_HIGH_SEVERITY,
        db_path=DATABASE_PATH,
    )
    if retention_stats["total_purged"] > 0:
        logger.info(
            "Initial retention policy purged %d old records (remaining: %d)",
            retention_stats["total_purged"],
            retention_stats["remaining_records"],
        )

    # 3. Start background offline queue sync worker if enabled
    sync_worker = None
    if SYNC_ENABLED:
        sync_worker = SyncWorker(
            db_path=DATABASE_PATH,
            api_url=BACKEND_API_URL,
            interval_seconds=SYNC_INTERVAL_SECONDS,
            batch_size=SYNC_BATCH_SIZE,
            max_retries=SYNC_MAX_RETRIES,
        )
        sync_worker.start()
        logger.info("Background offline queue sync worker initialized.")

    connection_tracker = ConnectionTracker()
    previous_processes = snapshot_processes()
    previous_connections = {
        connection_key(event) for event in snapshot_connections(tracker=connection_tracker)
    }
    previous_dns = snapshot_dns_cache()
    previous_startup = snapshot_startup_items()
    previous_tasks = snapshot_scheduled_tasks()
    previous_services = snapshot_services()

    # Monitored download folders (Downloads, Desktop, and custom paths)
    watched_download_dirs = (
        get_watched_download_directories(WATCHED_DOWNLOAD_DIRECTORIES)
        if WATCH_DOWNLOADS
        else []
    )
    previous_downloads = (
        snapshot_download_directory(watched_download_dirs)
        if WATCH_DOWNLOADS
        else {}
    )

    deduplicator = EventDeduplicator(cooldown_seconds=60.0)
    process_tracker = ProcessIdentityTracker()
    for proc in previous_processes.values():
        process_tracker.register_process(proc)

    print("Baseline captured:")
    print(f"  • Processes:       {len(previous_processes)}")
    print(f"  • Active conns:    {len(previous_connections)}")
    print(f"  • Cached DNS:      {len(previous_dns)}")
    print(f"  • Startup items:   {len(previous_startup)}")
    print(f"  • Scheduled tasks: {len(previous_tasks)}")
    print(f"  • Services:        {len(previous_services)}")
    if WATCH_DOWNLOADS:
        print(
            f"  • Downloads:       {len(previous_downloads)} tracked "
            f"({len(watched_download_dirs)} directory/directories)"
        )
    print(
        f"Polling intervals: Net/Proc/DNS/Startup: {POLL_INTERVAL_SECONDS}s, "
        f"Tasks: {TASK_POLL_INTERVAL_SECONDS}s, Services: {SERVICE_POLL_INTERVAL_SECONDS}s"
    )
    print("Monitoring system and network activity. Press Ctrl+C to stop.")

    last_task_check = time.time()
    last_service_check = time.time()
    last_retention_check = time.time()
    RETENTION_CHECK_INTERVAL = 3600.0  # Run retention cleanup every hour

    try:
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            now = time.time()

            # 1. Process Change Detection & Download-to-Execution Correlation
            current_processes = snapshot_processes()
            proc_changes = detect_process_changes(
                previous_processes, current_processes
            )

            for event in proc_changes["started"]:
                process_tracker.register_process(event)
                findings = (
                    analyze_process(event)
                    + global_download_tracker.correlate_process_execution(event)
                )
                record_event(event, findings, deduplicator=deduplicator)

            for event in proc_changes["terminated"]:
                pid = event.get("pid")
                process_tracker.unregister_process(pid, event.get("create_time"))
                if pid:
                    global_download_tracker.unregister_process(pid)
                    connection_tracker.reset_process(pid)
                record_event(event, analyze_process(event), deduplicator=deduplicator)

            previous_processes = current_processes

            # 2. Network Connections Detection & Download-Outbound Correlation
            current_connection_events = snapshot_connections(tracker=connection_tracker)
            current_connections = {
                connection_key(event): event
                for event in current_connection_events
            }

            new_keys = current_connections.keys() - previous_connections
            for key in new_keys:
                event = current_connections[key]
                findings = (
                    analyze_network(event)
                    + correlate_process_and_network(event)
                    + global_download_tracker.correlate_network_activity(event)
                )
                record_event(event, findings, deduplicator=deduplicator)

            previous_connections = set(current_connections.keys())

            # 3. DNS Cache & Query Monitoring
            current_dns = snapshot_dns_cache()
            for event in find_dns_changes(previous_dns, current_dns):
                record_event(event, analyze_dns(event), deduplicator=deduplicator)
            previous_dns = current_dns

            # 4. Startup Persistence Monitoring & Download-Persistence Correlation
            current_startup = snapshot_startup_items()
            startup_changes = find_startup_changes(previous_startup, current_startup)
            for event in (
                startup_changes["added"]
                + startup_changes["modified"]
                + startup_changes["removed"]
            ):
                findings = (
                    analyze_persistence(event)
                    + global_download_tracker.correlate_persistence_activity(event)
                )
                record_event(event, findings)
            previous_startup = current_startup

            # 5. Scheduled Tasks Monitoring
            if now - last_task_check >= TASK_POLL_INTERVAL_SECONDS:
                current_tasks = snapshot_scheduled_tasks()
                task_changes = find_task_changes(previous_tasks, current_tasks)
                for event in (
                    task_changes["created"]
                    + task_changes["modified"]
                    + task_changes["deleted"]
                ):
                    findings = (
                        analyze_scheduled_task(event)
                        + global_download_tracker.correlate_persistence_activity(event)
                    )
                    record_event(event, findings)
                previous_tasks = current_tasks
                last_task_check = now

            # 6. Windows Services Monitoring
            if now - last_service_check >= SERVICE_POLL_INTERVAL_SECONDS:
                current_services = snapshot_services()
                service_changes = find_service_changes(
                    previous_services, current_services
                )
                for event in (
                    service_changes["installed"]
                    + service_changes["modified"]
                    + service_changes["removed"]
                ):
                    findings = (
                        analyze_service(event)
                        + global_download_tracker.correlate_persistence_activity(event)
                    )
                    record_event(event, findings)
                previous_services = current_services
                last_service_check = now

            # 7. File Download Observation & End-to-End Threat Pipeline
            if WATCH_DOWNLOADS:
                current_downloads = snapshot_download_directory(watched_download_dirs)
                new_downloads = find_download_changes(
                    previous_downloads, current_downloads
                )
                for dl in new_downloads:
                    res = download_pipeline.process_download(
                        dl["path"],
                        auto_remediate=PREVENTION_ENABLED,
                    )
                    print(f"\n[DOWNLOAD {res['decision']} #{res['event_id']}]")
                    print(f"  File:     {res['filename']}")
                    print(f"  Path:     {res['file_path']}")
                    print(f"  SHA-256:  {res['sha256']}")
                    print(f"  MotW:     {res['mark_of_the_web']}")
                    if res.get("download_url"):
                        print(f"  URL:      {res['download_url']}")
                    print(f"  Risk:     {res['severity'].upper()} ({res['score']}/100)")
                    print(f"  Action:   {res['action']}")
                    if res.get("prevention", {}).get("prevented"):
                        print(f"  PREVENT:  {res['prevention'].get('actions_taken')}")
                previous_downloads = current_downloads

            # 8. Periodic Storage Retention Enforcement
            if now - last_retention_check >= RETENTION_CHECK_INTERVAL:
                apply_retention_policy(
                    retention_days=RETENTION_DAYS,
                    max_records=MAX_DB_RECORDS,
                    keep_high_severity=RETENTION_KEEP_HIGH_SEVERITY,
                    db_path=DATABASE_PATH,
                )
                last_retention_check = now

    except KeyboardInterrupt:
        print("\nAgent stopped by user.")
    finally:
        if sync_worker:
            sync_worker.stop()
            logger.info("Sync worker stopped.")


if __name__ == "__main__":
    main()

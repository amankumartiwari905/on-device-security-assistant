"""Read-only Windows security agent with local event storage."""

import time

from config import APP_NAME, POLL_INTERVAL_SECONDS
from engine.rules import analyze_process, analyze_network
from engine.scoring import score_findings
from monitors.processes import snapshot_processes, find_new_processes
from monitors.network import snapshot_connections
from storage.events import initialize_database, save_event


def connection_key(event: dict) -> tuple:
    return (
        event.get("pid"),
        event.get("protocol"),
        event.get("local_ip"),
        event.get("local_port"),
        event.get("remote_ip"),
        event.get("remote_port"),
    )


def record_event(event: dict, findings: list[dict]) -> None:
    assessment = score_findings(findings)
    event_id = save_event(event, findings, assessment)

    print(f"\n[{event['event_type'].upper()} #{event_id}]")
    print(f"  Process: {event.get('process_name') or 'unknown'}")
    print(f"  PID:     {event.get('pid')}")
    if event.get("event_type") == "network_connection_observed":
        print(
            f"  Local:   {event.get('local_ip')}:{event.get('local_port')}"
        )
        print(
            f"  Remote:  {event.get('remote_ip')}:{event.get('remote_port')}"
        )    
    print(
        f"  Risk:    {assessment['severity'].upper()} "
        f"({assessment['score']}/100)"
    )
    print(f"  Summary: {assessment['summary']}")

    for finding in findings:
        print(f"  Finding: {finding['title']}")
        print(f"  Reason:  {finding['reason']}")


def main() -> None:
    print("=" * 58)
    print(f"  {APP_NAME.upper()} — WINDOWS SECURITY AGENT")
    print("  Process monitoring + network observations + SQLite")
    print("=" * 58)

    initialize_database()

    previous_processes = snapshot_processes()
    previous_connections = {
        connection_key(event) for event in snapshot_connections()
    }

    print(f"Baseline captured: {len(previous_processes)} processes")
    print(f"Existing active connections: {len(previous_connections)}")
    print(f"Polling interval: {POLL_INTERVAL_SECONDS} seconds")
    print("Monitoring new activity. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)

            current_processes = snapshot_processes()

            for event in find_new_processes(
                previous_processes, current_processes
            ):
                record_event(event, analyze_process(event))

            previous_processes = current_processes

            current_connection_events = snapshot_connections()
            current_connections = {
                connection_key(event): event
                for event in current_connection_events
            }

            # Report connections that appeared since the previous poll.
            new_keys = current_connections.keys() - previous_connections

            for key in new_keys:
                event = current_connections[key]
                record_event(event, analyze_network(event))

            # Replace the snapshot so closed connections can be detected
            # if they appear again in a later polling cycle.
            previous_connections = set(current_connections.keys())

    except KeyboardInterrupt:
        print("\nAgent stopped by user.")


if __name__ == "__main__":
    main()

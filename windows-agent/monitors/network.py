
"""Read-only monitoring of active, attributable TCP connections."""

from datetime import datetime, timezone

import psutil


def snapshot_connections() -> list[dict]:
    observations = []

    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError) as exc:
        print(f"[NETWORK] Monitoring unavailable: {exc}")
        return observations

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED:
            continue

        if not conn.raddr or not conn.pid:
            continue

        try:
            process = psutil.Process(conn.pid)
            process_name = process.name()
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            OSError,
        ):
            continue

        local_ip = conn.laddr.ip
        local_port = conn.laddr.port
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        observations.append({
            "event_type": "network_connection_observed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pid": conn.pid,
            "process_name": process_name,
            "protocol": "TCP",
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status,
            "connection_id": (
                f"{conn.pid}|TCP|{local_ip}:{local_port}"
                f"->{remote_ip}:{remote_port}"
            ),
        })

    return observations

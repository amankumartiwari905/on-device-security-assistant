"""Read-only monitoring of active TCP connections, process-to-network mapping, and connection patterns."""

from collections import defaultdict
from datetime import datetime, timezone
import psutil

from monitors.ip_intelligence import (
    lookup_ip_intelligence,
    check_ip_reputation,
    is_public_ip,
)


SUSPICIOUS_CLIENT_INTERPRETERS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "vssadmin.exe",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectionTracker:
    """Tracks connection counts and detects repeated connections and burst patterns."""

    def __init__(self, burst_threshold: int = 5, fanout_threshold: int = 8):
        self.burst_threshold = burst_threshold
        self.fanout_threshold = fanout_threshold
        # Key: (pid, remote_ip) -> count
        self.destination_counts: dict[tuple[int, str], int] = defaultdict(int)
        # Key: pid -> set of (remote_ip, remote_port)
        self.process_destinations: dict[int, set[tuple[str, int]]] = defaultdict(set)

    def record_connection(self, pid: int, remote_ip: str, remote_port: int) -> dict:
        """
        Record a connection and evaluate whether it meets repeated burst or fanout thresholds.
        """
        key = (pid, remote_ip)
        self.destination_counts[key] += 1
        count = self.destination_counts[key]

        self.process_destinations[pid].add((remote_ip, remote_port))
        unique_destinations = len(self.process_destinations[pid])

        is_repeated_burst = count >= self.burst_threshold
        is_wide_fanout = unique_destinations >= self.fanout_threshold

        return {
            "connection_count": count,
            "unique_destinations": unique_destinations,
            "is_repeated_burst": is_repeated_burst,
            "is_wide_fanout": is_wide_fanout,
        }

    def reset_process(self, pid: int) -> None:
        """Reset tracking state for terminated process."""
        self.process_destinations.pop(pid, None)
        keys_to_remove = [k for k in self.destination_counts if k[0] == pid]
        for k in keys_to_remove:
            self.destination_counts.pop(k, None)


def inspect_connection_process(pid: int) -> dict:
    """Map network connection to its owning process details."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, OSError):
            exe = None

        try:
            cmdline = " ".join(proc.cmdline())
        except (psutil.AccessDenied, OSError):
            cmdline = None

        try:
            username = proc.username()
        except (psutil.AccessDenied, OSError):
            username = None

        try:
            parent = proc.parent()
            parent_name = parent.name() if parent else None
            parent_pid = parent.pid if parent else None
        except (psutil.AccessDenied, OSError):
            parent_name = None
            parent_pid = None

        return {
            "process_name": name,
            "executable": exe,
            "command_line": cmdline,
            "username": username,
            "parent_name": parent_name,
            "parent_pid": parent_pid,
        }
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError,
    ):
        return {
            "process_name": "unknown",
            "executable": None,
            "command_line": None,
            "username": None,
            "parent_name": None,
            "parent_pid": None,
        }


def snapshot_connections(
    status_filter: tuple = (psutil.CONN_ESTABLISHED,),
    tracker: ConnectionTracker | None = None,
) -> list[dict]:
    """
    Capture active TCP connections with process-to-network mapping and IP intelligence.
    """
    observations = []

    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError) as exc:
        print(f"[NETWORK] Monitoring unavailable: {exc}")
        return observations

    for conn in connections:
        if status_filter and conn.status not in status_filter:
            continue

        if not conn.raddr or not conn.pid:
            continue

        local_ip = conn.laddr.ip
        local_port = conn.laddr.port
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        proc_info = inspect_connection_process(conn.pid)
        if proc_info["process_name"] == "unknown" and not proc_info["executable"]:
            # If process has already terminated during inspection
            continue

        intel = lookup_ip_intelligence(remote_ip)
        reputation = check_ip_reputation(remote_ip)

        pattern_stats = {}
        if tracker:
            pattern_stats = tracker.record_connection(conn.pid, remote_ip, remote_port)

        is_suspicious_client = proc_info["process_name"].lower() in SUSPICIOUS_CLIENT_INTERPRETERS

        observation = {
            "event_type": "network_connection_observed",
            "timestamp": utc_now(),
            "pid": conn.pid,
            "process_name": proc_info["process_name"],
            "executable": proc_info["executable"],
            "command_line": proc_info["command_line"],
            "username": proc_info["username"],
            "parent_name": proc_info["parent_name"],
            "parent_pid": proc_info["parent_pid"],
            "protocol": "TCP",
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status,
            "connection_id": (
                f"{conn.pid}|TCP|{local_ip}:{local_port}->{remote_ip}:{remote_port}"
            ),
            "is_public_ip": is_public_ip(remote_ip),
            "country": intel.get("country"),
            "country_code": intel.get("country_code"),
            "region": intel.get("region"),
            "city": intel.get("city"),
            "org": intel.get("org"),
            "isp": intel.get("isp"),
            "asn": intel.get("asn"),
            "is_hosting": intel.get("is_hosting", False),
            "hosting_provider": intel.get("hosting_provider"),
            "threat_flagged": reputation.get("is_flagged", False),
            "threat_details": reputation.get("details"),
            "is_suspicious_client": is_suspicious_client,
            "connection_count": pattern_stats.get("connection_count", 1),
            "is_repeated_burst": pattern_stats.get("is_repeated_burst", False),
            "is_wide_fanout": pattern_stats.get("is_wide_fanout", False),
        }

        observations.append(observation)

    return observations


def find_new_connections(
    previous: set[tuple] | dict[tuple, dict],
    current: dict[tuple, dict] | list[dict],
) -> list[dict]:
    """
    Identify newly observed connections between polling snapshots.
    """
    if isinstance(current, list):
        current_map = {
            (
                e.get("pid"),
                e.get("protocol"),
                e.get("local_ip"),
                e.get("local_port"),
                e.get("remote_ip"),
                e.get("remote_port"),
            ): e
            for e in current
        }
    else:
        current_map = current

    prev_keys = previous if isinstance(previous, set) else set(previous.keys())
    new_keys = current_map.keys() - prev_keys
    return [current_map[k] for k in new_keys]

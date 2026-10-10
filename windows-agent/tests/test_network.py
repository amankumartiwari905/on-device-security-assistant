"""Unit tests for TCP connection monitoring, process-to-network mapping, and connection tracking."""

import psutil
import pytest

from monitors.network import (
    ConnectionTracker,
    find_new_connections,
    inspect_connection_process,
    snapshot_connections,
)


def test_connection_tracker_counts_and_bursts():
    tracker = ConnectionTracker(burst_threshold=3, fanout_threshold=4)

    # First connection to IP A
    stat1 = tracker.record_connection(pid=100, remote_ip="203.0.113.1", remote_port=443)
    assert stat1["connection_count"] == 1
    assert stat1["is_repeated_burst"] is False
    assert stat1["unique_destinations"] == 1

    # Second connection to IP A
    stat2 = tracker.record_connection(pid=100, remote_ip="203.0.113.1", remote_port=443)
    assert stat2["connection_count"] == 2
    assert stat2["is_repeated_burst"] is False

    # Third connection triggers burst threshold
    stat3 = tracker.record_connection(pid=100, remote_ip="203.0.113.1", remote_port=443)
    assert stat3["connection_count"] == 3
    assert stat3["is_repeated_burst"] is True


def test_connection_tracker_fanout():
    tracker = ConnectionTracker(burst_threshold=10, fanout_threshold=3)

    tracker.record_connection(pid=200, remote_ip="198.51.100.1", remote_port=80)
    tracker.record_connection(pid=200, remote_ip="198.51.100.2", remote_port=80)
    stat3 = tracker.record_connection(pid=200, remote_ip="198.51.100.3", remote_port=80)

    assert stat3["unique_destinations"] == 3
    assert stat3["is_wide_fanout"] is True


def test_connection_tracker_reset_process():
    tracker = ConnectionTracker()
    tracker.record_connection(pid=300, remote_ip="1.2.3.4", remote_port=80)
    assert (300, "1.2.3.4") in tracker.destination_counts

    tracker.reset_process(300)
    assert (300, "1.2.3.4") not in tracker.destination_counts
    assert 300 not in tracker.process_destinations


def test_find_new_connections():
    previous = {
        (100, "TCP", "192.168.1.5", 50000, "142.250.190.46", 443),
    }
    current = [
        {
            "pid": 100,
            "protocol": "TCP",
            "local_ip": "192.168.1.5",
            "local_port": 50000,
            "remote_ip": "142.250.190.46",
            "remote_port": 443,
        },
        {
            "pid": 200,
            "protocol": "TCP",
            "local_ip": "192.168.1.5",
            "local_port": 50001,
            "remote_ip": "93.184.216.34",
            "remote_port": 80,
        },
    ]

    new_conns = find_new_connections(previous, current)
    assert len(new_conns) == 1
    assert new_conns[0]["pid"] == 200
    assert new_conns[0]["remote_ip"] == "93.184.216.34"


def test_inspect_connection_process_nonexistent():
    info = inspect_connection_process(99999999)
    assert info["process_name"] == "unknown"
    assert info["executable"] is None


def test_snapshot_connections_mocked(monkeypatch):
    class MockAddr:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class MockConn:
        def __init__(self, pid, laddr, raddr, status):
            self.pid = pid
            self.laddr = laddr
            self.raddr = raddr
            self.status = status

    mock_conns = [
        MockConn(
            pid=1234,
            laddr=MockAddr("192.168.1.10", 55000),
            raddr=MockAddr("8.8.8.8", 53),
            status=psutil.CONN_ESTABLISHED,
        ),
    ]

    monkeypatch.setattr(psutil, "net_connections", lambda kind="tcp": mock_conns)
    monkeypatch.setattr(
        "monitors.network.inspect_connection_process",
        lambda pid: {
            "process_name": "dns-client.exe",
            "executable": r"C:\Windows\System32\dns-client.exe",
            "command_line": "dns-client.exe",
            "username": "SYSTEM",
            "parent_name": "services.exe",
            "parent_pid": 600,
        },
    )

    observations = snapshot_connections()
    assert len(observations) == 1
    obs = observations[0]
    assert obs["pid"] == 1234
    assert obs["process_name"] == "dns-client.exe"
    assert obs["remote_ip"] == "8.8.8.8"
    assert obs["remote_port"] == 53
    assert obs["status"] == psutil.CONN_ESTABLISHED
    assert obs["is_public_ip"] is True


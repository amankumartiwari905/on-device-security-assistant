"""Unit tests for risk scoring, multi-indicator correlation, deduplication, and process identity tracking."""

from engine.correlation import (
    EventDeduplicator,
    ProcessIdentityTracker,
    correlate_process_and_network,
)
from engine.scoring import classify_severity, score_findings
from engine.threat_detector import ThreatDetectionEngine
from monitors.processes import find_new_processes, find_terminated_processes


def test_severity_classification_thresholds():
    assert classify_severity(0) == "info"
    assert classify_severity(10) == "info"
    assert classify_severity(15) == "low"
    assert classify_severity(34) == "low"
    assert classify_severity(35) == "medium"
    assert classify_severity(59) == "medium"
    assert classify_severity(60) == "high"
    assert classify_severity(84) == "high"
    assert classify_severity(85) == "critical"
    assert classify_severity(100) == "critical"


def test_multi_indicator_compound_scoring():
    # Single finding baseline scores
    assert score_findings([])["score"] == 0
    assert score_findings([{"severity": "low"}])["score"] == 15
    assert score_findings([{"severity": "medium"}])["score"] == 35
    assert score_findings([{"severity": "high"}])["score"] == 60
    assert score_findings([{"severity": "critical"}])["score"] == 85

    # Multi-indicator compound scoring increases risk when multiple signals intersect
    compound_high_med = score_findings([
        {"severity": "high"},
        {"severity": "medium"},
    ])
    assert compound_high_med["score"] > 60
    assert compound_high_med["severity"] == "high"

    compound_two_highs = score_findings([
        {"severity": "high"},
        {"severity": "high"},
    ])
    assert compound_two_highs["score"] == 75
    assert compound_two_highs["severity"] == "high"

    compound_critical_high = score_findings([
        {"severity": "critical"},
        {"severity": "high"},
    ])
    assert compound_critical_high["score"] == 100
    assert compound_critical_high["severity"] == "critical"


def test_process_and_network_correlation_writable_exec():
    event = {
        "event_type": "network_connection_observed",
        "process_name": "stealer.exe",
        "pid": 4001,
        "executable": r"C:\Users\User\AppData\Local\Temp\stealer.exe",
        "remote_ip": "93.184.216.34",
        "remote_port": 443,
        "is_public_ip": True,
        "is_suspicious_client": False,
        "threat_flagged": False,
    }

    correlated = correlate_process_and_network(event)
    assert len(correlated) >= 1
    assert any(f["rule_id"] == "CORR_WRITABLE_EXEC_OUTBOUND" for f in correlated)
    finding = next(f for f in correlated if f["rule_id"] == "CORR_WRITABLE_EXEC_OUTBOUND")
    assert finding["severity"] == "high"
    assert "evidence" in finding


def test_process_and_network_correlation_shell_outbound():
    event = {
        "event_type": "network_connection_observed",
        "process_name": "powershell.exe",
        "pid": 4002,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "remote_ip": "203.0.113.5",
        "remote_port": 4444,
        "is_public_ip": True,
        "is_suspicious_client": True,
        "threat_flagged": False,
    }

    correlated = correlate_process_and_network(event)
    assert any(f["rule_id"] == "CORR_SHELL_INTERNET_COMMUNICATION" for f in correlated)
    finding = next(f for f in correlated if f["rule_id"] == "CORR_SHELL_INTERNET_COMMUNICATION")
    assert finding["severity"] == "high"


def test_process_and_network_correlation_malicious_ip():
    event = {
        "event_type": "network_connection_observed",
        "process_name": "powershell.exe",
        "pid": 4003,
        "executable": r"C:\Users\User\Downloads\script_runner.exe",
        "remote_ip": "198.51.100.66",
        "remote_port": 8443,
        "is_public_ip": True,
        "is_suspicious_client": True,
        "threat_flagged": True,
        "threat_details": "Known C2 Host",
    }

    correlated = correlate_process_and_network(event)
    assert any(f["rule_id"] == "CORR_SUSPICIOUS_PROC_MALICIOUS_IP" for f in correlated)
    finding = next(f for f in correlated if f["rule_id"] == "CORR_SUSPICIOUS_PROC_MALICIOUS_IP")
    assert finding["severity"] == "critical"


def test_duplicate_event_filtering_cooldown():
    dedup = EventDeduplicator(cooldown_seconds=30.0)

    event = {
        "event_type": "network_connection_observed",
        "pid": 1234,
        "process_name": "chrome.exe",
        "remote_ip": "142.250.190.46",
        "remote_port": 443,
    }
    findings = [
        {"rule_id": "NET_CONNECTION_OBSERVED", "severity": "info", "title": "Observed connection"},
    ]

    # First observation at t = 100 -> NOT suppressed
    active1, suppressed1 = dedup.filter_findings(event, findings, current_time=100.0)
    assert len(active1) == 1
    assert suppressed1 == 0

    # Repeat observation at t = 105 (within 30s cooldown) -> SUPPRESSED
    active2, suppressed2 = dedup.filter_findings(event, findings, current_time=105.0)
    assert len(active2) == 0
    assert suppressed2 == 1

    # Observation at t = 135 (past 30s cooldown) -> NOT suppressed
    active3, suppressed3 = dedup.filter_findings(event, findings, current_time=135.0)
    assert len(active3) == 1
    assert suppressed3 == 0


def test_process_identity_tracking_pid_reuse():
    tracker = ProcessIdentityTracker()

    proc1 = {"pid": 5555, "create_time": 1000.0, "process_name": "app_v1.exe"}
    id1 = tracker.register_process(proc1)
    assert id1 == "5555_1000"
    assert tracker.get_process_by_pid(5555)["process_name"] == "app_v1.exe"

    # OS terminates app_v1 and reallocates PID 5555 to a new process app_v2
    proc2 = {"pid": 5555, "create_time": 2000.0, "process_name": "app_v2.exe"}
    id2 = tracker.register_process(proc2)
    assert id2 == "5555_2000"
    assert id1 != id2
    # Active process under PID 5555 is now app_v2, not app_v1
    assert tracker.get_process_by_pid(5555)["process_name"] == "app_v2.exe"
    assert tracker.active_processes.get(id1) is None


def test_pid_reuse_change_detection():
    # Previous snapshot has PID 888 with create_time 100.0
    previous = {
        888: {"pid": 888, "create_time": 100.0, "process_name": "first_process.exe"}
    }
    # Current snapshot has PID 888 with create_time 200.0 (PID reused by OS)
    current = {
        888: {"pid": 888, "create_time": 200.0, "process_name": "second_process.exe"}
    }

    # Should detect second_process as newly started
    new_procs = find_new_processes(previous, current)
    assert len(new_procs) == 1
    assert new_procs[0]["process_name"] == "second_process.exe"

    # Should detect first_process as terminated
    terminated = find_terminated_processes(previous, current)
    assert len(terminated) == 1
    assert terminated[0]["process_name"] == "first_process.exe"


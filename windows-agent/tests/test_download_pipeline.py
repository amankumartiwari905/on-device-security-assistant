"""Unit tests for the end-to-end file download threat detection and prevention pipeline."""

from pathlib import Path
import sqlite3

from engine.correlation import DownloadTracker
from engine.download_pipeline import FileDownloadThreatPipeline
from engine.prevention import (
    PreventionPolicy,
    terminate_process,
    quarantine_file,
    restore_quarantined_file,
    apply_prevention,
)
from engine.rules import analyze_download
from monitors.downloads import (
    snapshot_download_directory,
    find_download_changes,
    inspect_downloaded_file,
)
from monitors.file_metadata import inspect_file_metadata, inspect_zone_identifier


def test_download_observation_and_file_information(tmp_path: Path):
    """Test Stage 1 & 2: Observe file and collect SHA-256, signature, location, and Mark-of-the-Web."""
    dl_file = tmp_path / "test_installer.exe"
    dl_file.write_bytes(b"MZ\x90\x00\x03InstallerPayload")

    # Add NTFS Zone.Identifier stream
    try:
        with open(f"{dl_file}:Zone.Identifier", "w", encoding="utf-8") as f:
            f.write("[ZoneTransfer]\nZoneId=3\nHostUrl=https://downloads.example.com/setup.exe\nReferrerUrl=https://example.com/download\n")
    except OSError:
        pass

    event = inspect_downloaded_file(dl_file)

    assert event["event_type"] == "file_download_observed"
    assert event["filename"] == "test_installer.exe"
    assert event["extension"] == ".exe"
    assert event["size_bytes"] == len(b"MZ\x90\x00\x03InstallerPayload")
    assert event["sha256"] is not None
    assert len(event["sha256"]) == 64
    assert event["is_writable_location"] is True
    assert event["signature"] is not None
    assert "status" in event["signature"]


def test_download_directory_snapshot_and_change_detection(tmp_path: Path):
    """Test detecting new downloads while ignoring in-progress temporary downloads."""
    watch_folder = tmp_path / "Downloads"
    watch_folder.mkdir()

    # Initial snapshot
    snap1 = snapshot_download_directory([watch_folder])
    assert len(snap1) == 0

    # Browser starts download (e.g. Chrome writes .crdownload)
    crdownload = watch_folder / "software.exe.crdownload"
    crdownload.write_bytes(b"partial")
    snap2 = snapshot_download_directory([watch_folder])
    changes = find_download_changes(snap1, snap2)
    assert len(changes) == 0  # In-progress temp files ignored

    # Download completes and file is renamed to final .exe
    crdownload.unlink()
    final_exe = watch_folder / "software.exe"
    final_exe.write_bytes(b"completed binary payload")
    snap3 = snapshot_download_directory([watch_folder])
    final_changes = find_download_changes(snap2, snap3)

    assert len(final_changes) == 1
    assert final_changes[0]["name"] == "software.exe"


def test_evidence_analysis_rules_and_reputation(tmp_path: Path):
    """Test Stage 3: Analyze available evidence against detection rules and reputation."""
    # 1. Unsigned download in user directory
    event_unsigned = {
        "filename": "installer.exe",
        "file_path": str(tmp_path / "installer.exe"),
        "sha256": "1111222233334444555566667777888899990000aaaaabbbbbcccccdddddeeeee",
        "extension": ".exe",
        "signature": {"status": "unsigned"},
        "mark_of_the_web": True,
        "zone_id": 3,
    }
    findings_unsigned = analyze_download(event_unsigned)
    rule_ids = {f["rule_id"] for f in findings_unsigned}
    assert "DOWNLOAD_UNSIGNED_EXECUTABLE" in rule_ids
    assert "DOWNLOAD_MOTW_INTERNET" in rule_ids

    # 2. Deceptive double extension
    event_double_ext = {
        "filename": "urgent_invoice.pdf.exe",
        "file_path": str(tmp_path / "urgent_invoice.pdf.exe"),
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "extension": ".exe",
        "signature": {"status": "unsigned"},
    }
    findings_double = analyze_download(event_double_ext)
    rule_ids_double = {f["rule_id"] for f in findings_double}
    assert "DOWNLOAD_DOUBLE_EXTENSION" in rule_ids_double

    # 3. Blocklist hash match
    event_blocklist = {
        "filename": "eicar_sample.exe",
        "file_path": str(tmp_path / "eicar_sample.exe"),
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "extension": ".exe",
        "signature": {"status": "unsigned"},
    }
    findings_block = analyze_download(event_blocklist)
    rule_ids_block = {f["rule_id"] for f in findings_block}
    assert "DOWNLOAD_HASH_BLOCKLIST" in rule_ids_block

    # 4. Allowlisted publisher
    event_trusted = {
        "filename": "chrome_installer.exe",
        "file_path": str(tmp_path / "chrome_installer.exe"),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000001",
        "extension": ".exe",
        "signature": {"status": "valid", "signer": "Google LLC"},
    }
    findings_trusted = analyze_download(event_trusted)
    rule_ids_trusted = {f["rule_id"] for f in findings_trusted}
    assert "DOWNLOAD_TRUSTED_PUBLISHER" in rule_ids_trusted


def test_monitor_process_behavior_correlation():
    """Test Stage 4: Monitor process creation, network, and persistence behaviors for downloaded file."""
    tracker = DownloadTracker()
    download_event = {
        "file_path": r"C:\Users\Alice\Downloads\stealer.exe",
        "filename": "stealer.exe",
        "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "timestamp": "2026-10-10T01:00:00Z",
        "download_url": "https://phishing.site/stealer.exe",
        "mark_of_the_web": True,
        "zone_id": 3,
    }
    tracker.register_download(download_event)

    # 1. Process creation correlation
    process_event = {
        "process_name": "stealer.exe",
        "pid": 4567,
        "executable": r"C:\Users\Alice\Downloads\stealer.exe",
        "file_metadata": {"sha256": download_event["sha256"]},
    }
    proc_findings = tracker.correlate_process_execution(process_event)
    assert len(proc_findings) == 1
    assert proc_findings[0]["rule_id"] == "CORR_DOWNLOAD_PROCESS_EXECUTION"

    # 2. Outbound network connection correlation
    net_event = {
        "process_name": "stealer.exe",
        "pid": 4567,
        "remote_ip": "198.51.100.99",
        "remote_port": 4444,
        "threat_flagged": True,
    }
    net_findings = tracker.correlate_network_activity(net_event)
    assert len(net_findings) == 1
    assert net_findings[0]["rule_id"] == "CORR_DOWNLOAD_OUTBOUND_CONN"
    assert net_findings[0]["severity"] == "high"

    # 3. Startup persistence modification correlation
    persist_event = {
        "event_type": "startup_item_added",
        "name": "AutoRunStealer",
        "command": r"C:\Users\Alice\Downloads\stealer.exe --silent",
    }
    persist_findings = tracker.correlate_persistence_activity(persist_event)
    assert len(persist_findings) == 1
    assert persist_findings[0]["rule_id"] == "CORR_DOWNLOAD_PERSISTENCE"


def test_download_pipeline_low_risk_flow(tmp_path: Path):
    """Test full pipeline decision branch for LOW RISK -> Allow normal activity."""
    db_file = tmp_path / "low_risk.db"
    safe_file = tmp_path / "safe_document.pdf"
    safe_file.write_bytes(b"%PDF-1.4 Benign Document Content")

    policy = PreventionPolicy(enabled=True, min_risk_score=70)
    pipeline = FileDownloadThreatPipeline(policy=policy, db_path=db_file)

    result = pipeline.process_download(safe_file)

    assert result["decision"] == "LOW_RISK"
    assert result["action"] == "ALLOW_NORMAL_ACTIVITY"
    assert result["score"] < 50
    assert result["prevention"]["prevented"] is False
    assert safe_file.exists()  # Safe file is not modified or quarantined


def test_download_pipeline_high_risk_and_prevention_justified(tmp_path: Path):
    """Test full pipeline decision branch for HIGH RISK -> Alert + Apply Prevention (quarantine)."""
    db_file = tmp_path / "high_risk.db"
    q_dir = tmp_path / "quarantine_vault"

    # Malicious double-extension payload
    mal_file = tmp_path / "salary_update.pdf.exe"
    # Using known EICAR hash in mock or content
    mal_file.write_bytes(b"MZ\x90MaliciousPayloadData")

    policy = PreventionPolicy(
        enabled=True,
        mode="quarantine_and_terminate",
        min_risk_score=70,
        quarantine_dir=q_dir,
    )
    pipeline = FileDownloadThreatPipeline(policy=policy, db_path=db_file)

    # Attach behavioral evidence (outbound C2 connection)
    net_events = [{
        "process_name": "salary_update.pdf.exe",
        "pid": 8888,
        "remote_ip": "198.51.100.66",  # Blocklist IP
        "remote_port": 8443,
        "threat_flagged": True,
    }]

    result = pipeline.process_download(mal_file, network_events=net_events, auto_remediate=True)

    assert result["decision"] == "HIGH_RISK"
    assert result["score"] >= 70
    assert result["severity"] in ("high", "critical")
    assert result["action"] == "ALERT_AND_PREVENTION_APPLIED"
    assert result["prevention"]["justified"] is True
    assert result["prevention"]["prevented"] is True

    # Verify original malicious file was removed from source
    assert not mal_file.exists()

    # Verify quarantined file exists in quarantine vault
    locked_files = list(q_dir.glob("*.locked"))
    assert len(locked_files) == 1
    assert locked_files[0].name.endswith(".locked")

    # Verify quarantine manifest
    manifests = list(q_dir.glob("*.manifest.json"))
    assert len(manifests) == 1


def test_prevention_safeguards_system_processes(tmp_path: Path):
    """Test prevention engine safeguards: never terminate core system processes or System32 files."""
    # Attempt to terminate PID 4 (System)
    res_pid4 = terminate_process(4, reason="Test attempt")
    assert res_pid4["success"] is False
    assert "critical system PID" in res_pid4["error"]

    # Attempt to quarantine System32 file
    res_sys32 = quarantine_file(r"C:\Windows\System32\cmd.exe", reason="Test attempt")
    assert res_sys32["success"] is False
    assert "Windows system directory" in res_sys32["error"]


def test_quarantine_and_restore_cycle(tmp_path: Path):
    """Test quarantining a suspicious file and restoring it cleanly."""
    q_dir = tmp_path / "quarantine"
    target = tmp_path / "test_drop.exe"
    target.write_bytes(b"Payload to be quarantined")

    q_res = quarantine_file(target, sha256="aabbccddeeff", reason="Testing quarantine", quarantine_dir=q_dir)
    assert q_res["success"] is True
    assert not target.exists()

    quarantine_id = q_res["quarantine_id"]

    # Restore the file
    r_res = restore_quarantined_file(quarantine_id, quarantine_dir=q_dir)
    assert r_res["success"] is True
    assert target.exists()
    assert target.read_bytes() == b"Payload to be quarantined"


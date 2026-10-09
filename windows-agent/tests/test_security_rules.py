from engine.rules import analyze_process, analyze_network
from engine.scoring import score_findings


def test_downloads_executable_is_flagged(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {
            "status": "Valid",
            "signer": "Demo Publisher",
            "message": "Signature verified.",
        },
    )

    event = {
        "process_name": "demo.exe",
        "pid": 123,
        "parent_pid": 1,
        "executable": r"C:\Users\Demo\Downloads\demo.exe",
        "reasons": [],
    }

    findings = analyze_process(event)

    assert findings[0]["rule_id"] == "PROC_WRITABLE_LOCATION"
    assert findings[0]["severity"] == "medium"


def test_normal_chrome_path_is_informational(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {
            "status": "Valid",
            "signer": "Google LLC",
            "message": "Signature verified.",
        },
    )

    event = {
        "process_name": "chrome.exe",
        "pid": 456,
        "parent_pid": 100,
        "executable": (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ),
        "reasons": [],
    }

    findings = analyze_process(event)

    assert findings[0]["rule_id"] == "PROC_OBSERVED"
    assert findings[0]["severity"] == "info"
    assert any(
        finding["rule_id"] == "PROC_SIGNATURE_VALID"
        for finding in findings
    )


def test_missing_executable_path_is_informational():
    event = {
        "process_name": "System",
        "pid": 4,
        "parent_pid": 0,
        "executable": None,
        "reasons": [],
    }

    findings = analyze_process(event)

    assert findings[0]["rule_id"] == "PROC_PATH_UNAVAILABLE"
    assert findings[0]["severity"] == "info"


def test_critical_score_is_85():
    result = score_findings([{"severity": "critical"}])

    assert result["score"] == 85
    assert result["severity"] == "critical"


def test_network_connection_is_observational():
    event = {
        "process_name": "chrome.exe",
        "remote_ip": "192.0.2.10",
        "remote_port": 443,
        "protocol": "TCP",
        "status": "ESTABLISHED",
    }

    findings = analyze_network(event)

    assert findings[0]["rule_id"] == "NET_CONNECTION_OBSERVED"
    assert findings[0]["severity"] == "info"


def test_unsigned_executable_needs_review(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {
            "status": "NotSigned",
            "signer": None,
            "message": "The file is not digitally signed.",
        },
    )

    event = {
        "process_name": "unknown.exe",
        "pid": 789,
        "parent_pid": 100,
        "executable": r"C:\Apps\unknown.exe",
        "reasons": [],
    }

    findings = analyze_process(event)

    signature_finding = next(
        finding for finding in findings
        if finding["rule_id"] == "PROC_SIGNATURE_REVIEW"
    )

    assert signature_finding["severity"] == "low"


def test_invalid_signature_needs_review(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {
            "status": "HashMismatch",
            "signer": "Example Publisher",
            "message": "The file hash does not match.",
        },
    )

    event = {
        "process_name": "changed.exe",
        "pid": 790,
        "parent_pid": 100,
        "executable": r"C:\Apps\changed.exe",
        "reasons": [],
    }

    findings = analyze_process(event)

    assert any(
        finding["rule_id"] == "PROC_SIGNATURE_REVIEW"
        for finding in findings
    )


def test_unavailable_signature_is_informational(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {
            "status": "unavailable",
            "signer": None,
            "message": "Inspection unavailable.",
        },
    )

    event = {
        "process_name": "app.exe",
        "pid": 791,
        "parent_pid": 100,
        "executable": r"C:\Apps\app.exe",
        "reasons": [],
    }

    findings = analyze_process(event)

    signature_finding = next(
        finding for finding in findings
        if finding["rule_id"] == "PROC_SIGNATURE_UNAVAILABLE"
    )

    assert signature_finding["severity"] == "info"

from engine.rules import (
    analyze_process,
    analyze_network,
    analyze_dns,
    analyze_persistence,
    analyze_scheduled_task,
    analyze_service,
)
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


# --- Extended Tests for Process Monitoring & Rules ---

def test_process_terminated_rule():
    event = {
        "event_type": "process_terminated",
        "process_name": "bad.exe",
        "pid": 1234,
    }
    findings = analyze_process(event)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PROC_TERMINATED"
    assert findings[0]["severity"] == "info"


def test_office_parent_spawning_interpreter(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "Valid", "signer": "Microsoft"},
    )
    event = {
        "process_name": "powershell.exe",
        "pid": 555,
        "parent_pid": 444,
        "parent_name": "winword.exe",
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -NoProfile",
    }
    findings = analyze_process(event)
    rule_ids = [f["rule_id"] for f in findings]
    assert "PROC_SUSPICIOUS_PARENT_OFFICE" in rule_ids
    office_finding = next(f for f in findings if f["rule_id"] == "PROC_SUSPICIOUS_PARENT_OFFICE")
    assert office_finding["severity"] == "high"


def test_suspicious_cmdline_encoded_command(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "Valid", "signer": "Microsoft"},
    )
    event = {
        "process_name": "powershell.exe",
        "pid": 556,
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -encodedcommand SQBFAFgA...",
    }
    findings = analyze_process(event)
    rule_ids = [f["rule_id"] for f in findings]
    assert "PROC_SUSPICIOUS_COMMAND_LINE" in rule_ids
    cmd_finding = next(f for f in findings if f["rule_id"] == "PROC_SUSPICIOUS_COMMAND_LINE")
    assert cmd_finding["severity"] == "high"


def test_suspicious_cmdline_shadow_copy(monkeypatch):
    monkeypatch.setattr(
        "engine.rules.inspect_signature",
        lambda path: {"status": "Valid", "signer": "Microsoft"},
    )
    event = {
        "process_name": "vssadmin.exe",
        "pid": 557,
        "executable": r"C:\Windows\System32\vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
    }
    findings = analyze_process(event)
    rule_ids = [f["rule_id"] for f in findings]
    assert "PROC_SUSPICIOUS_COMMAND_LINE" in rule_ids
    cmd_finding = next(f for f in findings if f["rule_id"] == "PROC_SUSPICIOUS_COMMAND_LINE")
    assert cmd_finding["severity"] == "high"


# --- Persistence Rules Tests ---

def test_persistence_writable_location():
    event = {
        "event_type": "startup_item_added",
        "name": "Updater",
        "location": "HKCU_Run",
        "command": r"C:\Users\User\AppData\Local\Temp\evil.exe",
    }
    findings = analyze_persistence(event)
    assert any(f["rule_id"] == "PERSIST_WRITABLE_LOCATION" for f in findings)


def test_persistence_suspicious_command():
    event = {
        "event_type": "startup_item_added",
        "name": "Sync",
        "location": "HKCU_Run",
        "command": "powershell.exe -enc AAAA",
    }
    findings = analyze_persistence(event)
    assert any(f["rule_id"] == "PERSIST_SUSPICIOUS_COMMAND" for f in findings)


def test_persistence_removed():
    event = {
        "event_type": "startup_item_removed",
        "name": "OldApp",
        "location": "HKCU_Run",
    }
    findings = analyze_persistence(event)
    assert findings[0]["rule_id"] == "PERSIST_REMOVED"
    assert findings[0]["severity"] == "info"


def test_persistence_normal():
    event = {
        "event_type": "startup_item_added",
        "name": "NormalApp",
        "location": "HKLM_Run",
        "command": r"C:\Program Files\NormalApp\app.exe",
    }
    findings = analyze_persistence(event)
    assert findings[0]["rule_id"] == "PERSIST_ITEM_OBSERVED"


# --- Scheduled Task Rules Tests ---

def test_scheduled_task_writable_location():
    event = {
        "event_type": "scheduled_task_created",
        "task_name": "\\MalTask",
        "task_to_run": r"C:\Users\User\Downloads\script.bat",
    }
    findings = analyze_scheduled_task(event)
    assert any(f["rule_id"] == "TASK_WRITABLE_LOCATION" for f in findings)


def test_scheduled_task_suspicious_command():
    event = {
        "event_type": "scheduled_task_created",
        "task_name": "\\BypassTask",
        "task_to_run": "powershell.exe -ExecutionPolicy Bypass -File C:\\script.ps1",
    }
    findings = analyze_scheduled_task(event)
    assert any(f["rule_id"] == "TASK_SUSPICIOUS_COMMAND" for f in findings)


def test_scheduled_task_deleted():
    event = {
        "event_type": "scheduled_task_deleted",
        "task_name": "\\OldTask",
    }
    findings = analyze_scheduled_task(event)
    assert findings[0]["rule_id"] == "TASK_DELETED"
    assert findings[0]["severity"] == "info"


def test_scheduled_task_normal():
    event = {
        "event_type": "scheduled_task_created",
        "task_name": "\\CleanTask",
        "task_to_run": r"C:\Windows\System32\cleanmgr.exe",
    }
    findings = analyze_scheduled_task(event)
    assert findings[0]["rule_id"] == "TASK_OBSERVED"


# --- Service Rules Tests ---

def test_service_writable_location():
    event = {
        "event_type": "service_installed",
        "name": "BadSvc",
        "display_name": "Bad Service",
        "binpath": r"C:\Users\User\AppData\Roaming\bad.exe",
    }
    findings = analyze_service(event)
    assert any(f["rule_id"] == "SVC_WRITABLE_LOCATION" for f in findings)


def test_service_script_host():
    event = {
        "event_type": "service_installed",
        "name": "CmdSvc",
        "display_name": "Command Service",
        "binpath": r"C:\Windows\System32\cmd.exe /c calc.exe",
    }
    findings = analyze_service(event)
    assert any(f["rule_id"] == "SVC_SCRIPT_HOST" for f in findings)


def test_service_removed():
    event = {
        "event_type": "service_removed",
        "name": "OldSvc",
        "display_name": "Old Service",
    }
    findings = analyze_service(event)
    assert findings[0]["rule_id"] == "SVC_REMOVED"
    assert findings[0]["severity"] == "info"


def test_service_normal():
    event = {
        "event_type": "service_installed",
        "name": "GoodSvc",
        "display_name": "Good Service",
        "binpath": r"C:\Windows\System32\svchost.exe -k netsvcs",
    }
    findings = analyze_service(event)
    assert findings[0]["rule_id"] == "SVC_OBSERVED"


# --- Network & DNS Rules Tests ---

def test_network_threat_flagged_ip():
    event = {
        "process_name": "unknown.exe",
        "pid": 999,
        "remote_ip": "198.51.100.66",
        "remote_port": 4444,
        "threat_flagged": True,
        "threat_details": "Known C2 IP",
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_KNOWN_MALICIOUS_IP" for f in findings)
    threat_finding = next(f for f in findings if f["rule_id"] == "NET_KNOWN_MALICIOUS_IP")
    assert threat_finding["severity"] == "critical"


def test_network_suspicious_client_interpreter_outbound():
    event = {
        "process_name": "powershell.exe",
        "pid": 111,
        "remote_ip": "93.184.216.34",
        "remote_port": 443,
        "is_suspicious_client": True,
        "is_public_ip": True,
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_SUSPICIOUS_CLIENT_PROCESS" for f in findings)
    finding = next(f for f in findings if f["rule_id"] == "NET_SUSPICIOUS_CLIENT_PROCESS")
    assert finding["severity"] == "high"


def test_network_repeated_burst():
    event = {
        "process_name": "updater.exe",
        "pid": 222,
        "remote_ip": "1.1.1.1",
        "remote_port": 53,
        "is_repeated_burst": True,
        "connection_count": 8,
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_REPEATED_BURST" for f in findings)
    finding = next(f for f in findings if f["rule_id"] == "NET_REPEATED_BURST")
    assert finding["severity"] == "medium"


def test_network_wide_fanout():
    event = {
        "process_name": "scanner.exe",
        "pid": 333,
        "remote_ip": "192.168.1.1",
        "remote_port": 80,
        "is_wide_fanout": True,
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_WIDE_FANOUT" for f in findings)
    finding = next(f for f in findings if f["rule_id"] == "NET_WIDE_FANOUT")
    assert finding["severity"] == "medium"


def test_network_hosting_is_informational():
    event = {
        "process_name": "chrome.exe",
        "remote_ip": "104.16.132.229",
        "remote_port": 443,
        "is_hosting": True,
        "hosting_provider": "Cloudflare",
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_HOSTING_INFRASTRUCTURE" for f in findings)
    finding = next(f for f in findings if f["rule_id"] == "NET_HOSTING_INFRASTRUCTURE")
    assert finding["severity"] == "info"


def test_network_foreign_ip_is_informational():
    event = {
        "process_name": "chrome.exe",
        "remote_ip": "185.199.108.153",
        "remote_port": 443,
        "country": "Netherlands",
        "city": "Amsterdam",
    }
    findings = analyze_network(event)
    assert any(f["rule_id"] == "NET_FOREIGN_LOCATION" for f in findings)
    finding = next(f for f in findings if f["rule_id"] == "NET_FOREIGN_LOCATION")
    assert finding["severity"] == "info"


def test_dns_dynamic_dns_rule():
    event = {
        "event_type": "dns_query_observed",
        "domain": "badc2.duckdns.org",
        "is_dynamic_dns": True,
    }
    findings = analyze_dns(event)
    assert any(f["rule_id"] == "DNS_DYNAMIC_DNS" for f in findings)
    assert findings[0]["severity"] == "medium"


def test_dns_potential_dga_rule():
    event = {
        "event_type": "dns_query_observed",
        "domain": "q89xkm18902vlza09.com",
        "is_potential_dga": True,
        "entropy": 3.8,
    }
    findings = analyze_dns(event)
    assert any(f["rule_id"] == "DNS_POTENTIAL_DGA" for f in findings)
    assert findings[0]["severity"] == "medium"


def test_dns_suspicious_tld_rule():
    event = {
        "event_type": "dns_query_observed",
        "domain": "tracker.top",
        "is_suspicious_tld": True,
    }
    findings = analyze_dns(event)
    assert any(f["rule_id"] == "DNS_SUSPICIOUS_TLD" for f in findings)
    assert findings[0]["severity"] == "low"


def test_dns_normal_query_rule():
    event = {
        "event_type": "dns_query_observed",
        "domain": "github.com",
        "resolved_ips": ["20.207.73.82"],
    }
    findings = analyze_dns(event)
    assert findings[0]["rule_id"] == "DNS_QUERY_OBSERVED"
    assert findings[0]["severity"] == "info"


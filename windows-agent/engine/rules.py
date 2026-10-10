"""Explainable local security rules for process, persistence, task, service, and network events."""

from pathlib import Path
import re

from engine.reputation import reputation_manager
from monitors.file_metadata import is_potentially_writable_location, inspect_file_metadata, calculate_file_hash
from monitors.signatures import inspect_signature


def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    reason: str,
    confidence: str = "informational",
    evidence: dict | None = None,
) -> dict:
    """Helper ensuring every finding complies with explainability standards."""
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence or {},
        "reason": reason,
        "explanation": reason,
    }


WRITABLE_DIR_NAMES = {
    "downloads",
    "temp",
    "tmp",
    "appdata",
    "roaming",
    "local",
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    (re.compile(r"-(?:enc|encodedcommand)\b", re.I), "Encoded PowerShell command execution"),
    (re.compile(r"-executionpolicy\s+bypass\b", re.I), "PowerShell execution policy bypass"),
    (re.compile(r"-windowstyle\s+hidden\b", re.I), "Hidden window execution style"),
    (re.compile(r"\bdownloadstring\b", re.I), "In-memory script download string"),
    (re.compile(r"\bcurl\b.*\|\s*(?:bash|powershell|cmd)\b", re.I), "Piped web download into shell execution"),
    (re.compile(r"\bvssadmin\s+delete\s+shadows\b", re.I), "Volume shadow copy deletion attempt"),
    (re.compile(r"\bcertutil\b.*-urlcache\b", re.I), "Certutil abused for file download"),
]

LOLBIN_COMMAND_PATTERNS = [
    (re.compile(r"\bcertutil(?:\.exe)?\b.*-(?:urlcache|decode)\b", re.I), "Certutil abused for remote download or payload decoding"),
    (re.compile(r"\bmshta(?:\.exe)?\b.*(?:https?://|vbscript:|javascript:)", re.I), "Mshta abused to execute remote script or inline payload"),
    (re.compile(r"\bregsvr32(?:\.exe)?\b.*(?:\/i:https?:\/\/|\/i:ftp:\/\/)", re.I), "Regsvr32 abused to execute remote scriptlet"),
    (re.compile(r"\brundll32(?:\.exe)?\b.*(?:javascript:|vbscript:)", re.I), "Rundll32 abused to execute inline script"),
    (re.compile(r"\bbitsadmin(?:\.exe)?\b.*\/transfer\b", re.I), "Bitsadmin abused for background file download"),
]

OFFICE_PARENT_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}

SUSPICIOUS_CHILD_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}


def analyze_process(event: dict) -> list[dict]:
    """Analyze a process event and return security findings."""
    event_type = event.get("event_type", "process_observed")

    if event_type == "process_terminated":
        name = str(event.get("process_name") or "unknown")
        pid = event.get("pid")
        return [{
            "rule_id": "PROC_TERMINATED",
            "title": "Process terminated",
            "severity": "info",
            "reason": f"Process {name} (PID {pid}) terminated.",
            "confidence": "informational",
        }]

    findings = []
    name = str(event.get("process_name") or "unknown").lower()
    executable = event.get("executable")
    parent_pid = event.get("parent_pid")
    parent_name = str(event.get("parent_name") or "").lower()
    command_line = event.get("command_line") or ""
    reasons = event.get("reasons", [])

    # Check for core system process masquerading (e.g. svchost outside System32)
    if executable and reputation_manager.check_masquerading(name, executable):
        findings.append({
            "rule_id": "PROC_MASQUERADING",
            "title": "Core system process running from abnormal location (masquerading)",
            "severity": "critical",
            "reason": (
                f"Core Windows process '{name}' is executing from '{executable}'. "
                "Legitimate system instances must execute exclusively from System32 or Windows directories."
            ),
            "explanation": (
                f"Core Windows process '{name}' is executing from '{executable}'. "
                "Legitimate system instances must execute exclusively from System32 or Windows directories."
            ),
            "confidence": "high",
            "evidence": {"process_name": name, "executable": executable},
        })

    # Check for deceptive double extensions (e.g. invoice.pdf.exe)
    if executable:
        exe_path = Path(executable)
        if reputation_manager.check_double_extension(exe_path.name):
            findings.append({
                "rule_id": "PROC_DOUBLE_EXTENSION",
                "title": "Executable uses deceptive double extension",
                "severity": "high",
                "reason": (
                    f"Binary '{exe_path.name}' uses a deceptive double extension. "
                    "Double extensions are used to trick users into opening executables disguised as documents."
                ),
                "explanation": (
                    f"Binary '{exe_path.name}' uses a deceptive double extension. "
                    "Double extensions are used to trick users into opening executables disguised as documents."
                ),
                "confidence": "high",
                "evidence": {"filename": exe_path.name, "executable": executable},
            })

    # Check for suspicious parent-child process relationship
    if parent_name in OFFICE_PARENT_PROCESSES and name in SUSPICIOUS_CHILD_PROCESSES:
        findings.append({
            "rule_id": "PROC_SUSPICIOUS_PARENT_OFFICE",
            "title": "Office application spawned a shell or script interpreter",
            "severity": "high",
            "reason": (
                f"{parent_name} (PID {parent_pid}) spawned {name}. "
                "Office macros launching command interpreters is a common malware technique."
            ),
            "explanation": (
                f"{parent_name} (PID {parent_pid}) spawned {name}. "
                "Office macros launching command interpreters is a common malware technique."
            ),
            "confidence": "high",
            "evidence": {"parent_name": parent_name, "parent_pid": parent_pid, "child_name": name},
        })

    # Check for Living-Off-The-Land binaries (LOLBins) and suspicious arguments
    if command_line:
        for pattern, desc in LOLBIN_COMMAND_PATTERNS:
            if pattern.search(command_line):
                findings.append({
                    "rule_id": "PROC_SUSPICIOUS_LOLBIN",
                    "title": f"Living-off-the-land command pattern: {desc}",
                    "severity": "high",
                    "reason": f"{name} executed with LOLBin argument: {desc}.",
                    "explanation": f"{name} executed with LOLBin argument: {desc}.",
                    "confidence": "high",
                    "evidence": {"command_line": command_line, "pattern": desc},
                })
                break

        for pattern, desc in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern.search(command_line):
                findings.append({
                    "rule_id": "PROC_SUSPICIOUS_COMMAND_LINE",
                    "title": f"Suspicious command-line argument: {desc}",
                    "severity": "high" if "shadow" in desc.lower() or "encoded" in desc.lower() else "medium",
                    "reason": f"{name} executed with command line containing: {desc}.",
                    "explanation": f"{name} executed with command line containing: {desc}.",
                    "confidence": "medium",
                    "evidence": {"command_line": command_line, "pattern": desc},
                })
                break

    # Executable path, hash reputation, and signature checks
    if executable:
        path = Path(executable)
        normalized_parts = {part.lower() for part in path.parts}

        # File hash reputation check
        sha256 = event.get("file_metadata", {}).get("sha256")
        if not sha256 and path.is_file():
            sha256 = calculate_file_hash(path)

        if sha256:
            rep = reputation_manager.check_hash_reputation(sha256)
            if rep["is_blocklisted"]:
                findings.append({
                    "rule_id": "THREAT_BLOCKLIST_HASH",
                    "title": "Process executable matches known malicious hash",
                    "severity": "critical",
                    "reason": f"File hash {sha256} matches known threat indicator: {rep['threat_name']}.",
                    "explanation": f"File hash {sha256} matches known threat indicator: {rep['threat_name']}.",
                    "confidence": "high",
                    "evidence": {"sha256": sha256, "executable": executable, "threat": rep["threat_name"]},
                })
            elif rep["is_allowlisted"]:
                findings.append({
                    "rule_id": "PROC_ALLOWLISTED_HASH",
                    "title": "Process matches trusted hash allowlist",
                    "severity": "info",
                    "reason": f"File hash {sha256} is present on the trusted application allowlist.",
                    "explanation": f"File hash {sha256} is present on the trusted application allowlist.",
                    "confidence": "informational",
                    "evidence": {"sha256": sha256, "executable": executable},
                })

        if normalized_parts & WRITABLE_DIR_NAMES or is_potentially_writable_location(path):
            findings.append({
                "rule_id": "PROC_WRITABLE_LOCATION",
                "title": "Executable in a potentially writable location",
                "severity": "medium",
                "reason": (
                    f"{event.get('process_name')} is running from {executable}. "
                    "Executables in user-writable folders can warrant review."
                ),
                "explanation": (
                    f"{event.get('process_name')} is running from {executable}. "
                    "Executables in user-writable folders can warrant review."
                ),
                "confidence": "low",
                "evidence": {"executable": executable},
            })

        # Signature inspection provides evidence, not an automatic verdict.
        signature = inspect_signature(str(executable))
        signature_status = str(signature.get("status") or "unknown")
        signer = signature.get("signer")
        message = str(signature.get("message") or "")

        if signature_status.lower() == "valid":
            is_trusted_pub = reputation_manager.is_allowlisted_publisher(signer)
            findings.append({
                "rule_id": "PROC_SIGNATURE_VALID",
                "title": (
                    "Executable digitally signed by trusted publisher"
                    if is_trusted_pub
                    else "Executable has a valid digital signature"
                ),
                "severity": "info",
                "reason": (
                    f"{event.get('process_name')} has a valid Authenticode signature"
                    + (f" from {signer}" if signer else "")
                    + (". Publisher is on trusted allowlist." if is_trusted_pub else "")
                    + ". A valid signature helps verify publisher identity "
                    "and file integrity but does not guarantee the file is safe."
                ),
                "explanation": (
                    f"{event.get('process_name')} has a valid Authenticode signature"
                    + (f" from {signer}" if signer else "")
                    + ". A valid signature verifies publisher identity and file integrity."
                ),
                "confidence": "informational",
                "evidence": {"signer": signer, "signature_status": "Valid", "is_trusted_publisher": is_trusted_pub},
            })

        elif signature_status.lower() in {
            "notsigned",
            "not_signed",
            "hashmismatch",
            "nottrusted",
            "unknownerror",
        }:
            findings.append({
                "rule_id": "PROC_SIGNATURE_REVIEW",
                "title": "Executable signature needs review",
                "severity": "low",
                "reason": (
                    f"{event.get('process_name')} signature status is {signature_status}. "
                    "This is not proof of malicious activity. "
                    f"{message}".strip()
                ),
                "explanation": (
                    f"{event.get('process_name')} signature status is {signature_status}. "
                    "Unsigned executables require investigation, but are not automatically malicious."
                ),
                "confidence": "low",
                "evidence": {"signature_status": signature_status, "message": message},
            })

        elif signature_status.lower() == "unavailable":
            findings.append({
                "rule_id": "PROC_SIGNATURE_UNAVAILABLE",
                "title": "Executable signature could not be checked",
                "severity": "info",
                "reason": (
                    f"Signature inspection for {event.get('process_name')} was unavailable. "
                    "No conclusion about the executable's safety can be made."
                ),
                "explanation": (
                    f"Signature inspection for {event.get('process_name')} was unavailable."
                ),
                "confidence": "informational",
                "evidence": {"signature_status": "unavailable"},
            })

        else:
            findings.append({
                "rule_id": "PROC_SIGNATURE_STATUS_UNKNOWN",
                "title": "Executable signature status is inconclusive",
                "severity": "info",
                "reason": (
                    f"Signature inspection for {event.get('process_name')} returned "
                    f"status {signature_status}. {message}".strip()
                ),
                "explanation": (
                    f"Signature inspection for {event.get('process_name')} returned status {signature_status}."
                ),
                "confidence": "informational",
                "evidence": {"signature_status": signature_status},
            })

    for reason in reasons:
        findings.append({
            "rule_id": "PROC_MONITOR_SIGNAL",
            "title": "Process monitor reported a signal",
            "severity": "medium",
            "reason": str(reason),
            "explanation": str(reason),
            "confidence": "low",
            "evidence": {"signal": str(reason)},
        })

    if not executable and not findings:
        findings.append({
            "rule_id": "PROC_PATH_UNAVAILABLE",
            "title": "Executable path unavailable",
            "severity": "info",
            "reason": (
                f"The executable path for {event.get('process_name')} could not be obtained. "
                "This can occur for protected or system processes."
            ),
            "explanation": (
                f"The executable path for {event.get('process_name')} could not be obtained."
            ),
            "confidence": "informational",
            "evidence": {"process_name": event.get("process_name")},
        })

    elif executable:
        has_process_signal = any(
            finding["rule_id"] in {
                "THREAT_BLOCKLIST_HASH",
                "PROC_MASQUERADING",
                "PROC_DOUBLE_EXTENSION",
                "PROC_SUSPICIOUS_LOLBIN",
                "PROC_WRITABLE_LOCATION",
                "PROC_MONITOR_SIGNAL",
                "PROC_SUSPICIOUS_PARENT_OFFICE",
                "PROC_SUSPICIOUS_COMMAND_LINE",
            }
            for finding in findings
        )

        if not has_process_signal:
            findings.insert(0, {
                "rule_id": "PROC_OBSERVED",
                "title": "New process observed",
                "severity": "info",
                "reason": (
                    f"Observed {event.get('process_name')} (PID {event.get('pid')}, "
                    f"parent PID {parent_pid}); "
                    "no configured suspicious indicators matched."
                ),
                "explanation": (
                    f"Observed {event.get('process_name')} (PID {event.get('pid')}, "
                    f"parent PID {parent_pid}); "
                    "no configured suspicious indicators matched."
                ),
                "confidence": "informational",
                "evidence": {"process_name": event.get("process_name"), "pid": event.get("pid")},
            })

    return findings


def analyze_persistence(event: dict) -> list[dict]:
    """Analyze startup persistence additions and modifications."""
    findings = []
    event_type = event.get("event_type", "startup_item_added")
    name = event.get("name", "unknown")
    command = str(event.get("command") or "")
    location = event.get("location", "")

    if event_type == "startup_item_removed":
        return [{
            "rule_id": "PERSIST_REMOVED",
            "title": "Startup persistence item removed",
            "severity": "info",
            "reason": f"Startup item '{name}' was removed from {location}.",
            "confidence": "informational",
        }]

    # Check for executable in user-writable location
    is_writable = False
    command_lower = command.lower()
    for dir_name in WRITABLE_DIR_NAMES:
        if f"\\{dir_name}\\" in command_lower or f"/{dir_name}/" in command_lower:
            is_writable = True
            break

    if is_writable:
        findings.append({
            "rule_id": "PERSIST_WRITABLE_LOCATION",
            "title": "Startup entry points to a user-writable directory",
            "severity": "high",
            "reason": (
                f"Startup entry '{name}' in {location} points to a writable folder: {command}. "
                "Persistence established in Temp/AppData/Downloads is frequently seen in malware."
            ),
            "confidence": "medium",
        })

    # Check for script interpreters or suspicious command lines
    for pattern, desc in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern.search(command):
            findings.append({
                "rule_id": "PERSIST_SUSPICIOUS_COMMAND",
                "title": f"Startup entry uses suspicious arguments ({desc})",
                "severity": "high",
                "reason": f"Startup item '{name}' executes: {desc}.",
                "confidence": "medium",
            })
            break

    if not findings:
        findings.append({
            "rule_id": "PERSIST_ITEM_OBSERVED",
            "title": "Startup persistence entry registered",
            "severity": "low" if event_type == "startup_item_added" else "info",
            "reason": f"Startup entry '{name}' in {location} executes: {command}.",
            "confidence": "informational",
        })

    return findings


def analyze_scheduled_task(event: dict) -> list[dict]:
    """Analyze scheduled task creations and modifications."""
    findings = []
    event_type = event.get("event_type", "scheduled_task_created")
    task_name = event.get("task_name", "unknown")
    task_to_run = str(event.get("task_to_run") or "")

    if event_type == "scheduled_task_deleted":
        return [{
            "rule_id": "TASK_DELETED",
            "title": "Scheduled task deleted",
            "severity": "info",
            "reason": f"Scheduled task '{task_name}' was deleted.",
            "confidence": "informational",
        }]

    # Check if task executes from a writable directory
    is_writable = False
    task_lower = task_to_run.lower()
    for dir_name in WRITABLE_DIR_NAMES:
        if f"\\{dir_name}\\" in task_lower or f"/{dir_name}/" in task_lower:
            is_writable = True
            break

    if is_writable:
        findings.append({
            "rule_id": "TASK_WRITABLE_LOCATION",
            "title": "Scheduled task executes binary in writable directory",
            "severity": "high",
            "reason": (
                f"Task '{task_name}' runs command in writable location: {task_to_run}. "
                "Scheduled tasks executing from user-writable paths warrant investigation."
            ),
            "confidence": "medium",
        })

    # Check for suspicious command lines
    for pattern, desc in SUSPICIOUS_CMDLINE_PATTERNS:
        if pattern.search(task_to_run):
            findings.append({
                "rule_id": "TASK_SUSPICIOUS_COMMAND",
                "title": f"Scheduled task contains suspicious argument ({desc})",
                "severity": "high",
                "reason": f"Task '{task_name}' contains: {desc}.",
                "confidence": "medium",
            })
            break

    if not findings:
        findings.append({
            "rule_id": "TASK_OBSERVED",
            "title": "Scheduled task registered or modified",
            "severity": "low" if event_type == "scheduled_task_created" else "info",
            "reason": f"Scheduled task '{task_name}' configured to run: {task_to_run or '(no action)'}.",
            "confidence": "informational",
        })

    return findings


def analyze_service(event: dict) -> list[dict]:
    """Analyze Windows service installations and modifications."""
    findings = []
    event_type = event.get("event_type", "service_installed")
    name = event.get("name", "unknown")
    display_name = event.get("display_name", name)
    binpath = str(event.get("binpath") or "")

    if event_type == "service_removed":
        return [{
            "rule_id": "SVC_REMOVED",
            "title": "Windows service removed",
            "severity": "info",
            "reason": f"Service '{display_name}' ({name}) was removed.",
            "confidence": "informational",
        }]

    # Check for service binary in user writable directory
    is_writable = False
    bin_lower = binpath.lower()
    for dir_name in WRITABLE_DIR_NAMES:
        if f"\\{dir_name}\\" in bin_lower or f"/{dir_name}/" in bin_lower:
            is_writable = True
            break

    if is_writable:
        findings.append({
            "rule_id": "SVC_WRITABLE_LOCATION",
            "title": "Service executable installed in user-writable location",
            "severity": "high",
            "reason": (
                f"Service '{display_name}' ({name}) points to {binpath}. "
                "Services running from user-writable paths can indicate persistence."
            ),
            "confidence": "high",
        })

    # Check if service executes scripts / cmd / powershell
    for child in SUSPICIOUS_CHILD_PROCESSES:
        if child in bin_lower:
            findings.append({
                "rule_id": "SVC_SCRIPT_HOST",
                "title": "Service executes script or command interpreter",
                "severity": "high",
                "reason": f"Service '{display_name}' executes command interpreter: {binpath}.",
                "confidence": "medium",
            })
            break

    if not findings:
        findings.append({
            "rule_id": "SVC_OBSERVED",
            "title": "Windows service observed",
            "severity": "low" if event_type == "service_installed" else "info",
            "reason": f"Service '{display_name}' ({name}) binary path: {binpath}.",
            "confidence": "informational",
        })

    return findings


def analyze_network(event: dict) -> list[dict]:
    """Analyze network connection event and return security findings."""
    findings = []
    process = str(event.get("process_name") or "unknown")
    pid = event.get("pid")
    remote_ip = str(event.get("remote_ip") or "unknown")
    remote_port = event.get("remote_port")
    status = str(event.get("status") or "UNKNOWN")
    protocol = str(event.get("protocol") or "TCP")
    is_public = event.get("is_public_ip", False)
    country = event.get("country")
    city = event.get("city")
    is_hosting = event.get("is_hosting", False)
    hosting_provider = event.get("hosting_provider")

    # 1. Threat Intelligence & Blocklist Flag
    blocklisted_ip = reputation_manager.check_ip_blocklist(remote_ip)
    if event.get("threat_flagged") or blocklisted_ip:
        threat_desc = blocklisted_ip["threat_name"] if blocklisted_ip else (event.get("threat_details") or "Matches threat intelligence blocklist")
        findings.append({
            "rule_id": "NET_KNOWN_MALICIOUS_IP",
            "title": "Connection to known malicious IP address",
            "severity": "critical",
            "reason": (
                f"{process} (PID {pid}) connected to threat-flagged IP {remote_ip}:{remote_port}. "
                f"Details: {threat_desc}."
            ),
            "explanation": (
                f"{process} (PID {pid}) connected to threat-flagged IP {remote_ip}:{remote_port}. "
                f"Details: {threat_desc}."
            ),
            "confidence": "high",
            "evidence": {"remote_ip": remote_ip, "threat": threat_desc},
        })

    # 2. Suspicious client interpreter connecting to public external IP
    if event.get("is_suspicious_client") and is_public:
        findings.append({
            "rule_id": "NET_SUSPICIOUS_CLIENT_PROCESS",
            "title": "Script or command interpreter established external internet connection",
            "severity": "high",
            "reason": (
                f"Command interpreter {process} (PID {pid}) connected to public IP {remote_ip}:{remote_port}. "
                "Shells and script interpreters communicating directly over the public internet "
                "are common in reverse shells and staged payload downloads."
            ),
            "confidence": "high",
        })

    # 3. Repeated connection burst
    if event.get("is_repeated_burst"):
        findings.append({
            "rule_id": "NET_REPEATED_BURST",
            "title": "Repeated connection burst detected",
            "severity": "medium",
            "reason": (
                f"{process} initiated repeated high-frequency connections "
                f"({event.get('connection_count', 1)} times) to {remote_ip}:{remote_port}."
            ),
            "confidence": "medium",
        })

    # 4. Wide fanout / scanning
    if event.get("is_wide_fanout"):
        findings.append({
            "rule_id": "NET_WIDE_FANOUT",
            "title": "High destination fanout detected",
            "severity": "medium",
            "reason": (
                f"{process} (PID {pid}) has connected to a wide variety of distinct endpoints "
                "which may indicate scanning, sweeping, or rapid API queries."
            ),
            "confidence": "low",
        })

    # 5. Hosting Detection (Informational - explicitly clarifies benign cloud use)
    if is_hosting and hosting_provider:
        findings.append({
            "rule_id": "NET_HOSTING_INFRASTRUCTURE",
            "title": f"Remote server hosted in cloud infrastructure ({hosting_provider})",
            "severity": "info",
            "reason": (
                f"Remote IP {remote_ip} belongs to {hosting_provider}. "
                "Cloud-hosted servers and CDNs are standard for legitimate web traffic, "
                "APIs, and SaaS; this is not evidence of malicious activity on its own."
            ),
            "confidence": "informational",
        })

    # 6. Geolocation (Informational - explicitly clarifies foreign IP is normal)
    if country and country != "Local / Private":
        loc_str = f"{city}, {country}" if city else country
        findings.append({
            "rule_id": "NET_FOREIGN_LOCATION",
            "title": f"Remote host located in {loc_str}",
            "severity": "info",
            "reason": (
                f"Connection established to {remote_ip} in {loc_str}. "
                "Global internet services route traffic through diverse geographic jurisdictions; "
                "a foreign IP address is not automatically malicious."
            ),
            "confidence": "informational",
        })

    if not findings:
        findings.append({
            "rule_id": "NET_CONNECTION_OBSERVED",
            "title": "Network connection observed",
            "severity": "info",
            "reason": (
                f"{process} connected to {remote_ip}:{remote_port} "
                f"using {protocol}; state: {status}. "
                "This observation alone does not establish malicious activity."
            ),
            "confidence": "informational",
        })

    return findings


def analyze_dns(event: dict) -> list[dict]:
    """Analyze DNS query event and return security findings."""
    findings = []
    domain = str(event.get("domain") or "unknown")
    entropy = event.get("entropy", 0.0)
    resolved_ips = event.get("resolved_ips", [])

    blocklisted_domain = reputation_manager.check_domain_blocklist(domain)
    if blocklisted_domain:
        findings.append({
            "rule_id": "DNS_BLOCKLISTED_DOMAIN",
            "title": "Query to blocklisted malicious domain",
            "severity": "critical",
            "reason": f"Domain '{domain}' matches threat intelligence blocklist: {blocklisted_domain['threat_name']}.",
            "explanation": f"Domain '{domain}' matches threat intelligence blocklist: {blocklisted_domain['threat_name']}.",
            "confidence": "high",
            "evidence": {"domain": domain, "threat": blocklisted_domain["threat_name"]},
        })

    if event.get("is_dynamic_dns"):
        findings.append({
            "rule_id": "DNS_DYNAMIC_DNS",
            "title": "Query resolved to Dynamic DNS provider",
            "severity": "medium",
            "reason": (
                f"Domain '{domain}' uses a dynamic DNS provider. Dynamic DNS allows "
                "rapid IP reallocation and is frequently abused for transient C2 endpoints."
            ),
            "confidence": "medium",
        })

    if event.get("is_potential_dga"):
        findings.append({
            "rule_id": "DNS_POTENTIAL_DGA",
            "title": "High-entropy domain name (possible DGA)",
            "severity": "medium",
            "reason": (
                f"Domain '{domain}' has high Shannon entropy ({entropy}) and pseudo-random "
                "characteristics commonly associated with Domain Generation Algorithms (DGA)."
            ),
            "confidence": "medium",
        })

    if event.get("is_suspicious_tld"):
        findings.append({
            "rule_id": "DNS_SUSPICIOUS_TLD",
            "title": "Query to high-abuse / high-spam TLD",
            "severity": "low",
            "reason": (
                f"Domain '{domain}' uses a top-level domain frequently associated with "
                "disposable infrastructure and spam campaigns."
            ),
            "confidence": "low",
        })

    if not findings:
        ip_summary = f" (resolved to: {', '.join(resolved_ips[:3])})" if resolved_ips else ""
        findings.append({
            "rule_id": "DNS_QUERY_OBSERVED",
            "title": "DNS query observed",
            "severity": "info",
            "reason": f"Resolved domain '{domain}'{ip_summary}.",
            "confidence": "informational",
        })

    return findings


def analyze_download(event: dict) -> list[dict]:
    """
    Evaluate collected file download evidence against local detection rules,
    file reputation, and digital signature verification.
    """
    findings: list[dict] = []
    filename = event.get("filename") or ""
    file_path = event.get("file_path") or ""
    sha256 = (event.get("sha256") or "").lower()
    signature = event.get("signature") or {}
    sig_status = signature.get("status", "unavailable").lower()
    signer = signature.get("signer")
    ext = (event.get("extension") or Path(filename).suffix).lower()
    motw = event.get("mark_of_the_web", False)
    zone_id = event.get("zone_id")

    # 1. Blocklist File Hash (Critical Threat Intelligence Hit)
    if sha256 and reputation_manager.is_hash_blocklisted(sha256):
        findings.append({
            "rule_id": "DOWNLOAD_HASH_BLOCKLIST",
            "title": "Downloaded file matches known malicious SHA-256 hash",
            "severity": "critical",
            "confidence": "high",
            "evidence": {
                "sha256": sha256,
                "filename": filename,
                "file_path": file_path,
            },
            "reason": (
                f"File '{filename}' matches a known malicious hash in threat intelligence "
                f"blocklist ({sha256})."
            ),
            "explanation": (
                f"File '{filename}' matches a known malware hash in the blocklist."
            ),
        })

    # 2. Allowlisted File Hash or Trusted Publisher
    if sha256 and reputation_manager.is_hash_allowlisted(sha256):
        findings.append({
            "rule_id": "DOWNLOAD_HASH_ALLOWLIST",
            "title": "Downloaded file matches known benign hash",
            "severity": "info",
            "confidence": "high",
            "evidence": {"sha256": sha256, "filename": filename},
            "reason": f"File '{filename}' matches an allowlisted benign hash.",
            "explanation": f"File '{filename}' is allowlisted.",
        })
    elif signer and reputation_manager.is_publisher_trusted(signer):
        findings.append({
            "rule_id": "DOWNLOAD_TRUSTED_PUBLISHER",
            "title": f"Downloaded file signed by trusted publisher ({signer})",
            "severity": "info",
            "confidence": "high",
            "evidence": {"signer": signer, "filename": filename},
            "reason": f"File '{filename}' has a valid signature from trusted vendor '{signer}'.",
            "explanation": f"File '{filename}' is signed by trusted publisher '{signer}'.",
        })

    # 3. Deceptive Double Extension (e.g. invoice.pdf.exe)
    if filename and reputation_manager.has_double_extension(filename):
        findings.append({
            "rule_id": "DOWNLOAD_DOUBLE_EXTENSION",
            "title": "Downloaded file employs deceptive double extension",
            "severity": "critical",
            "confidence": "high",
            "evidence": {"filename": filename, "file_path": file_path},
            "reason": (
                f"File '{filename}' uses a deceptive double extension to disguise an executable "
                "or script payload as a benign document."
            ),
            "explanation": (
                f"File '{filename}' uses a deceptive double extension."
            ),
        })

    # 4. Masquerading System Binary
    if filename and reputation_manager.is_masquerading(filename, file_path):
        findings.append({
            "rule_id": "DOWNLOAD_MASQUERADING",
            "title": "Downloaded file masquerades as core Windows system component",
            "severity": "high",
            "confidence": "high",
            "evidence": {"filename": filename, "file_path": file_path},
            "reason": (
                f"File '{filename}' matches a Windows system binary name but was downloaded to a user directory ({file_path})."
            ),
            "explanation": (
                f"File '{filename}' masquerades as a Windows core component."
            ),
        })

    # 5. Invalid / Tampered Digital Signature
    if sig_status in ("invalid", "bad", "tampered"):
        findings.append({
            "rule_id": "DOWNLOAD_INVALID_SIGNATURE",
            "title": "Downloaded binary has invalid or tampered digital signature",
            "severity": "high",
            "confidence": "high",
            "evidence": {"status": sig_status, "filename": filename},
            "reason": f"Executable '{filename}' has a broken or invalid Authenticode signature.",
            "explanation": f"Executable '{filename}' has an invalid digital signature.",
        })

    # 6. Unsigned Executable in Downloads
    elif ext in (".exe", ".dll", ".sys") and sig_status == "unsigned":
        findings.append({
            "rule_id": "DOWNLOAD_UNSIGNED_EXECUTABLE",
            "title": "Downloaded executable lacks valid digital signature",
            "severity": "medium",
            "confidence": "medium",
            "evidence": {"extension": ext, "filename": filename},
            "reason": (
                f"Executable '{filename}' was downloaded without an Authenticode digital signature. "
                "Unsigned downloads pose elevated risk and warrant user review."
            ),
            "explanation": (
                f"Executable '{filename}' is unsigned."
            ),
        })

    # 7. Suspicious Script or Container Payload with Mark-of-the-Web
    dangerous_payload_exts = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta", ".scr", ".iso", ".img", ".jar"}
    if ext in dangerous_payload_exts and (motw or zone_id == 3):
        findings.append({
            "rule_id": "DOWNLOAD_SUSPICIOUS_PAYLOAD",
            "title": f"Downloaded script or payload container ({ext}) from the Internet",
            "severity": "medium",
            "confidence": "medium",
            "evidence": {
                "extension": ext,
                "filename": filename,
                "mark_of_the_web": motw,
                "zone_id": zone_id,
            },
            "reason": (
                f"Script or payload container '{filename}' ({ext}) was downloaded from the Internet "
                "with Mark-of-the-Web. Such file types are common vectors for initial access."
            ),
            "explanation": (
                f"Script or payload file '{filename}' was downloaded from the Internet."
            ),
        })

    # 8. Mark-of-the-Web Observation
    if motw or zone_id == 3:
        findings.append({
            "rule_id": "DOWNLOAD_MOTW_INTERNET",
            "title": "File tagged with Mark-of-the-Web (Internet Zone)",
            "severity": "info",
            "confidence": "high",
            "evidence": {
                "filename": filename,
                "zone_id": zone_id,
                "download_url": event.get("download_url"),
            },
            "reason": f"File '{filename}' originated from Internet Zone (ZoneId={zone_id}).",
            "explanation": f"File '{filename}' originated from Internet Zone.",
        })

    # Fallback informational finding if no other findings
    if not findings:
        findings.append({
            "rule_id": "DOWNLOAD_OBSERVED",
            "title": "Downloaded file observed",
            "severity": "info",
            "confidence": "informational",
            "evidence": {"filename": filename, "file_path": file_path},
            "reason": f"Observed file '{filename}' in monitored download location.",
            "explanation": f"Observed file '{filename}'.",
        })

    return findings

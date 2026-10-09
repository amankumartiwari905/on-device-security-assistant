
"""Explainable local security rules for process and network events."""

from pathlib import Path

from monitors.signatures import inspect_signature


WRITABLE_DIR_NAMES = {
    "downloads",
    "temp",
    "tmp",
}


def analyze_process(event: dict) -> list[dict]:
    findings = []

    name = str(event.get("process_name") or "unknown")
    executable = event.get("executable")
    parent_pid = event.get("parent_pid")
    reasons = event.get("reasons", [])

    if executable:
        path = Path(executable)
        normalized_parts = {
            part.lower() for part in path.parts
        }

        if normalized_parts & WRITABLE_DIR_NAMES:
            findings.append({
                "rule_id": "PROC_WRITABLE_LOCATION",
                "title": "Executable in a potentially writable location",
                "severity": "medium",
                "reason": (
                    f"{name} is running from {executable}. "
                    "Executables in user-writable folders can warrant review."
                ),
                "confidence": "low",
            })

        # Signature inspection provides evidence, not a malware verdict.
        signature = inspect_signature(str(executable))
        signature_status = str(
            signature.get("status") or "unknown"
        )
        signer = signature.get("signer")
        message = str(signature.get("message") or "")

        if signature_status.lower() == "valid":
            findings.append({
                "rule_id": "PROC_SIGNATURE_VALID",
                "title": "Executable has a valid digital signature",
                "severity": "info",
                "reason": (
                    f"{name} has a valid Authenticode signature"
                    + (f" from {signer}" if signer else "")
                    + ". A valid signature helps verify publisher identity "
                    "and file integrity but does not guarantee the file is safe."
                ),
                "confidence": "informational",
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
                    f"{name} signature status is {signature_status}. "
                    "This is not proof of malicious activity. "
                    f"{message}".strip()
                ),
                "confidence": "low",
            })

        elif signature_status.lower() == "unavailable":
            findings.append({
                "rule_id": "PROC_SIGNATURE_UNAVAILABLE",
                "title": "Executable signature could not be checked",
                "severity": "info",
                "reason": (
                    f"Signature inspection for {name} was unavailable. "
                    "No conclusion about the executable's safety can be made."
                ),
                "confidence": "informational",
            })

        else:
            findings.append({
                "rule_id": "PROC_SIGNATURE_STATUS_UNKNOWN",
                "title": "Executable signature status is inconclusive",
                "severity": "info",
                "reason": (
                    f"Signature inspection for {name} returned "
                    f"status {signature_status}. {message}".strip()
                ),
                "confidence": "informational",
            })

    for reason in reasons:
        findings.append({
            "rule_id": "PROC_MONITOR_SIGNAL",
            "title": "Process monitor reported a signal",
            "severity": "medium",
            "reason": str(reason),
            "confidence": "low",
        })


    if not executable and not findings:
        findings.append({
            "rule_id": "PROC_PATH_UNAVAILABLE",
            "title": "Executable path unavailable",
            "severity": "info",
            "reason": (
                f"The executable path for {name} could not be obtained. "
                "This can occur for protected or system processes."
            ),
            "confidence": "informational",
        })

    elif executable:
        has_process_signal = any(
            finding["rule_id"] in {
                "PROC_WRITABLE_LOCATION",
                "PROC_MONITOR_SIGNAL",
            }
            for finding in findings
        )

        if not has_process_signal:
            findings.insert(0, {
                "rule_id": "PROC_OBSERVED",
                "title": "New process observed",
                "severity": "info",
                "reason": (
                    f"Observed {name} (PID {event.get('pid')}, "
                    f"parent PID {parent_pid}); "
                    "no configured suspicious indicators matched."
                ),
                "confidence": "informational",
            })


    return findings


def analyze_network(event: dict) -> list[dict]:
    process = str(event.get("process_name") or "unknown")
    remote_ip = str(event.get("remote_ip") or "unknown")
    remote_port = event.get("remote_port")
    status = str(event.get("status") or "UNKNOWN")
    protocol = str(event.get("protocol") or "TCP")

    return [{
        "rule_id": "NET_CONNECTION_OBSERVED",
        "title": "Network connection observed",
        "severity": "info",
        "reason": (
            f"{process} connected to {remote_ip}:{remote_port} "
            f"using {protocol}; state: {status}. "
            "This observation alone does not establish malicious activity."
        ),
        "confidence": "informational",
    }]

"""Risk scoring, multi-indicator correlation, deduplication, and process identity tracking."""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import time

from monitors.file_metadata import WRITABLE_DIRECTORY_NAMES


class ProcessIdentityTracker:
    """
    Tracks running processes by unambiguous composite identity (PID + creation timestamp),
    preventing PID reuse from confusing a newly launched process with a terminated one.
    """

    def __init__(self):
        # Maps process_identity -> process snapshot dict
        self.active_processes: dict[str, dict] = {}
        # Maps pid -> current active process_identity
        self.pid_to_identity: dict[int, str] = {}

    @staticmethod
    def get_identity(pid: int, create_time: float | str | None = None) -> str:
        """Create a composite unique process identity key."""
        ts_str = str(int(create_time)) if isinstance(create_time, (int, float)) else str(create_time or "0")
        return f"{pid}_{ts_str}"

    def register_process(self, proc: dict) -> str:
        """Register a process in the identity registry."""
        pid = proc.get("pid")
        if pid is None:
            return "0_0"
        create_time = proc.get("create_time") or proc.get("process_started_at")
        identity = self.get_identity(pid, create_time)

        # If PID was previously assigned to another identity, old process terminated
        old_identity = self.pid_to_identity.get(pid)
        if old_identity and old_identity != identity:
            self.active_processes.pop(old_identity, None)

        self.pid_to_identity[pid] = identity
        self.active_processes[identity] = proc
        return identity

    def unregister_process(self, pid: int, create_time: float | str | None = None) -> None:
        """Remove a terminated process from the identity registry."""
        identity = self.get_identity(pid, create_time) if create_time else self.pid_to_identity.get(pid)
        if identity:
            self.active_processes.pop(identity, None)
            if self.pid_to_identity.get(pid) == identity:
                self.pid_to_identity.pop(pid, None)

    def get_process_by_pid(self, pid: int) -> dict | None:
        """Retrieve the currently active process associated with a PID."""
        identity = self.pid_to_identity.get(pid)
        return self.active_processes.get(identity) if identity else None


class EventDeduplicator:
    """
    Suppresses redundant alerts for identical observations within a configurable cooldown window,
    mitigating alert fatigue.
    """

    def __init__(self, cooldown_seconds: float = 60.0):
        self.cooldown_seconds = cooldown_seconds
        # Maps fingerprint -> last_alerted_time
        self.seen_signatures: dict[str, float] = {}
        # Maps fingerprint -> count of suppressed duplicates
        self.suppressed_counts: dict[str, int] = defaultdict(int)

    @staticmethod
    def fingerprint_finding(event: dict, finding: dict) -> str:
        """Generate a deterministic fingerprint for an event finding."""
        elements = [
            event.get("event_type", ""),
            str(event.get("pid") or ""),
            str(event.get("process_name") or event.get("domain") or ""),
            str(finding.get("rule_id", "")),
            str(event.get("remote_ip") or ""),
            str(event.get("remote_port") or ""),
            str(event.get("command") or event.get("task_name") or ""),
        ]
        raw = "|".join(elements)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def filter_findings(
        self,
        event: dict,
        findings: list[dict],
        current_time: float | None = None,
    ) -> tuple[list[dict], int]:
        """
        Filter out findings that have already been alerted within the cooldown window.
        Returns:
            (active_findings, total_suppressed_count)
        """
        now = time.time() if current_time is None else current_time
        active_findings = []
        suppressed_in_call = 0

        for finding in findings:
            fp = self.fingerprint_finding(event, finding)
            last_time = self.seen_signatures.get(fp)

            if last_time is not None and (now - last_time) < self.cooldown_seconds:
                self.suppressed_counts[fp] += 1
                suppressed_in_call += 1
            else:
                self.seen_signatures[fp] = now
                active_findings.append(finding)

        # Periodic cleanup of expired entries (older than 10x cooldown)
        if len(self.seen_signatures) > 1000:
            threshold = now - (self.cooldown_seconds * 10)
            self.seen_signatures = {
                k: v for k, v in self.seen_signatures.items() if v > threshold
            }

        return active_findings, suppressed_in_call

    def reset(self) -> None:
        """Clear all deduplication records."""
        self.seen_signatures.clear()
        self.suppressed_counts.clear()


def correlate_process_and_network(conn_event: dict) -> list[dict]:
    """
    Correlate network socket activity with owning process attributes
    to identify compound multi-indicator risks.
    """
    correlated_findings = []
    process_name = str(conn_event.get("process_name") or "").lower()
    executable = str(conn_event.get("executable") or "")
    remote_ip = str(conn_event.get("remote_ip") or "")
    remote_port = conn_event.get("remote_port")
    is_public = conn_event.get("is_public_ip", False)
    is_suspicious_client = conn_event.get("is_suspicious_client", False)
    threat_flagged = conn_event.get("threat_flagged", False)

    # 1. Suspicious client process connecting to confirmed malicious IP
    if threat_flagged and (is_suspicious_client or any(d in executable.lower() for d in WRITABLE_DIRECTORY_NAMES)):
        correlated_findings.append({
            "rule_id": "CORR_SUSPICIOUS_PROC_MALICIOUS_IP",
            "title": "Suspicious process communicating with threat-flagged IP",
            "severity": "critical",
            "confidence": "high",
            "evidence": {
                "process_name": process_name,
                "executable": executable,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "threat_details": conn_event.get("threat_details"),
            },
            "reason": (
                f"Process {process_name} running from '{executable}' connected to confirmed "
                f"malicious infrastructure {remote_ip}:{remote_port}. Multiple high-confidence risk vectors matched."
            ),
            "explanation": (
                f"Process {process_name} running from '{executable}' connected to confirmed "
                f"malicious infrastructure {remote_ip}:{remote_port}."
            ),
        })

    # 2. Executable in user-writable location establishing outbound public connection
    is_writable_exec = any(f"\\{d}\\" in executable.lower() or f"/{d}/" in executable.lower() for d in WRITABLE_DIRECTORY_NAMES)
    if is_writable_exec and is_public:
        correlated_findings.append({
            "rule_id": "CORR_WRITABLE_EXEC_OUTBOUND",
            "title": "Executable in user-writable directory established outbound internet connection",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "process_name": process_name,
                "executable": executable,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
            },
            "reason": (
                f"Executable {process_name} located in user-writable directory ({executable}) "
                f"connected to external public IP {remote_ip}:{remote_port}. "
                "Executables running from Temp, Downloads, or AppData communicating over the internet warrant investigation."
            ),
            "explanation": (
                f"Executable {process_name} located in user-writable directory ({executable}) "
                f"connected to external public IP {remote_ip}:{remote_port}."
            ),
        })

    # 3. Command interpreter or shell communicating externally
    if is_suspicious_client and is_public and not any(f["rule_id"] == "CORR_SUSPICIOUS_PROC_MALICIOUS_IP" for f in correlated_findings):
        correlated_findings.append({
            "rule_id": "CORR_SHELL_INTERNET_COMMUNICATION",
            "title": "Command interpreter established external internet communication",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "process_name": process_name,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
            },
            "reason": (
                f"Command shell {process_name} established an outbound internet connection to {remote_ip}:{remote_port}. "
                "Direct internet sockets from shells are characteristic of reverse shells and staged downloads."
            ),
            "explanation": (
                f"Command shell {process_name} established an outbound internet connection to {remote_ip}:{remote_port}."
            ),
        })

    return correlated_findings


# Shared default instances
global_process_tracker = ProcessIdentityTracker()
global_deduplicator = EventDeduplicator(cooldown_seconds=60.0)


class DownloadTracker:
    """
    Tracks downloaded files and correlates subsequent process creations,
    network connections, and persistence modifications with their download origins.
    """

    def __init__(self):
        # Maps canonical path -> download info
        self.downloads_by_path: dict[str, dict] = {}
        # Maps sha256 -> download info
        self.downloads_by_hash: dict[str, dict] = {}
        # Maps pid -> download info of the binary that spawned it
        self.active_download_pids: dict[int, dict] = {}

    def register_download(self, download_event: dict) -> None:
        """Register an observed downloaded file."""
        file_path = download_event.get("file_path") or download_event.get("executable")
        meta = download_event.get("file_metadata") or {}
        sha256 = download_event.get("sha256") or meta.get("sha256")

        entry = {
            "file_path": str(file_path).lower() if file_path else "",
            "filename": download_event.get("filename", ""),
            "sha256": (sha256 or "").lower(),
            "timestamp": download_event.get("timestamp"),
            "download_url": download_event.get("download_url"),
            "referrer_url": download_event.get("referrer_url"),
            "mark_of_the_web": download_event.get("mark_of_the_web", False),
            "zone_id": download_event.get("zone_id"),
        }

        if entry["file_path"]:
            self.downloads_by_path[entry["file_path"]] = entry
        if entry["sha256"]:
            self.downloads_by_hash[entry["sha256"]] = entry

    def is_downloaded(
        self, path: str | None = None, sha256: str | None = None
    ) -> dict | None:
        """Check if a path or hash corresponds to a known downloaded file."""
        if path:
            norm_path = str(path).lower()
            if norm_path in self.downloads_by_path:
                return self.downloads_by_path[norm_path]
        if sha256:
            norm_hash = str(sha256).lower()
            if norm_hash in self.downloads_by_hash:
                return self.downloads_by_hash[norm_hash]
        return None

    def correlate_process_execution(self, process_event: dict) -> list[dict]:
        """Check if a newly started process was spawned from a downloaded file."""
        exe = process_event.get("executable")
        meta = process_event.get("file_metadata") or {}
        sha256 = meta.get("sha256")
        download_info = self.is_downloaded(path=exe, sha256=sha256)

        findings: list[dict] = []
        pid = process_event.get("pid")

        if download_info:
            if pid:
                self.active_download_pids[pid] = download_info

            findings.append({
                "rule_id": "CORR_DOWNLOAD_PROCESS_EXECUTION",
                "title": "Execution of recently downloaded file",
                "severity": "medium",
                "confidence": "high",
                "evidence": {
                    "process_name": process_event.get("process_name"),
                    "pid": pid,
                    "download_path": download_info.get("file_path"),
                    "download_url": download_info.get("download_url"),
                    "mark_of_the_web": download_info.get("mark_of_the_web"),
                },
                "reason": (
                    f"Process '{process_event.get('process_name')}' (PID: {pid}) was launched from "
                    f"recently downloaded file '{download_info.get('file_path')}'. "
                    f"Origin: {download_info.get('download_url') or 'Internet download'}."
                ),
                "explanation": (
                    f"Process '{process_event.get('process_name')}' was launched from a recently downloaded file."
                ),
            })
        return findings

    def correlate_network_activity(self, network_event: dict) -> list[dict]:
        """Check if network socket belongs to a process spawned from a downloaded file."""
        pid = network_event.get("pid")
        download_info = self.active_download_pids.get(pid)
        if not download_info:
            return []

        remote_ip = network_event.get("remote_ip", "")
        remote_port = network_event.get("remote_port", "")
        proc_name = network_event.get("process_name", "unknown")

        return [{
            "rule_id": "CORR_DOWNLOAD_OUTBOUND_CONN",
            "title": "Downloaded binary established outbound network connection",
            "severity": (
                "high"
                if network_event.get("threat_flagged") or network_event.get("is_foreign")
                else "medium"
            ),
            "confidence": "high",
            "evidence": {
                "process_name": proc_name,
                "pid": pid,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "download_url": download_info.get("download_url"),
            },
            "reason": (
                f"Process '{proc_name}' (PID: {pid}), originating from downloaded file "
                f"'{download_info.get('file_path')}', initiated an outbound connection to {remote_ip}:{remote_port}."
            ),
            "explanation": (
                f"Downloaded binary '{proc_name}' initiated an outbound connection to {remote_ip}:{remote_port}."
            ),
        }]

    def correlate_persistence_activity(self, event: dict) -> list[dict]:
        """Check if startup/task/service modification references a downloaded file."""
        cmd = (
            event.get("command")
            or event.get("task_to_run")
            or event.get("binpath")
            or ""
        )
        cmd_lower = cmd.lower()

        matched_download = None
        for path, info in self.downloads_by_path.items():
            if path in cmd_lower or (
                info.get("filename") and info["filename"].lower() in cmd_lower
            ):
                matched_download = info
                break

        if matched_download:
            return [{
                "rule_id": "CORR_DOWNLOAD_PERSISTENCE",
                "title": "Downloaded binary established startup persistence",
                "severity": "high",
                "confidence": "high",
                "evidence": {
                    "event_type": event.get("event_type"),
                    "command": cmd,
                    "download_path": matched_download.get("file_path"),
                },
                "reason": (
                    f"Downloaded binary '{matched_download.get('file_path')}' was registered "
                    f"for persistence: {cmd}."
                ),
                "explanation": (
                    "Downloaded binary was registered for startup persistence."
                ),
            }]
        return []

    def unregister_process(self, pid: int) -> None:
        """Clear PID mapping when process terminates."""
        self.active_download_pids.pop(pid, None)


global_download_tracker = DownloadTracker()


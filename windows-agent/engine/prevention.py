"""Prevention engine for automated threat mitigation (process termination and file quarantine)."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import shutil
import uuid

import psutil

from config import PREVENTION_ENABLED, PREVENTION_MODE, PREVENTION_MIN_SCORE, QUARANTINE_DIR
from engine.reputation import CORE_SYSTEM_PROCESSES

logger = logging.getLogger("phishguard.prevention")

# Critical Windows system processes that must NEVER be terminated
PROTECTED_PROCESS_NAMES = CORE_SYSTEM_PROCESSES | {
    "explorer.exe",
    "system",
    "idle",
    "registry",
    "fontdrvhost.exe",
    "dwm.exe",
}

CRITICAL_PIDS = {0, 4}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PreventionPolicy:
    """Configurable prevention policy parameters."""

    def __init__(
        self,
        enabled: bool = PREVENTION_ENABLED,
        mode: str = PREVENTION_MODE,
        min_risk_score: int = PREVENTION_MIN_SCORE,
        quarantine_dir: str | Path = QUARANTINE_DIR,
    ):
        self.enabled = enabled
        self.mode = mode.lower()  # "alert_only", "quarantine_file", "terminate_process", "quarantine_and_terminate"
        self.min_risk_score = max(0, min(100, int(min_risk_score)))
        self.quarantine_dir = Path(quarantine_dir)


def terminate_process(pid: int, reason: str = "") -> dict:
    """
    Safely terminate a malicious process tree.
    Enforces strict safeguards to prevent terminating core Windows system processes.
    """
    if pid in CRITICAL_PIDS:
        return {
            "success": False,
            "pid": pid,
            "action": "terminate_process",
            "error": f"Refusing to terminate critical system PID {pid}",
        }

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()

        if proc_name in PROTECTED_PROCESS_NAMES:
            return {
                "success": False,
                "pid": pid,
                "action": "terminate_process",
                "error": f"Refusing to terminate protected system process '{proc_name}'",
            }

        # Terminate child processes first
        children = proc.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        proc.kill()
        logger.warning(
            "PREVENTION: Terminated malicious process '%s' (PID %d). Reason: %s",
            proc_name,
            pid,
            reason,
        )
        return {
            "success": True,
            "pid": pid,
            "process_name": proc_name,
            "action": "terminate_process",
            "reason": reason,
            "children_terminated": len(children),
        }

    except psutil.NoSuchProcess:
        return {
            "success": False,
            "pid": pid,
            "action": "terminate_process",
            "error": "Process not found (already exited)",
        }
    except psutil.AccessDenied as exc:
        return {
            "success": False,
            "pid": pid,
            "action": "terminate_process",
            "error": f"Access denied: {exc}",
        }
    except Exception as exc:
        return {
            "success": False,
            "pid": pid,
            "action": "terminate_process",
            "error": str(exc),
        }


def quarantine_file(
    file_path: str | Path,
    sha256: str | None = None,
    reason: str = "",
    quarantine_dir: str | Path = QUARANTINE_DIR,
) -> dict:
    """
    Quarantine a malicious file by moving it into a secure vault directory
    and appending .locked extension with an accompanying metadata manifest.
    """
    src = Path(file_path).resolve()
    if not src.is_file():
        return {
            "success": False,
            "action": "quarantine_file",
            "error": f"Source file does not exist: {src}",
        }

    # Safety check: Never quarantine files in System32 directly
    parts = {p.lower() for p in src.parts}
    if "system32" in parts or "syswow64" in parts:
        return {
            "success": False,
            "action": "quarantine_file",
            "error": "Refusing to quarantine Windows system directory file",
        }

    q_dir = Path(quarantine_dir)
    q_dir.mkdir(parents=True, exist_ok=True)

    quarantine_id = str(uuid.uuid4())
    hash_prefix = (sha256[:16] if sha256 else "") or quarantine_id[:16]
    quarantined_name = f"{hash_prefix}_{src.name}.locked"
    dst = q_dir / quarantined_name
    manifest_file = q_dir / f"{quarantine_id}.manifest.json"

    try:
        shutil.move(str(src), str(dst))

        manifest = {
            "quarantine_id": quarantine_id,
            "timestamp": utc_now(),
            "original_path": str(src),
            "quarantined_path": str(dst),
            "sha256": sha256,
            "reason": reason,
        }
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        logger.warning(
            "PREVENTION: Quarantined file '%s' -> '%s'. Reason: %s",
            src,
            dst,
            reason,
        )
        return {
            "success": True,
            "action": "quarantine_file",
            "quarantine_id": quarantine_id,
            "original_path": str(src),
            "quarantined_path": str(dst),
            "reason": reason,
        }
    except Exception as exc:
        return {
            "success": False,
            "action": "quarantine_file",
            "error": str(exc),
        }


def restore_quarantined_file(
    quarantine_id: str,
    destination: str | Path | None = None,
    quarantine_dir: str | Path = QUARANTINE_DIR,
) -> dict:
    """Restore a quarantined file to its original location or designated path."""
    q_dir = Path(quarantine_dir)
    manifest_file = q_dir / f"{quarantine_id}.manifest.json"

    if not manifest_file.exists():
        return {"success": False, "error": f"Manifest not found for ID {quarantine_id}"}

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        locked_path = Path(manifest["quarantined_path"])
        dest_path = Path(destination) if destination else Path(manifest["original_path"])

        if not locked_path.exists():
            return {"success": False, "error": f"Quarantined file missing: {locked_path}"}

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(locked_path), str(dest_path))
        manifest_file.unlink(missing_ok=True)

        return {
            "success": True,
            "quarantine_id": quarantine_id,
            "restored_path": str(dest_path),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def apply_prevention(
    assessment: dict,
    target_event: dict,
    policy: PreventionPolicy | None = None,
) -> dict:
    """
    Decide whether prevention is justified based on risk score and evidence,
    and apply configured prevention actions (process termination, file quarantine).
    """
    active_policy = policy or PreventionPolicy()

    if not active_policy.enabled:
        return {
            "justified": False,
            "prevented": False,
            "reason": "Prevention disabled by policy configuration",
        }

    score = int(assessment.get("score", 0))
    severity = assessment.get("severity", "info")
    findings = target_event.get("findings") or []

    # Check if high/critical or contains blocklist hit
    has_critical_finding = any(
        f.get("severity") == "critical" or "BLOCKLIST" in f.get("rule_id", "")
        for f in findings
    )

    is_justified = score >= active_policy.min_risk_score or has_critical_finding

    if not is_justified:
        return {
            "justified": False,
            "prevented": False,
            "score": score,
            "threshold": active_policy.min_risk_score,
            "reason": f"Risk score ({score}) below prevention threshold ({active_policy.min_risk_score})",
        }

    if active_policy.mode == "alert_only":
        return {
            "justified": True,
            "prevented": False,
            "mode": "alert_only",
            "reason": "Prevention justified but policy mode set to alert_only",
        }

    actions_taken = []
    pid = target_event.get("pid")
    file_path = (
        target_event.get("file_path")
        or target_event.get("executable")
        or (target_event.get("file_metadata") or {}).get("path")
    )
    sha256 = target_event.get("sha256") or (target_event.get("file_metadata") or {}).get("sha256")

    # 1. Terminate running process
    if "terminate" in active_policy.mode and pid:
        term_res = terminate_process(
            pid, reason=assessment.get("summary", "Malicious activity detected")
        )
        actions_taken.append(term_res)

    # 2. Quarantine executable
    if "quarantine" in active_policy.mode and file_path and Path(file_path).exists():
        quar_res = quarantine_file(
            file_path,
            sha256=sha256,
            reason=assessment.get("summary", "Malicious file detected"),
            quarantine_dir=active_policy.quarantine_dir,
        )
        actions_taken.append(quar_res)

    any_success = any(a.get("success") for a in actions_taken)

    return {
        "justified": True,
        "prevented": any_success,
        "score": score,
        "severity": severity,
        "actions_taken": actions_taken,
        "reason": f"High risk threat detected (Score: {score}/100, Severity: {severity.upper()})",
    }


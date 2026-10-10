"""Unified Threat Detection Engine coordinating rules, correlation, reputation, and explainable findings."""

from engine.correlation import (
    EventDeduplicator,
    ProcessIdentityTracker,
    correlate_process_and_network,
    global_deduplicator,
    global_process_tracker,
)
from engine.reputation import ThreatReputationManager, reputation_manager
from engine.rules import (
    analyze_process,
    analyze_network,
    analyze_dns,
    analyze_persistence,
    analyze_scheduled_task,
    analyze_service,
    analyze_download,
)
from engine.scoring import score_findings
from monitors.file_metadata import inspect_file_metadata
from monitors.signatures import inspect_signature


class ThreatDetectionEngine:
    """
    Evaluates system and network evidence against configurable security rules,
    reputation sources, allowlists, and blocklists to produce explainable security findings.
    """

    def __init__(
        self,
        rep_manager: ThreatReputationManager | None = None,
        deduplicator: EventDeduplicator | None = None,
        process_tracker: ProcessIdentityTracker | None = None,
    ):
        self.reputation = rep_manager or reputation_manager
        self.deduplicator = deduplicator or global_deduplicator
        self.process_tracker = process_tracker or global_process_tracker

    def evaluate_event(
        self,
        event: dict,
        deduplicate: bool = False,
        current_time: float | None = None,
    ) -> dict:
        """
        Evaluate any collected event and generate explainable findings and risk score.
        Supports multi-indicator correlation and optional duplicate alert filtering.
        """
        event_type = event.get("event_type", "unknown")
        findings = []

        # Process lifecycle tracking
        if event_type in ("process_started", "process_observed"):
            self.process_tracker.register_process(event)
            findings = analyze_process(event)
        elif event_type == "process_terminated":
            self.process_tracker.unregister_process(
                event.get("pid", 0),
                event.get("create_time"),
            )
            findings = analyze_process(event)
        elif event_type == "network_connection_observed":
            findings = analyze_network(event)
            # Process and Network Correlation
            correlated = correlate_process_and_network(event)
            findings.extend(correlated)
        elif event_type == "dns_query_observed":
            findings = analyze_dns(event)
        elif event_type in ("startup_item_added", "startup_item_modified", "startup_item_removed"):
            findings = analyze_persistence(event)
        elif event_type in ("scheduled_task_created", "scheduled_task_modified", "scheduled_task_deleted"):
            findings = analyze_scheduled_task(event)
        elif event_type in ("service_installed", "service_modified", "service_removed"):
            findings = analyze_service(event)
        elif event_type == "file_download_observed":
            findings = analyze_download(event)
        else:
            findings = [{
                "rule_id": "GENERIC_EVENT_OBSERVED",
                "title": "System event observed",
                "severity": "info",
                "confidence": "informational",
                "evidence": {"event_type": event_type},
                "reason": f"Event of type '{event_type}' observed.",
                "explanation": f"Event of type '{event_type}' observed.",
            }]

        suppressed_count = 0
        if deduplicate:
            findings, suppressed_count = self.deduplicator.filter_findings(
                event, findings, current_time=current_time
            )

        assessment = score_findings(findings)

        return {
            "event_type": event_type,
            "timestamp": event.get("timestamp"),
            "target": (
                event.get("process_name")
                or event.get("filename")
                or event.get("domain")
                or event.get("name")
                or event.get("task_name")
                or event.get("service_name")
                or "unknown"
            ),
            "findings": findings,
            "assessment": assessment,
            "score": assessment.get("score", 0),
            "severity": assessment.get("severity", "info"),
            "summary": assessment.get("summary", ""),
            "has_threats": assessment.get("score", 0) >= 35,
            "suppressed_duplicates": suppressed_count,
        }

    def evaluate_file(self, file_path: str) -> dict:
        """
        On-demand threat inspection of an executable file on disk.
        Evaluates file metadata, SHA-256 hash reputation, Authenticode signature, and name heuristics.
        """
        metadata = inspect_file_metadata(file_path)
        sig = inspect_signature(file_path) if metadata.get("exists") else {"status": "unavailable", "signer": None}

        synthetic_event = {
            "event_type": "process_observed",
            "process_name": metadata.get("filename") or "unknown",
            "executable": file_path,
            "file_metadata": metadata,
            "signature": sig,
            "command_line": None,
            "parent_name": None,
            "parent_pid": None,
        }

        return self.evaluate_event(synthetic_event)


# Global default engine instance
threat_engine = ThreatDetectionEngine()

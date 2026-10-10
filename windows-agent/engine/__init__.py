"""Threat Detection Engine package."""

from engine.scoring import score_findings, classify_severity
from engine.reputation import (
    ThreatReputationManager,
    reputation_manager,
    DEFAULT_TRUSTED_PUBLISHERS,
    DEFAULT_BLOCKLIST_HASHES,
    DEFAULT_BLOCKLIST_IPS,
    DEFAULT_BLOCKLIST_DOMAINS,
)
from engine.rules import (
    analyze_process,
    analyze_network,
    analyze_dns,
    analyze_persistence,
    analyze_scheduled_task,
    analyze_service,
    analyze_download,
    make_finding,
)
from engine.correlation import (
    ProcessIdentityTracker,
    EventDeduplicator,
    DownloadTracker,
    correlate_process_and_network,
    global_deduplicator,
    global_process_tracker,
    global_download_tracker,
)
from engine.threat_detector import ThreatDetectionEngine, threat_engine
from engine.prevention import (
    PreventionPolicy,
    terminate_process,
    quarantine_file,
    restore_quarantined_file,
    apply_prevention,
)
from engine.download_pipeline import (
    FileDownloadThreatPipeline,
    download_pipeline,
)

__all__ = [
    "ThreatDetectionEngine",
    "threat_engine",
    "ThreatReputationManager",
    "reputation_manager",
    "score_findings",
    "classify_severity",
    "analyze_process",
    "analyze_network",
    "analyze_dns",
    "analyze_persistence",
    "analyze_scheduled_task",
    "analyze_service",
    "analyze_download",
    "make_finding",
    "ProcessIdentityTracker",
    "EventDeduplicator",
    "DownloadTracker",
    "correlate_process_and_network",
    "global_deduplicator",
    "global_process_tracker",
    "global_download_tracker",
    "PreventionPolicy",
    "terminate_process",
    "quarantine_file",
    "restore_quarantined_file",
    "apply_prevention",
    "FileDownloadThreatPipeline",
    "download_pipeline",
    "DEFAULT_TRUSTED_PUBLISHERS",
    "DEFAULT_BLOCKLIST_HASHES",
    "DEFAULT_BLOCKLIST_IPS",
    "DEFAULT_BLOCKLIST_DOMAINS",
]

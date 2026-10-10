"""End-to-end file download threat detection and response pipeline.

Implements the exact lifecycle:
1. User downloads a file -> Agent observes it
2. Collect file information (SHA-256 hash, digital signature, file location, Mark-of-the-Web)
3. Analyze available evidence (local detection rules, file reputation, threat intelligence)
4. Monitor process behavior (process creation, network connections, startup modifications)
5. Calculate compound risk score (0-100)
6. Decision branch:
   - LOW RISK: Allow normal activity
   - HIGH RISK: Generate explainable alert + apply prevention if justified
"""

from collections.abc import Callable
import logging
from pathlib import Path
from typing import Any

from config import (
    DATABASE_PATH,
    PREVENTION_ENABLED,
    PREVENTION_MODE,
    PREVENTION_MIN_SCORE,
    QUARANTINE_DIR,
)
from engine.correlation import DownloadTracker, global_download_tracker
from engine.prevention import PreventionPolicy, apply_prevention
from engine.reputation import ThreatReputationManager, reputation_manager
from engine.rules import analyze_download, analyze_process, analyze_network, analyze_persistence
from engine.scoring import score_findings
from monitors.downloads import inspect_downloaded_file
from storage.events import save_event

logger = logging.getLogger("phishguard.pipeline")


class FileDownloadThreatPipeline:
    """
    End-to-end download threat analysis and mitigation pipeline.
    """

    def __init__(
        self,
        download_tracker: DownloadTracker | None = None,
        rep_manager: ThreatReputationManager | None = None,
        policy: PreventionPolicy | None = None,
        db_path: str | Path = DATABASE_PATH,
    ):
        self.download_tracker = download_tracker or global_download_tracker
        self.reputation_manager = rep_manager or reputation_manager
        self.policy = policy or PreventionPolicy(
            enabled=PREVENTION_ENABLED,
            mode=PREVENTION_MODE,
            min_risk_score=PREVENTION_MIN_SCORE,
            quarantine_dir=QUARANTINE_DIR,
        )
        self.db_path = db_path

    def process_download(
        self,
        file_path: str | Path,
        process_event: dict | None = None,
        network_events: list[dict] | None = None,
        persistence_events: list[dict] | None = None,
        auto_remediate: bool = True,
    ) -> dict:
        """
        Execute the full download threat workflow.
        """
        # ---------------------------------------------------------
        # STAGE 1 & 2: OBSERVE FILE & COLLECT FILE INFORMATION
        # ---------------------------------------------------------
        file_event = inspect_downloaded_file(file_path)
        self.download_tracker.register_download(file_event)

        logger.debug(
            "Observed download: %s | SHA256: %s | MotW: %s",
            file_event["filename"],
            file_event["sha256"],
            file_event["mark_of_the_web"],
        )

        # ---------------------------------------------------------
        # STAGE 3: ANALYZE AVAILABLE EVIDENCE (Rules, Reputation, Intel)
        # ---------------------------------------------------------
        evidence_findings = analyze_download(file_event)
        all_findings = list(evidence_findings)

        # ---------------------------------------------------------
        # STAGE 4: MONITOR PROCESS BEHAVIOR (Execution, Network, Persistence)
        # ---------------------------------------------------------
        behavioral_findings: list[dict] = []
        if process_event:
            # Correlate process launch with download
            proc_corr = self.download_tracker.correlate_process_execution(process_event)
            proc_rules = analyze_process(process_event)
            behavioral_findings.extend(proc_corr)
            behavioral_findings.extend(proc_rules)

        if network_events:
            for net_event in network_events:
                net_corr = self.download_tracker.correlate_network_activity(net_event)
                net_rules = analyze_network(net_event)
                behavioral_findings.extend(net_corr)
                behavioral_findings.extend(net_rules)

        if persistence_events:
            for p_event in persistence_events:
                persist_corr = self.download_tracker.correlate_persistence_activity(p_event)
                persist_rules = analyze_persistence(p_event)
                behavioral_findings.extend(persist_corr)
                behavioral_findings.extend(persist_rules)

        all_findings.extend(behavioral_findings)

        # ---------------------------------------------------------
        # STAGE 5: CALCULATE RISK SCORE (0 - 100)
        # ---------------------------------------------------------
        assessment = score_findings(all_findings)
        score = int(assessment.get("score", 0))
        severity = assessment.get("severity", "info")
        file_event["findings"] = all_findings

        # ---------------------------------------------------------
        # STAGE 6: DECISION BRANCH (LOW RISK vs HIGH RISK)
        # ---------------------------------------------------------
        is_high_risk = score >= 50 or severity in ("high", "critical")
        prevention_result: dict = {
            "justified": False,
            "prevented": False,
            "actions_taken": [],
            "reason": "Not applied",
        }

        if not is_high_risk:
            # BRANCH A: LOW RISK -> Allow normal activity
            decision = "LOW_RISK"
            action = "ALLOW_NORMAL_ACTIVITY"
            event_id = save_event(
                file_event,
                all_findings,
                assessment,
                db_path=self.db_path,
                deduplicate=True,
            )
            logger.info(
                "[LOW RISK] Allowed file '%s' (Score: %d/100, Event #%d)",
                file_event["filename"],
                score,
                event_id,
            )
        else:
            # BRANCH B: HIGH RISK -> Generate alert & apply prevention if justified
            decision = "HIGH_RISK"
            action = "GENERATE_ALERT"

            # Apply prevention if justified
            if auto_remediate and self.policy.enabled:
                prevention_result = apply_prevention(
                    assessment,
                    file_event,
                    policy=self.policy,
                )
                if prevention_result.get("prevented"):
                    action = "ALERT_AND_PREVENTION_APPLIED"

            event_id = save_event(
                file_event,
                all_findings,
                assessment,
                db_path=self.db_path,
                deduplicate=True,
            )

            logger.warning(
                "[HIGH RISK] Alert generated for '%s' (Score: %d/100, Action: %s, Event #%d)",
                file_event["filename"],
                score,
                action,
                event_id,
            )

        return {
            "status": "success",
            "file_path": file_event["file_path"],
            "filename": file_event["filename"],
            "sha256": file_event["sha256"],
            "mark_of_the_web": file_event["mark_of_the_web"],
            "download_url": file_event["download_url"],
            "score": score,
            "severity": severity,
            "decision": decision,
            "action": action,
            "summary": assessment.get("summary", ""),
            "findings": all_findings,
            "evidence_count": len(all_findings),
            "prevention": prevention_result,
            "event_id": event_id,
        }


# Global default pipeline instance
download_pipeline = FileDownloadThreatPipeline()


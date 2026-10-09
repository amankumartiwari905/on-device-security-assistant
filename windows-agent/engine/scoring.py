"""Transparent heuristic scoring for process findings."""


SEVERITY_POINTS = {
    "info": 0,
    "low": 15,
    "medium": 35,
    "high": 60,
    "critical": 85,
}


def score_findings(findings: list[dict]) -> dict:
    if not findings:
        return {
            "score": 0,
            "severity": "info",
            "summary": "No findings were produced.",
        }

    # Avoid inflating risk by simply adding duplicate findings.
    points = [SEVERITY_POINTS.get(item.get("severity", "info"), 0)
              for item in findings]
    score = min(100, max(points, default=0))

    if score >= 85:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score >= 15:
        severity = "low"
    else:
        severity = "info"

    return {
        "score": score,
        "severity": severity,
        "summary": f"{len(findings)} finding(s); highest rule-based score is {score}/100.",
    }

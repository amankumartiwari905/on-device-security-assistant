"""Multi-indicator risk scoring and severity classification."""

SEVERITY_POINTS = {
    "info": 0,
    "low": 15,
    "medium": 35,
    "high": 60,
    "critical": 85,
}

SEVERITY_THRESHOLDS = [
    (85, "critical"),
    (60, "high"),
    (35, "medium"),
    (15, "low"),
    (0, "info"),
]


def classify_severity(score: int) -> str:
    """Classify a numeric score (0-100) into a severity category."""
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "info"


def score_findings(findings: list[dict]) -> dict:
    """
    Combine security findings and calculate a transparent risk score (0-100),
    incorporating multi-indicator compound evidence.
    """
    if not findings:
        return {
            "score": 0,
            "severity": "info",
            "summary": "No findings were produced.",
            "finding_count": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    points = [
        SEVERITY_POINTS.get(item.get("severity", "info"), 0)
        for item in findings
    ]
    sorted_points = sorted(points, reverse=True)
    base_score = sorted_points[0] if sorted_points else 0

    # Multi-indicator correlation compound scoring:
    # Multiple distinct non-informational signals amplify the composite risk score
    compound_bonus = 0
    if len(sorted_points) > 1:
        for p in sorted_points[1:]:
            if p > 0:
                compound_bonus += int(p * 0.25)

    final_score = min(100, max(0, base_score + compound_bonus))
    severity = classify_severity(final_score)

    critical_count = sum(1 for item in findings if item.get("severity") == "critical")
    high_count = sum(1 for item in findings if item.get("severity") == "high")
    medium_count = sum(1 for item in findings if item.get("severity") == "medium")
    low_count = sum(1 for item in findings if item.get("severity") == "low")
    info_count = sum(1 for item in findings if item.get("severity") == "info")

    summary_parts = []
    if critical_count:
        summary_parts.append(f"{critical_count} critical")
    if high_count:
        summary_parts.append(f"{high_count} high")
    if medium_count:
        summary_parts.append(f"{medium_count} medium")
    if low_count:
        summary_parts.append(f"{low_count} low")

    if summary_parts:
        summary = f"{len(findings)} finding(s) ({', '.join(summary_parts)}); composite score is {final_score}/100."
    else:
        summary = f"{len(findings)} informational finding(s); highest rule-based score is {final_score}/100."

    return {
        "score": final_score,
        "severity": severity,
        "summary": summary,
        "finding_count": len(findings),
        "severity_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        },
    }

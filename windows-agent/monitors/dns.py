"""DNS cache observation and suspicious domain analysis for Windows."""

import collections
from datetime import datetime, timezone
import math
import re
import subprocess


DYNAMIC_DNS_DOMAINS = {
    "duckdns.org",
    "no-ip.com",
    "no-ip.biz",
    "no-ip.org",
    "hopto.org",
    "zapto.org",
    "ddns.net",
    "ngrok.io",
    "ngrok-free.app",
    "serveo.net",
    "localtunnel.me",
    "pagekite.me",
    "sytes.net",
    "myftp.org",
    "myvnc.com",
    "bounceme.net",
}

SUSPICIOUS_TLDS = {
    ".top",
    ".xyz",
    ".buzz",
    ".click",
    ".club",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".work",
    ".rest",
    ".cam",
    ".gdn",
    ".loan",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


def analyze_domain(domain: str) -> dict:
    """
    Analyze domain name for suspicious characteristics (Dynamic DNS, high-entropy DGA, suspicious TLDs).
    """
    cleaned = domain.strip().rstrip(".").lower()
    if not cleaned:
        return {
            "domain": "",
            "is_dynamic_dns": False,
            "is_suspicious_tld": False,
            "is_potential_dga": False,
            "entropy": 0.0,
            "indicators": [],
        }

    indicators = []

    # 1. Dynamic DNS detection
    is_dynamic_dns = any(
        cleaned == ddns or cleaned.endswith(f".{ddns}")
        for ddns in DYNAMIC_DNS_DOMAINS
    )
    if is_dynamic_dns:
        indicators.append("Dynamic DNS domain service")

    # 2. Suspicious TLD check
    is_suspicious_tld = any(
        cleaned.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )
    if is_suspicious_tld:
        indicators.append("Domain uses high-abuse / high-spam TLD")

    # 3. Shannon Entropy / DGA calculation on primary label
    parts = cleaned.split(".")
    primary_label = parts[0] if parts else cleaned
    entropy = round(calculate_entropy(primary_label), 3)

    is_potential_dga = False
    # If the primary label is sufficiently long and exhibits very high entropy or lack of vowels
    if len(primary_label) >= 12:
        vowel_count = sum(1 for c in primary_label if c in "aeiou")
        vowel_ratio = vowel_count / len(primary_label)
        has_digits_and_letters = (
            any(c.isdigit() for c in primary_label)
            and any(c.isalpha() for c in primary_label)
        )

        if entropy >= 3.6 or (vowel_ratio < 0.15 and has_digits_and_letters):
            is_potential_dga = True
            indicators.append(f"High-entropy / possible DGA label (entropy {entropy})")

    # 4. Punycode check
    if "xn--" in cleaned:
        indicators.append("Internationalized / Punycode domain")

    return {
        "domain": cleaned,
        "is_dynamic_dns": is_dynamic_dns,
        "is_suspicious_tld": is_suspicious_tld,
        "is_potential_dga": is_potential_dga,
        "entropy": entropy,
        "indicators": indicators,
    }


def parse_displaydns_output(text: str) -> dict[str, dict]:
    """Parse output from ipconfig /displaydns into structured domain records."""
    records = {}
    current_name = None

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("---") or line.startswith("Windows IP Configuration"):
            continue

        if ":" in line:
            parts = [p.strip() for p in line.split(":", 1)]
            key = parts[0]
            val = parts[1] if len(parts) > 1 else ""

            if key.startswith("Record Name"):
                current_name = val.rstrip(".").lower()
                if current_name and current_name not in records:
                    records[current_name] = {
                        "domain": current_name,
                        "ips": [],
                        "ttls": [],
                    }
            elif key.startswith("Time To Live") and current_name and current_name in records:
                try:
                    records[current_name]["ttls"].append(int(val))
                except ValueError:
                    pass
            elif "Record" in key and not key.startswith("Record Type") and current_name and current_name in records:
                if val and val not in records[current_name]["ips"]:
                    records[current_name]["ips"].append(val)

    return records


def snapshot_dns_cache() -> dict[str, dict]:
    """
    Capture the current Windows DNS client resolution cache.
    Returns a dictionary mapping normalized domain names to their record details.
    """
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode != 0:
            return {}
        return parse_displaydns_output(proc.stdout)
    except (subprocess.SubprocessError, OSError, TimeoutError):
        return {}


def find_dns_changes(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> list[dict]:
    """
    Identify newly queried or resolved domains between DNS cache snapshots.
    """
    now = utc_now()
    new_queries = []

    for domain, record in current.items():
        if domain not in previous:
            analysis = analyze_domain(domain)
            event = {
                "event_type": "dns_query_observed",
                "timestamp": now,
                "domain": domain,
                "resolved_ips": record.get("ips", []),
                "ttls": record.get("ttls", []),
                **analysis,
            }
            new_queries.append(event)

    return new_queries


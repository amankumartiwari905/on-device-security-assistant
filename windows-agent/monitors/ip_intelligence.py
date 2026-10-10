"""Remote IP intelligence, geolocation, hosting detection, and threat reputation."""

import functools
import ipaddress
import json
import re
from urllib.error import URLError
import urllib.request


# Known hosting and cloud infrastructure keywords for provider attribution
HOSTING_PROVIDER_PATTERNS = [
    (re.compile(r"\b(amazon|aws)\b", re.I), "Amazon Web Services (AWS)"),
    (re.compile(r"\b(microsoft|azure)\b", re.I), "Microsoft Azure"),
    (re.compile(r"\b(google|google cloud|gcp)\b", re.I), "Google Cloud"),
    (re.compile(r"\b(cloudflare)\b", re.I), "Cloudflare"),
    (re.compile(r"\b(digitalocean)\b", re.I), "DigitalOcean"),
    (re.compile(r"\b(ovh)\b", re.I), "OVHcloud"),
    (re.compile(r"\b(hetzner)\b", re.I), "Hetzner"),
    (re.compile(r"\b(linode|akamai)\b", re.I), "Akamai / Linode"),
    (re.compile(r"\b(oracle|oci)\b", re.I), "Oracle Cloud"),
    (re.compile(r"\b(alibaba|aliyun)\b", re.I), "Alibaba Cloud"),
    (re.compile(r"\b(vultr|choopa)\b", re.I), "Vultr / Choopa"),
    (re.compile(r"\b(fastly)\b", re.I), "Fastly"),
    (re.compile(r"\b(leaseweb)\b", re.I), "Leaseweb"),
    (re.compile(r"\b(hostinger)\b", re.I), "Hostinger"),
]

# Configurable threat intelligence feed of known malicious IPs / test indicators
DEFAULT_KNOWN_MALICIOUS_IPS = {
    "198.51.100.66": "Known Cobalt Strike C2 IP (Simulated Threat Intel)",
    "203.0.113.199": "Known Botnet Command & Control (Simulated Threat Intel)",
}


def is_public_ip(ip: str) -> bool:
    """Return True if the IP is a routable public IP (not private, loopback, or reserved)."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return (
            ip_obj.is_global
            and not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
            and not ip_obj.is_unspecified
        )
    except (ValueError, AttributeError):
        return False


def identify_hosting_provider(org: str = "", asn: str = "") -> str | None:
    """Detect cloud and hosting providers based on ASN or organization text."""
    combined = f"{org} {asn}".strip()
    if not combined:
        return None

    for pattern, provider_name in HOSTING_PROVIDER_PATTERNS:
        if pattern.search(combined):
            return provider_name

    return None


@functools.lru_cache(maxsize=1024)
def lookup_ip_intelligence(ip: str, timeout: float = 1.5) -> dict:
    """
    Retrieve approximate geographic information, organization, and hosting detection.
    Results are cached in memory. Gracefully falls back if offline or lookup fails.
    """
    ip_str = ip.strip()

    if not is_public_ip(ip_str):
        return {
            "ip": ip_str,
            "is_public": False,
            "country": "Local / Private",
            "country_code": "LOC",
            "region": None,
            "city": None,
            "org": None,
            "isp": None,
            "asn": None,
            "is_hosting": False,
            "hosting_provider": None,
        }

    # Query public IP intelligence endpoint with strict timeout and offline fallback
    url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,isp,org,as,hosting"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PhishGuard-Agent/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") == "success":
            org = data.get("org") or ""
            asn = data.get("as") or ""
            api_hosting = bool(data.get("hosting"))
            provider = identify_hosting_provider(org, asn)

            return {
                "ip": ip_str,
                "is_public": True,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": asn,
                "is_hosting": api_hosting or bool(provider),
                "hosting_provider": provider or ("Cloud / Hosting Provider" if api_hosting else None),
            }

    except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        pass

    return {
        "ip": ip_str,
        "is_public": True,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "org": None,
        "isp": None,
        "asn": None,
        "is_hosting": False,
        "hosting_provider": None,
    }


def check_ip_reputation(
    ip: str,
    threat_feed: dict[str, str] | None = None,
) -> dict:
    """
    Check public IP address against known threat intelligence sources.
    """
    ip_str = ip.strip()
    feed = DEFAULT_KNOWN_MALICIOUS_IPS if threat_feed is None else threat_feed

    if ip_str in feed:
        return {
            "ip": ip_str,
            "is_flagged": True,
            "threat_source": "Threat Intelligence Feed",
            "threat_category": "Known Malicious Infrastructure",
            "details": feed[ip_str],
        }

    return {
        "ip": ip_str,
        "is_flagged": False,
        "threat_source": None,
        "threat_category": None,
        "details": None,
    }


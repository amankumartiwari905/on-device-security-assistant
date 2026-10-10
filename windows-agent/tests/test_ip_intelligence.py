"""Unit tests for IP intelligence, geolocation, hosting detection, and reputation."""

import io
import json
import urllib.request
import pytest

from monitors.ip_intelligence import (
    is_public_ip,
    identify_hosting_provider,
    lookup_ip_intelligence,
    check_ip_reputation,
)


def test_is_public_ip_classification():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("93.184.216.34") is True

    # Private and special IP ranges must return False
    assert is_public_ip("192.168.1.100") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.5.10") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("169.254.10.20") is False
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("invalid_ip") is False
    assert is_public_ip("") is False


def test_identify_hosting_provider():
    assert identify_hosting_provider("Amazon.com, Inc.", "AS16509 AWS") == "Amazon Web Services (AWS)"
    assert identify_hosting_provider("Microsoft Corporation", "AS8075 MICROSOFT-CORP") == "Microsoft Azure"
    assert identify_hosting_provider("Google LLC", "AS15169 GOOGLE") == "Google Cloud"
    assert identify_hosting_provider("Cloudflare, Inc.", "AS13335 CLOUDFLARENET") == "Cloudflare"
    assert identify_hosting_provider("DigitalOcean, LLC", "AS14061 DIGITALOCEAN") == "DigitalOcean"
    assert identify_hosting_provider("OVH SAS", "AS16276 OVH") == "OVHcloud"
    assert identify_hosting_provider("Hetzner Online GmbH", "AS24940 HETZNER") == "Hetzner"
    assert identify_hosting_provider("Local ISP Telecom", "AS1234") is None


def test_lookup_ip_intelligence_private_ip():
    res = lookup_ip_intelligence("192.168.1.1")
    assert res["is_public"] is False
    assert res["country"] == "Local / Private"
    assert res["country_code"] == "LOC"
    assert res["is_hosting"] is False


def test_lookup_ip_intelligence_mocked_public(monkeypatch):
    mock_payload = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Hesse",
        "city": "Frankfurt",
        "org": "Hetzner Online GmbH",
        "isp": "Hetzner",
        "as": "AS24940 Hetzner",
        "hosting": True,
    }

    class MockResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def read(self):
            return json.dumps(mock_payload).encode("utf-8")

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=1.5: MockResponse(),
    )

    # Use a unique IP to avoid lru_cache hits from other tests
    res = lookup_ip_intelligence("116.203.0.1")
    assert res["is_public"] is True
    assert res["country"] == "Germany"
    assert res["country_code"] == "DE"
    assert res["city"] == "Frankfurt"
    assert res["is_hosting"] is True
    assert res["hosting_provider"] == "Hetzner"


def test_lookup_ip_intelligence_offline_resilience(monkeypatch):
    def failing_urlopen(req, timeout=1.5):
        raise urllib.request.URLError("Network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", failing_urlopen)

    res = lookup_ip_intelligence("93.184.216.34")
    assert res["is_public"] is True
    assert res["country"] is None
    assert res["is_hosting"] is False


def test_check_ip_reputation():
    feed = {
        "198.51.100.66": "Known C2 IP",
    }
    flagged = check_ip_reputation("198.51.100.66", threat_feed=feed)
    assert flagged["is_flagged"] is True
    assert "Known C2 IP" in flagged["details"]

    clean = check_ip_reputation("8.8.8.8", threat_feed=feed)
    assert clean["is_flagged"] is False
    assert clean["details"] is None

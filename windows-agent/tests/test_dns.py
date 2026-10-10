"""Unit tests for DNS cache monitoring, displaydns parsing, and suspicious domain analysis."""

from monitors.dns import (
    calculate_entropy,
    analyze_domain,
    parse_displaydns_output,
    find_dns_changes,
)


def test_calculate_entropy():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaaa") == 0.0
    entropy_normal = calculate_entropy("google")
    entropy_random = calculate_entropy("x8k9q1lmv02z8a")
    assert entropy_random > entropy_normal


def test_analyze_domain_dynamic_dns():
    res = analyze_domain("mybot.duckdns.org")
    assert res["is_dynamic_dns"] is True
    assert any("Dynamic DNS" in ind for ind in res["indicators"])

    res2 = analyze_domain("tunnel.ngrok.io")
    assert res2["is_dynamic_dns"] is True


def test_analyze_domain_suspicious_tld():
    res = analyze_domain("update-check.top")
    assert res["is_suspicious_tld"] is True
    assert any("high-abuse" in ind for ind in res["indicators"])


def test_analyze_domain_potential_dga():
    # Long, random pseudo-random label with numbers and high entropy
    res = analyze_domain("q89xkm18902vlza09.com")
    assert res["is_potential_dga"] is True
    assert any("DGA" in ind for ind in res["indicators"])


def test_analyze_domain_benign():
    res = analyze_domain("www.google.com")
    assert res["is_dynamic_dns"] is False
    assert res["is_suspicious_tld"] is False
    assert res["is_potential_dga"] is False
    assert res["indicators"] == []


def test_analyze_domain_punycode():
    res = analyze_domain("xn--e1afmkfd.xn--p1ai")
    assert any("Punycode" in ind for ind in res["indicators"])


def test_parse_displaydns_output():
    sample_text = """
Windows IP Configuration

    array611.prod.do.dsp.mp.microsoft.com
    ----------------------------------------
    Record Name . . . . . : array611.prod.do.dsp.mp.microsoft.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 276
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 72.145.35.106


    www.googleapis.com
    ----------------------------------------
    Record Name . . . . . : www.googleapis.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 13
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 172.217.119.4
"""

    parsed = parse_displaydns_output(sample_text)
    assert len(parsed) == 2
    assert "www.googleapis.com" in parsed
    assert "72.145.35.106" in parsed["array611.prod.do.dsp.mp.microsoft.com"]["ips"]
    assert 276 in parsed["array611.prod.do.dsp.mp.microsoft.com"]["ttls"]


def test_find_dns_changes():
    previous = {
        "google.com": {"domain": "google.com", "ips": ["142.250.190.46"], "ttls": [100]},
    }
    current = {
        "google.com": {"domain": "google.com", "ips": ["142.250.190.46"], "ttls": [100]},
        "c2.duckdns.org": {"domain": "c2.duckdns.org", "ips": ["198.51.100.1"], "ttls": [60]},
    }

    new_events = find_dns_changes(previous, current)
    assert len(new_events) == 1
    assert new_events[0]["domain"] == "c2.duckdns.org"
    assert new_events[0]["event_type"] == "dns_query_observed"
    assert new_events[0]["is_dynamic_dns"] is True

